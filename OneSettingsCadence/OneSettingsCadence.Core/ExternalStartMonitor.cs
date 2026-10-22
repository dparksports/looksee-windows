using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;

namespace LookSee.OneSettingsCadence
{
    /// <summary>
    /// Pure correlation state machine behind live external-start detection —
    /// no event-log, no timers, fully covered by the offline self-test.
    ///
    /// A launch of the RefreshCache task is EID 100 (started). A trigger-fired
    /// launch is preceded (by milliseconds) by EID 107 (timer), 108 (event /
    /// WNF) or 119 (logon) carrying the same InstanceId. A launch whose
    /// InstanceId has no trigger event within the deadline was started by
    /// something calling Run() on the task — an external start. EID 129 names
    /// the taskhostw instance and its PID; Sysmon EID 3 (connect) and EID 5
    /// (exit) for that PID are the fetch evidence.
    /// </summary>
    public sealed class ExternalStartCorrelator
    {
        public sealed class FetchRecord
        {
            public DateTime TimeUtc;
            public string Destination;     // ip:port (Sysmon DestinationIp:DestinationPort)
        }

        public sealed class StartInstance
        {
            public string InstanceId;
            public DateTime StartedUtc;
            public int Pid;                // from EID 129; 0 until known
            public bool TriggerSeen;       // 107/108/119 with this InstanceId
            public bool ConfirmedExternal; // set once, at deadline, when no trigger
            public DateTime? ExitedUtc;    // Sysmon EID 5 for the pid
            public readonly List<FetchRecord> Fetches = new();
        }

        public static readonly TimeSpan Deadline = TimeSpan.FromSeconds(3);

        private readonly object _lock = new();
        private readonly List<StartInstance> _instances = new();
        private readonly Dictionary<string, StartInstance> _byInstanceId = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<int, StartInstance> _byPid = new();

        public int MaxInstances { get; set; } = 50;

        public IReadOnlyList<StartInstance> Snapshot()
        {
            lock (_lock) return _instances.ToList();
        }

        /// <summary>
        /// True when this call confirmed the instance as an external start
        /// (the caller raises the alert exactly then).
        /// </summary>
        public bool FeedScheduler(int eventId, string instanceId, DateTime timeUtc, int pid)
        {
            lock (_lock)
            {
                if (string.IsNullOrEmpty(instanceId)) return false;
                switch (eventId)
                {
                    case 107 or 108 or 119:
                        Instance(instanceId, timeUtc).TriggerSeen = true;
                        return false;

                    case 100:
                        Instance(instanceId, timeUtc);
                        return false; // verdict waits for the deadline

                    case 129:
                        // "launch task X, instance taskhostw.exe, with process
                        // ID N" — attaches the pid to the instance (129 can
                        // arrive just before or just after the 100)
                        StartInstance inst = Instance(instanceId, timeUtc);
                        if (pid > 0 && inst.Pid == 0)
                        {
                            inst.Pid = pid;
                            _byPid[pid] = inst;
                        }
                        return false;

                    default:
                        return false;
                }
            }
        }

        /// <summary>Called periodically by the monitor; confirms external starts whose deadline elapsed with no trigger.</summary>
        public List<StartInstance> FeedDeadline(DateTime nowUtc)
        {
            var confirmed = new List<StartInstance>();
            lock (_lock)
            {
                foreach (StartInstance inst in _instances)
                {
                    if (inst.ConfirmedExternal || inst.TriggerSeen) continue;
                    if (nowUtc - inst.StartedUtc < Deadline) continue;
                    inst.ConfirmedExternal = true;
                    confirmed.Add(inst);
                }
            }
            return confirmed;
        }

        public void FeedSysmonConnect(int pid, string destination, DateTime timeUtc)
        {
            lock (_lock)
            {
                if (!_byPid.TryGetValue(pid, out StartInstance inst)) return;
                if (inst.ExitedUtc != null) return; // pid recycled onto a new process
                if (inst.Fetches.Count >= 64) return; // a fetch storm must not grow the row forever
                inst.Fetches.Add(new FetchRecord { TimeUtc = timeUtc, Destination = destination });
            }
        }

        public void FeedSysmonExit(int pid, DateTime timeUtc)
        {
            lock (_lock)
            {
                if (!_byPid.TryGetValue(pid, out StartInstance inst)) return;
                inst.ExitedUtc ??= timeUtc;
                _byPid.Remove(pid);
            }
        }

        private StartInstance Instance(string instanceId, DateTime timeUtc)
        {
            if (_byInstanceId.TryGetValue(instanceId, out StartInstance existing))
            {
                if (timeUtc < existing.StartedUtc) existing.StartedUtc = timeUtc;
                return existing;
            }

            var inst = new StartInstance { InstanceId = instanceId, StartedUtc = timeUtc };
            _byInstanceId[instanceId] = inst;
            _instances.Insert(0, inst); // newest first, like the history feed
            if (_instances.Count > MaxInstances)
            {
                StartInstance dropped = _instances[^1];
                _instances.RemoveAt(_instances.Count - 1);
                _byInstanceId.Remove(dropped.InstanceId);
                if (dropped.Pid > 0 && ReferenceEquals(_byPid.GetValueOrDefault(dropped.Pid), dropped))
                    _byPid.Remove(dropped.Pid);
            }
            return inst;
        }
    }

    /// <summary>
    /// Live watcher over the Task Scheduler operational channel (and Sysmon,
    /// when installed) that turns the correlator's decisions into events.
    /// Read-only: it subscribes to event channels and touches nothing else.
    /// The 100/107/108/119/129 + Sysmon EID 3/5 XML is parsed with the same
    /// EventData conventions as RunHistory (namespace is exact-match).
    /// </summary>
    public sealed class ExternalStartMonitor : IDisposable
    {
        private const string SchedulerChannel = "Microsoft-Windows-TaskScheduler/Operational";
        private const string SysmonChannel = "Microsoft-Windows-Sysmon/Operational";

        private static readonly string SchedulerXPath =
            "*[System[(EventID=100 or EventID=107 or EventID=108 or EventID=119 or EventID=129)]]";
        private static readonly string SysmonXPath =
            "*[System[(EventID=3 or EventID=5)]]";

        private readonly object _startLock = new();
        private EventLogWatcher _schedulerWatcher, _sysmonWatcher;
        private Timer _deadlineTimer;
        private bool _started, _disposed;

        public ExternalStartCorrelator Correlator { get; } = new();

        /// <summary>Channel opened; false when the scheduler log is unreadable (watching is impossible).</summary>
        public bool SchedulerChannelOk { get; private set; }

        /// <summary>False when Sysmon is not installed — starts are still detected, fetch evidence is not.</summary>
        public bool SysmonAvailable { get; private set; } = true;

        /// <summary>Raised once per external start, on a background thread.</summary>
        public event Action<ExternalStartCorrelator.StartInstance> ExternalStart;

        /// <summary>Raised when fetch evidence or exits update an instance, on a background thread.</summary>
        public event Action Changed;

        public void Start()
        {
            lock (_startLock)
            {
                if (_started || _disposed) return;
                _started = true;
            }

            try
            {
                _schedulerWatcher = new EventLogWatcher(new EventLogQuery(SchedulerChannel, PathType.LogName, SchedulerXPath));
                _schedulerWatcher.EventRecordWritten += Scheduler_Recorded;
                _schedulerWatcher.Enabled = true;
                SchedulerChannelOk = true;
            }
            catch
            {
                SchedulerChannelOk = false;
                return;
            }

            try
            {
                _sysmonWatcher = new EventLogWatcher(new EventLogQuery(SysmonChannel, PathType.LogName, SysmonXPath));
                _sysmonWatcher.EventRecordWritten += Sysmon_Recorded;
                _sysmonWatcher.Enabled = true;
            }
            catch (EventLogNotFoundException)
            {
                SysmonAvailable = false; // the tab says so instead of guessing
            }
            catch
            {
                SysmonAvailable = false;
            }

            // debounce sweep: confirms 100-without-trigger launches a beat
            // after their trigger window closes
            _deadlineTimer = new Timer(_ =>
            {
                foreach (var inst in Correlator.FeedDeadline(DateTime.UtcNow))
                {
                    try { ExternalStart?.Invoke(inst); }
                    catch { /* a UI-handler bug must never take down the sweep */ }
                }
            }, null, dueTime: TimeSpan.FromMilliseconds(500), period: TimeSpan.FromSeconds(1));
        }

        private void Scheduler_Recorded(object sender, EventRecordWrittenEventArgs e)
        {
            EventRecord rec = e.EventRecord;
            if (rec == null) return;
            try
            {
                var fields = RunHistory.ParseFields(rec.ToXml());
                if (fields == null) return;
                if (!IsOurTask(fields)) return;
                string instance = (Get(fields, "InstanceId") ?? Get(fields, "TaskInstanceId"))?.Trim('{', '}');
                if (string.IsNullOrEmpty(instance)) return;
                int pid = ParseInt(Get(fields, "ProcessId")) ?? 0;
                if (rec.TimeCreated is DateTime t)
                    Correlator.FeedScheduler(rec.Id, instance, t.ToUniversalTime(), pid);
            }
            catch { /* one malformed record never stops the watcher */ }
            finally { rec.Dispose(); }
        }

        private void Sysmon_Recorded(object sender, EventRecordWrittenEventArgs e)
        {
            EventRecord rec = e.EventRecord;
            if (rec == null) return;
            try
            {
                var fields = RunHistory.ParseFields(rec.ToXml());
                if (fields == null) return;
                int pid = ParseInt(Get(fields, "SourceProcessId") ?? Get(fields, "ProcessId")) ?? 0;
                if (pid <= 0) return;
                if (rec.TimeCreated is DateTime t)
                {
                    if (rec.Id == 3)
                    {
                        string dest = (Get(fields, "DestinationIp") ?? "?") + ":" + (Get(fields, "DestinationPort") ?? "?");
                        Correlator.FeedSysmonConnect(pid, dest, t.ToUniversalTime());
                        Changed?.Invoke();
                    }
                    else if (rec.Id == 5)
                    {
                        Correlator.FeedSysmonExit(pid, t.ToUniversalTime());
                        Changed?.Invoke();
                    }
                }
            }
            catch { /* attribution is best-effort */ }
            finally { rec.Dispose(); }
        }

        private static bool IsOurTask(Dictionary<string, string> fields) =>
            string.Equals(Get(fields, "TaskName")?.TrimEnd('\\'), CadenceEngine.TaskPath,
                          StringComparison.OrdinalIgnoreCase);

        private static string Get(Dictionary<string, string> fields, string name) =>
            fields.TryGetValue(name, out string value) ? value : null;

        private static int? ParseInt(string value) =>
            int.TryParse(value, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out int v) ? v : null;

        public void Dispose()
        {
            lock (_startLock)
            {
                if (_disposed) return;
                _disposed = true;
            }
            _deadlineTimer?.Dispose();
            try { if (_schedulerWatcher != null) { _schedulerWatcher.Enabled = false; _schedulerWatcher.Dispose(); } } catch { }
            try { if (_sysmonWatcher != null) { _sysmonWatcher.Enabled = false; _sysmonWatcher.Dispose(); } } catch { }
        }
    }
}
