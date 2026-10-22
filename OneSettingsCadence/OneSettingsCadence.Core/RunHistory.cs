using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Xml.Linq;

namespace LookSee.OneSettingsCadence
{
    /// <summary>
    /// Observed run history for the RefreshCache task, read from the Task
    /// Scheduler operational channel (Microsoft-Windows-TaskScheduler/Operational)
    /// — the same source the Taskhostw Spawns attribution uses. This is the
    /// compliance half of cadence control: the watchdog re-asserts the task
    /// *definition* daily, but "is it actually obeying me" needs observed
    /// launches vs the expected cadence. Each launch is bucketed by why the
    /// scheduler says it fired:
    ///
    ///   EID 107  timer (the repetition we control)
    ///   EID 108  event / WNF state change (the triggers set removes)
    ///   EID 119  logon
    ///   EID 100 with none of the above  manual / API start — something called
    ///                                   Run() on the task; no trigger fired
    /// </summary>
    public static class RunHistory
    {
        private const string Channel = "Microsoft-Windows-TaskScheduler/Operational";

        public sealed class TaskRun
        {
            public DateTime TimeUtc;
            public string Trigger;          // timer (schedule) / event / WNF / logon / manual / API
            public int? ResultCode;         // EID 201/203 ResultCode
            public DateTime? CompletedUtc;
        }

        public sealed class History
        {
            public List<TaskRun> Runs = new();
            public bool ChannelWasDisabled; // the reader enabled it just now — history starts here
        }

        /// <summary>
        /// Reads this task's launches in the last <paramref name="days"/> days.
        /// Read-only apart from one thing done everywhere the app touches this
        /// channel (TaskAttributionService does the same): if Task Scheduler
        /// history is disabled, it is enabled, and ChannelWasDisabled reports
        /// that the window starts at this moment.
        /// </summary>
        public static History Read(int days = 7)
        {
            var result = new History();
            bool wasDisabled = false;
            try
            {
                using (var config = new EventLogConfiguration(Channel))
                {
                    if (!config.IsEnabled)
                    {
                        config.IsEnabled = true;
                        config.SaveChanges();
                        wasDisabled = true;
                    }
                }
            }
            catch { /* not elevated or channel locked — read whatever exists */ }
            result.ChannelWasDisabled = wasDisabled;

            // instance → run under construction; a launch is 100 (started) +
            // 107/108/119 (why) + 201/203 (result), sharing an InstanceId
            var byInstance = new Dictionary<string, TaskRun>(StringComparer.OrdinalIgnoreCase);
            long windowMs = (long)TimeSpan.FromDays(days).TotalMilliseconds;
            string xpath =
                "*[System[(EventID=100 or EventID=107 or EventID=108 or EventID=119 or EventID=201 or EventID=203)" +
                $" and TimeCreated[timediff(@SystemTime) <= {windowMs}]]]";

            try
            {
                var query = new EventLogQuery(Channel,
                    PathType.LogName, xpath)
                { ReverseDirection = true };
                using var reader = new EventLogReader(query);
                EventRecord rec;
                while ((rec = reader.ReadEvent()) != null)
                {
                    using (rec)
                    {
                        try
                        {
                            var fields = ParseFields(rec.ToXml());
                            if (fields == null) continue;
                            string taskName = Get(fields, "TaskName");
                            if (!string.Equals(taskName?.TrimEnd('\\'), CadenceEngine.TaskPath, StringComparison.OrdinalIgnoreCase)) continue;
                            string instance = (Get(fields, "InstanceId") ?? Get(fields, "TaskInstanceId"))?.Trim('{', '}')
                                              ?? string.Empty;
                            if (instance.Length == 0) continue;
                            if (!byInstance.TryGetValue(instance, out TaskRun run))
                            {
                                run = new TaskRun { Trigger = "manual / API" }; // 100 alone means no trigger fired
                                byInstance[instance] = run;
                            }
                            if (rec.TimeCreated is DateTime t)
                            {
                                t = t.ToUniversalTime();
                                if (run.TimeUtc == default || t < run.TimeUtc) run.TimeUtc = t;
                            }
                            switch (rec.Id)
                            {
                                case 107: run.Trigger = "timer (schedule)"; break;
                                case 108: run.Trigger = "event / WNF"; break;
                                case 119: run.Trigger = "logon"; break;
                                case 201:
                                case 203:
                                    run.ResultCode ??= ParseInt(Get(fields, "ResultCode") ?? Get(fields, "ErrorCode"));
                                    if (rec.TimeCreated is DateTime done) run.CompletedUtc = done.ToUniversalTime();
                                    break;
                            }
                        }
                        catch { /* one malformed record never stops the scan */ }
                    }
                }
            }
            catch (EventLogNotFoundException) { return result; }
            catch (COMException) { return result; }   // event service unreachable
            catch (FormatException) { return result; } // bad XPath on older hosts

            result.Runs = byInstance.Values
                .Where(r => r.TimeUtc != default)
                .OrderByDescending(r => r.TimeUtc)
                .ToList();
            return result;
        }

        // ── expected-vs-observed compliance ─────────────────────────────────

        public sealed class Compliance
        {
            public int Days;
            public TimeSpan Cadence;           // what the timer says now
            public bool CadenceIsSaved;        // false = judging against live stock values
            public double ExpectedTimerRuns;
            public int TimerRuns, EventRuns, LogonRuns, ManualRuns;
            public int TotalRuns;
            public string Verdict;             // one honest sentence
        }

        /// <summary>
        /// Buckets observed runs against the cadence the timer should be
        /// holding. Extra timer runs beyond ~expected + 1 mean the definition
        /// was reverted for part of the window (or the interval never landed);
        /// event/WNF and manual runs are *not* cadence violations of the timer
        /// — they are other actors, and the verdict names them.
        /// </summary>
        public static Compliance Compute(List<TaskRun> runs, TimeSpan cadence, bool cadenceIsSaved, int days,
                                         bool wnfTriggersPresent = false)
        {
            var c = new Compliance
            {
                Days = days,
                Cadence = cadence,
                CadenceIsSaved = cadenceIsSaved,
                TotalRuns = runs.Count,
                ExpectedTimerRuns = Math.Round(days * 24.0 / cadence.TotalHours, 1),
            };
            foreach (TaskRun r in runs)
            {
                if (r.Trigger == "timer (schedule)") c.TimerRuns++;
                else if (r.Trigger == "event / WNF") c.EventRuns++;
                else if (r.Trigger == "logon") c.LogonRuns++;
                else c.ManualRuns++;
            }

            if (runs.Count == 0)
            {
                c.Verdict = $"no launches recorded in the last {days} day(s)";
            }
            else if (c.TimerRuns > c.ExpectedTimerRuns + 1)
            {
                // WNF state-change triggers fire through the same EID-107
                // channel the time trigger uses, so with them installed the
                // excess over the repetition rate is their work, not drift
                // (observed here: 107s 2-13 minutes apart at a 3h36m interval)
                c.Verdict = wnfTriggersPresent
                    ? $"{c.TimerRuns} runs observed vs ~{c.ExpectedTimerRuns} the repetition alone would fire — the WNF " +
                      "state-change triggers use the same channel, so the excess is theirs (remove them with Apply, or keep them and expect this)"
                    : $"{c.TimerRuns} timer runs observed vs ~{c.ExpectedTimerRuns} expected — the previous cadence " +
                      "was live for part of this window (Windows servicing reverts the task; re-apply, and consider the watchdog)";
            }
            else
            {
                c.Verdict = $"timer is holding: {c.TimerRuns} run(s) vs ~{c.ExpectedTimerRuns} expected";
                if (c.EventRuns > 0) c.Verdict += $"; {c.EventRuns} extra run(s) from event/WNF triggers (remove them, or keep them and expect this)";
                if (c.LogonRuns > 0) c.Verdict += $"; {c.LogonRuns} at logon";
                if (c.ManualRuns > 0) c.Verdict += $"; {c.ManualRuns} started outside any trigger — something called Run() on the task (the watchdog re-asserts the definition, not external starts)";
            }
            return c;
        }

        // ── event XML helpers (same shape as TaskAttributionService.ParseFields) ──

        /// <summary>Exposed for the offline self-test: the event namespace is exact-match, and a typo'd URI parses nothing.</summary>
        public static Dictionary<string, string> ParseFields(string xml)
        {
            var doc = XDocument.Parse(xml);
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            var eventData = doc.Root?.Element(ns + "EventData");
            if (eventData == null) return null;

            // case-insensitive on purpose: scheduler events mix spellings
            var fields = new Dictionary<string, string>(16, StringComparer.OrdinalIgnoreCase);
            foreach (var data in eventData.Elements(ns + "Data"))
            {
                string name = data.Attribute("Name")?.Value;
                if (name != null && !fields.ContainsKey(name)) fields[name] = data.Value;
            }
            return fields;
        }

        private static string Get(Dictionary<string, string> fields, string name) =>
            fields.TryGetValue(name, out string value) ? value : null;

        private static int? ParseInt(string value) =>
            int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int v) ? v : null;
    }
}
