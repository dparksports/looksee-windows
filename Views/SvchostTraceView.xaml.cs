using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using SvchostAnalyzer.Core;
using LookSee.Services;

namespace LookSee.Views
{
    /// <summary>
    /// Svchost Trace & Patterns — the timeline/pattern layer that complements
    /// SvchostMonitorView (which shows live Sysmon/socket traffic).
    ///
    /// Captures three synchronized event streams, same JSONL schema as the
    /// standalone svchost-watch PowerShell tooling:
    ///   spawn       — who created each svchost instance (parent process + service)
    ///   connect/    — TCP destinations, lifetimes and transmit windows
    ///   disconnect
    ///   bytes       — cumulative IO counters per network-active PID
    ///
    /// Pattern detection on top: destination classification (Microsoft /
    /// Akamai / Gcore / unclassified), beacon regularity (coefficient of
    /// variation of connect intervals), respawn loops, upload dominance.
    /// Polls WMI + the kernel TCP table (GetExtendedTcpTable) at 1s —
    /// deliberately non-elevated-friendly; kernel ETW (Sysmon) needs
    /// admin, this degrades gracefully instead.
    /// </summary>
    public partial class SvchostTraceView : UserControl
    {
        private const int MaxRows = 2000;

        private readonly DispatcherTimer _poll = new() { Interval = TimeSpan.FromSeconds(1) };
        private readonly DispatcherTimer _analysis = new() { Interval = TimeSpan.FromSeconds(30) };
        private readonly DispatcherTimer _svcTimer = new() { Interval = TimeSpan.FromSeconds(10) };
        private bool _suppressAutoStartEvents;
        // one-time init guard — Loaded fires on every tab switch, but the
        // Tick subscription and the trace auto-start must happen only once
        private bool _isInitialized;

        // pid -> services hosted
        private readonly Dictionary<int, string> _svcByPid = new();
        // pid -> parsed -k/-s identity (visible cmdline only; SYSTEM lines are
        // unreadable non-elevated — recorded as hidden, never guessed)
        private readonly Dictionary<int, IdentityInfo> _identByPid = new();
        // sticky identity flags — survive their PID's exit, printed by Analyze()
        private readonly List<(int Pid, string Text)> _identityFlags = new();
        // "pid|ip:port" -> connected-at
        private readonly Dictionary<string, DateTime> _connOpen = new();
        // every connect event, for pattern analysis
        private readonly List<(DateTime T, int Pid, string Svc, string Ip, int Port)> _connEvents = new();
        // pids that have ever held a connection -> byte-counter samples
        private readonly Dictionary<int, List<(DateTime T, long R, long W)>> _bytes = new();
        // JSONL export lines (same schema as analyze-svchost.ps1 input)
        private readonly List<string> _jsonEvents = new();

        private readonly ObservableCollection<TraceRow> _rows = new();
        private int _ticks;
        private int _flags;
        private bool _tracing;

        /// <summary>Live state for the Spawns host's feed indicator.</summary>
        public bool IsTracing => _tracing;

        public SvchostTraceView()
        {
            InitializeComponent();
            TraceGrid.ItemsSource = _rows;
            _poll.Tick += (_, _) => PollSafe();
            _analysis.Tick += (_, _) => Analyze();
        }

        private void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            if (!_isInitialized)
            {
                _isInitialized = true;
                _svcTimer.Tick += (_, _) => _ = RefreshServiceStatusAsync();
                // Auto-start on first load, matching the other feeds'
                // tab's contract: instances appear the moment the tab is
                // first shown, instead of waiting for an explicit Start.
                StartTraceBtn_Click(StartTraceBtn, null);
            }
            _svcTimer.Start();
            _ = RefreshServiceStatusAsync();
        }

        private void UserControl_Unloaded(object sender, RoutedEventArgs e)
        {
            // Only the status strip is tab-scoped. The trace poll keeps
            // running across tab switches — a recorder must not stop
            // because another tab was viewed (same lifetime policy as the
            // static CaptureEngine below). Rows collected while hidden are
            // all there when the tab returns.
            _svcTimer.Stop();
        }

        // ── capture control ────────────────────────────────────────────────

        private void StartTraceBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_tracing) { Stop(); return; }
            _tracing = true;
            StartTraceBtn.Content = "⏹ Stop Trace";
            try { Baseline(); }
            catch (Exception ex)
            {
                // Auto-start runs this on first tab load — a WMI failure
                // must not surface as a modal via the app-level Dispatcher
                // handler. The poll keeps retrying and reports here.
                TraceStatusText.Text = $"Baseline failed: {ex.Message} — polls continue, errors shown here";
            }
            _poll.Start();
            _analysis.Start();
            UpdateEmptyHint();
        }

        private void Stop()
        {
            _tracing = false;
            _poll.Stop();
            _analysis.Stop();
            if (StartTraceBtn != null) StartTraceBtn.Content = "▶ Start Trace";
            if (TraceStatusText != null)
                TraceStatusText.Text = $"Trace stopped. {_rows.Count} events captured — Analyze or Export.";
            UpdateEmptyHint();
        }

        private void ClearBtn_Click(object sender, RoutedEventArgs e)
        {
            _rows.Clear(); _jsonEvents.Clear(); _connEvents.Clear();
            _svcByPid.Clear(); _connOpen.Clear(); _bytes.Clear();
            _identByPid.Clear(); _identityFlags.Clear();
            _ticks = 0; _flags = 0;
            EventsChip.Text = "events: 0"; FlagsChip.Text = "flags: 0";
            UpdateEmptyHint();
        }

        // ── poll: spawns, exits, connections, byte samples ─────────────────

        /// <summary>
        /// One-time snapshot at Start: existing svchost population + connections
        /// already established (e.g. the persistent WNS channel) — without this,
        /// only transitions during the trace are visible. Batched WMI queries
        /// (one roundtrip per table) so the UI doesn't stall on 80+ per-PID lookups.
        /// </summary>
        private void Baseline()
        {
            var now = DateTime.Now;
            var procs = QueryProcesses();
            var svcMap = QueryServiceMap();
            var nameMap = QueryNameMap();

            foreach (var p in procs)
            {
                string services = svcMap.TryGetValue(p.Pid, out var s) ? s : "<pending>";
                string parent = nameMap.TryGetValue(p.Ppid, out var pn) ? pn : "<exited>";
                _svcByPid[p.Pid] = services;
                var id = RecordIdentity(p.Pid, p.Cmd, services, parent, now);
                if (parent != "services.exe")
                {
                    AddRow(new TraceRow(now, "FLAG", p.Pid, services, parent, "",
                        $"parent is '{parent}', expected services.exe"));
                    _flags++;
                }
                AddRow(new TraceRow(now, "baseline", p.Pid, services, parent, "",
                    $"created {p.Created}{id.DetailSuffix}"));
                var evt = new Dictionary<string, object> {
                    ["type"]="baseline", ["pid"]=p.Pid, ["services"]=services,
                    ["ppid"]=p.Ppid, ["parent"]=parent, ["created"]=p.Created, ["cmd"]=p.Cmd ?? "" };
                foreach (var kv in id.JsonFields) evt[kv.Key] = kv.Value;
                _jsonEvents.Add(Json(evt));
            }

            foreach (var c in TcpConnectionTable.GetEstablished())
            {
                string ip = c.RemoteIp;
                if (ip.StartsWith("127.") || ip == "::1") continue; // loopback only — this tab traces LAN too
                int pid = c.Pid;
                if (!_svcByPid.ContainsKey(pid)) continue;
                _connOpen[$"{pid}|{ip}:{c.RemotePort}"] = now;
                _connEvents.Add((now, pid, _svcByPid[pid], ip, c.RemotePort));
                if (!_bytes.ContainsKey(pid)) _bytes[pid] = new();
                AddRow(new TraceRow(now, "connect", pid, _svcByPid[pid], "", $"{ip}:{c.RemotePort}", "already open at trace start"));
                _jsonEvents.Add(Json(new Dictionary<string, object> {
                    ["type"]="connect", ["preexisting"]=true, ["pid"]=pid,
                    ["services"]=_svcByPid[pid], ["ip"]=ip, ["port"]=c.RemotePort }));
            }

            EventsChip.Text = $"events: {_rows.Count}";
            FlagsChip.Text = $"flags: {_flags}";
            TraceStatusText.Text = $"Tracing… baseline: {_svcByPid.Count} svchost instances, {_connOpen.Count} preexisting connections · 1s polls";
        }

        private void Poll()
        {
            _ticks++;
            var now = DateTime.Now;
            var procs = QueryProcesses();

            // spawns during the trace (baseline population is handled by Baseline())
            foreach (var p in procs)
                if (!_svcByPid.ContainsKey(p.Pid))
                    OnSpawn(p, "spawn", now);

            // exits
            var live = procs.Select(p => p.Pid).ToHashSet();
            foreach (var pid in _svcByPid.Keys.Where(k => !live.Contains(k)).ToList())
            {
                AddRow(new TraceRow(now, "exit", pid, _svcByPid[pid], "", "", "process exited"));
                _jsonEvents.Add(Json(new Dictionary<string, object> {
                    ["type"]="exit", ["pid"]=pid, ["services"]=_svcByPid[pid] }));
                _svcByPid.Remove(pid);
                _identByPid.Remove(pid);
            }

            // connections (established, non-loopback, svchost-owned)
            var cur = new Dictionary<string, bool>();
            foreach (var c in TcpConnectionTable.GetEstablished())
            {
                string ip = c.RemoteIp;
                if (ip.StartsWith("127.") || ip == "::1") continue; // loopback only — this tab traces LAN too
                int pid = c.Pid;
                if (!_svcByPid.ContainsKey(pid)) continue;

                string key = $"{pid}|{ip}:{c.RemotePort}";
                cur[key] = true;
                if (!_connOpen.ContainsKey(key))
                {
                    _connOpen[key] = now;
                    _connEvents.Add((now, pid, _svcByPid[pid], ip, c.RemotePort));
                    if (!_bytes.ContainsKey(pid)) _bytes[pid] = new();
                    AddRow(new TraceRow(now, "connect", pid, _svcByPid[pid], "", $"{ip}:{c.RemotePort}", $"opened → port {c.RemotePort}"));
                    _jsonEvents.Add(Json(new Dictionary<string, object> {
                        ["type"]="connect", ["pid"]=pid, ["services"]=_svcByPid[pid], ["ip"]=ip, ["port"]=c.RemotePort }));
                }
            }
            foreach (var key in _connOpen.Keys.Where(k => !cur.ContainsKey(k)).ToList())
            {
                double dur = (now - _connOpen[key]).TotalSeconds;
                var parts = key.Split('|');
                int pid = int.Parse(parts[0]);
                string ipport = parts[1];
                AddRow(new TraceRow(now, "disconnect", pid,
                    _svcByPid.TryGetValue(pid, out var s) ? s : "", "", ipport, $"closed after {dur:F1}s"));
                _jsonEvents.Add(Json(new Dictionary<string, object> {
                    ["type"]="disconnect", ["pid"]=pid, ["ipport"]=ipport, ["dur"]=Math.Round(dur, 1) }));
                _connOpen.Remove(key);
            }

            // byte counters every 5th tick for network-active PIDs
            if (_ticks % 5 == 0 && _bytes.Count > 0)
                foreach (var p in QueryProcesses())
                    if (_bytes.TryGetValue(p.Pid, out var hist))
                    {
                        hist.Add((now, p.R, p.W));
                        _jsonEvents.Add(Json(new Dictionary<string, object> {
                            ["type"]="bytes", ["pid"]=p.Pid, ["r"]=p.R, ["w"]=p.W }));
                    }

            EventsChip.Text = $"events: {_rows.Count}";
            TraceStatusText.Text = $"Tracing… tick {_ticks} · {_svcByPid.Count} svchost instances · {_connOpen.Count} live connections";
        }

        /// <summary>
        /// Poll wrapper: WMI/TCP-table failures surface in the status line
        /// instead of raising a modal per tick through the app-level
        /// Dispatcher handler. Transient WMI errors recover on retry.
        /// </summary>
        private void PollSafe()
        {
            try { Poll(); }
            catch (Exception ex)
            {
                TraceStatusText.Text = $"Trace error (tick {_ticks}): {ex.Message} — retrying next tick";
            }
        }

        /// <summary>The grid overlay shown while stopped with no rows, so a
        /// passive tab reads as "not tracing" rather than broken detection.</summary>
        private void UpdateEmptyHint()
        {
            if (EmptyHint != null)
                EmptyHint.Visibility = (!_tracing && _rows.Count == 0)
                    ? Visibility.Visible : Visibility.Collapsed;
        }

        private void OnSpawn((int Pid, int Ppid, string Created, string Cmd, long R, long W) p, string type, DateTime now)
        {
            string services = QueryServices(p.Pid) ?? "<no service>";
            string parent = QueryProcessName(p.Ppid) ?? "<exited>";
            _svcByPid[p.Pid] = services;

            bool badParent = parent != "services.exe";
            bool noSvc = services == "<no service>";
            var id = RecordIdentity(p.Pid, p.Cmd, services, parent, now);

            if (badParent || noSvc)
            {
                AddRow(new TraceRow(now, "FLAG", p.Pid, services, parent, "",
                    noSvc ? "svchost with NO resolvable service" : $"parent is '{parent}', expected services.exe"));
                _flags++;
                FlagsChip.Text = $"flags: {_flags}";
            }
            AddRow(new TraceRow(now, type, p.Pid, services, parent, "",
                $"created {p.Created}{id.DetailSuffix}"));
            var evt = new Dictionary<string, object> {
                ["type"]=type, ["pid"]=p.Pid, ["services"]=services,
                ["ppid"]=p.Ppid, ["parent"]=parent, ["created"]=p.Created, ["cmd"]=p.Cmd ?? "" };
            foreach (var kv in id.JsonFields) evt[kv.Key] = kv.Value;
            _jsonEvents.Add(Json(evt));
        }

        /// <summary>
        /// Parses the instance's -k/-s identity and records it. Masquerade
        /// signals raise FLAG rows immediately (counted once here, merely
        /// reprinted by Analyze()): a -s claim that contradicts the
        /// SCM-resident services, and a readable command line without -k —
        /// hidden command lines (non-elevated WMI cannot read SYSTEM
        /// processes) are the normal case and are labeled, not flagged.
        /// </summary>
        private IdentityInfo RecordIdentity(int pid, string cmd, string services, string parent, DateTime now)
        {
            var id = IdentityInfo.Parse(cmd, services);
            _identByPid[pid] = id;
            // one identity flag per instance — the strongest signal wins
            // (a mismatch already implies the line is not genuine)
            if (id.Mismatch)
            {
                string text = $"-s '{id.S}' but SCM hosts '{services}' — identity mismatch (masquerade signal)";
                AddRow(new TraceRow(now, "FLAG", pid, services, parent, "", text));
                _identityFlags.Add((pid, text));
                _flags++;
            }
            else if (id.NoK)
            {
                string text = $"readable command line without -k service group — not an SCM-launched service host";
                AddRow(new TraceRow(now, "FLAG", pid, services, parent, "", text));
                _identityFlags.Add((pid, text));
                _flags++;
            }
            return id;
        }

        /// <summary>
        /// One instance's command-line identity: -k group and -s service with
        /// the corroboration verdict against the SCM ground truth, plus the
        /// ready-made suffix and JSONL fields derived from it.
        /// </summary>
        private readonly record struct IdentityInfo(string K, string S, bool Visible, bool Mismatch, bool NoK)
        {
            public static IdentityInfo Parse(string cmd, string services)
            {
                var id = SvchostIdentity.Parse(cmd);
                bool visible = !string.IsNullOrEmpty(cmd);
                // "<pending>"/"<no service>" placeholders are not SCM data
                bool corroborable = !string.IsNullOrEmpty(services) && !services.StartsWith('<');
                return new IdentityInfo(id.Group, id.DeclaredService, visible,
                    corroborable && SvchostIdentity.Mismatches(id.DeclaredService, services),
                    visible && id.Group == null);
            }

            /// <summary>Suffix for the row's Detail column (" · netsvcs · -s WpnService" / " · cmdline hidden").</summary>
            public string DetailSuffix => Visible
                ? " · " + (K ?? "no -k ⚠") + (S != null ? $" · -s {S}" : "")
                : " · cmdline hidden";

            /// <summary>Extra JSONL fields (same schema as the CaptureEngine's k/s/mismatch/noK).</summary>
            public Dictionary<string, object> JsonFields
            {
                get
                {
                    var d = new Dictionary<string, object>();
                    if (K != null) d["k"] = K;
                    if (S != null) d["s"] = S;
                    if (Mismatch) d["mismatch"] = true;
                    if (NoK) d["noK"] = true;
                    return d;
                }
            }
        }

        // ── pattern analysis ───────────────────────────────────────────────

        private void AnalyzeBtn_Click(object sender, RoutedEventArgs e) => Analyze();

        private void Analyze()
        {
            if (_rows.Count == 0) { AnalysisBox.Text = "No events captured yet."; return; }
            var sb = new StringBuilder();
            sb.AppendLine($"=== PATTERN ANALYSIS · {_rows.Count} events, span {(DateTime.Now - (_rows.Count > 0 ? _rows[^1].At : DateTime.Now)).TotalMinutes:F1} min (newest→oldest rows) ===");

            // 1. spawn genealogy
            var spawnRows = _rows.Where(r => r.Type is "spawn" or "baseline").ToList();
            sb.AppendLine($"\n--- PROCESS CREATION ({spawnRows.Count} svchost instances) ---");
            foreach (var g in spawnRows.GroupBy(r => string.IsNullOrEmpty(r.Parent) ? "?" : r.Parent).OrderByDescending(g => g.Count()))
                sb.AppendLine($"  parent {g.Key}: {g.Count()} instance(s)");
            foreach (var g in spawnRows.Where(r => r.Type == "spawn").GroupBy(r => r.Services).Where(g => g.Count() >= 4))
            {
                sb.AppendLine($"  ⚠ FLAG: service '{g.Key}' respawned {g.Count()}x during capture — crash/respawn loop");
                _flags++;
            }

            // 1b. identity: -k group · -s service vs SCM ground truth
            sb.AppendLine("\n--- IDENTITY (-k group · -s service vs SCM) ---");
            if (_identByPid.Count == 0 && _identityFlags.Count == 0)
            {
                sb.AppendLine("  (no svchost instances captured)");
            }
            else
            {
                var readable = _identByPid.Values.Where(v => v.Visible).ToList();
                int hidden = _identByPid.Count - readable.Count;
                sb.AppendLine($"  {_identByPid.Count} current instance(s) · {readable.Count} readable command line(s) · {hidden} hidden" +
                              (hidden > 0 ? " (non-elevated: SYSTEM svchost lines are unreadable — normal)" : ""));
                foreach (var g in readable.GroupBy(v => v.K ?? "<no -k>").OrderByDescending(g => g.Count()))
                    sb.AppendLine($"  group {g.Key}: {g.Count()} instance(s)");
                // identity flags were counted when raised; here they are only reprinted
                foreach (var (flagPid, flagText) in _identityFlags)
                    sb.AppendLine($"  ⚠ FLAG: PID {flagPid} — {flagText}");
                if (_identityFlags.Count == 0)
                    sb.AppendLine("  every readable command line corroborates its SCM services");
            }

            // 2. destinations + classification
            sb.AppendLine($"\n--- DESTINATIONS ({_connEvents.Count} connections) ---");
            foreach (var g in _connEvents.GroupBy(c => (c.Svc, c.Ip)).OrderByDescending(g => g.Count()))
                sb.AppendLine($"  {g.Key.Svc} -> {g.Key.Ip}: {g.Count()}x port {g.First().Port} [{Classify(g.Key.Ip)}]");
            var unknown = _connEvents.Select(c => c.Ip).Distinct().Where(ip => Classify(ip) == "UNCLASSIFIED").ToList();
            if (unknown.Count > 0)
                sb.AppendLine($"  ⚠ {unknown.Count} UNCLASSIFIED destination(s): {string.Join(", ", unknown)} — verify via https://rdap.org/ip/<ip>");

            // 3. beacon regularity (CV of connect intervals)
            sb.AppendLine("\n--- BEACON ANALYSIS (connect intervals, ≥4 connects) ---");
            bool anyBeacon = false;
            foreach (var g in _connEvents.GroupBy(c => (c.Svc, c.Ip)))
            {
                var times = g.Select(c => c.T).OrderBy(t => t).ToList();
                if (times.Count < 4) continue;
                var iv = times.Zip(times.Skip(1), (a, b) => (b - a).TotalSeconds).ToList();
                double mean = iv.Average();
                if (mean <= 0) continue;
                double std = Math.Sqrt(iv.Sum(v => (v - mean) * (v - mean)) / iv.Count);
                double cv = std / mean;
                bool beacon = cv < 0.35;
                sb.AppendLine($"  {g.Key.Svc} -> {g.Key.Ip}: n={times.Count}, mean={mean:F1}s, CV={cv:F2} {(beacon ? "⚠ REGULAR — beacon-like" : "(irregular — normal)")}");
                if (beacon) { anyBeacon = true; _flags++; }
            }
            if (_connEvents.Count == 0) sb.AppendLine("  (no svchost connections captured in this window)");
            else if (!anyBeacon) sb.AppendLine("  no regular-interval pattern detected");

            // 4. byte flows — upload dominance
            sb.AppendLine("\n--- BYTE FLOWS (Δ cumulative counters) ---");
            foreach (var (pid, hist) in _bytes)
            {
                if (hist.Count < 2) continue;
                long dr = hist[^1].R - hist[0].R, dw = hist[^1].W - hist[0].W;
                string svc = _svcByPid.TryGetValue(pid, out var s) ? s : "?";
                sb.AppendLine($"  PID {pid} ({svc}): received {dr:N0} B, sent {dw:N0} B");
                if (dw > 3_000_000 && dw > 3 * dr)
                {
                    sb.AppendLine($"  ⚠ FLAG: PID {pid} upload-dominant ({dw:N0} B sent vs {dr:N0} B received)");
                    _flags++;
                }
            }

            FlagsChip.Text = $"flags: {_flags}";
            AnalysisBox.Text = sb.ToString();
        }

        // ── destination classification (session-verified ranges) ───────────

        private static readonly (string Name, string[] Cidrs)[] Ranges =
        {
            ("Microsoft/Azure", new[] { "20.0.0.0/8", "40.0.0.0/8", "13.64.0.0/11", "13.104.0.0/14",
                                        "52.96.0.0/12", "52.112.0.0/14", "65.52.0.0/14", "72.145.32.0/19", "172.176.0.0/12" }),
            ("Akamai (MS CDN)", new[] { "23.32.0.0/11", "23.192.0.0/11", "2.16.0.0/13", "95.100.0.0/15", "184.24.0.0/13", "104.64.0.0/10" }),
            ("Gcore (MS CDN)",  new[] { "92.223.0.0/16" }),
        };

        internal static string Classify(string ip)
        {
            if (!IPAddress.TryParse(ip, out var addr) || addr.AddressFamily != AddressFamily.InterNetwork)
                return "IPv6/other";
            var b = addr.GetAddressBytes();
            uint v = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
            foreach (var (name, cidrs) in Ranges)
                foreach (var cidr in cidrs)
                {
                    var parts = cidr.Split('/');
                    var nb = IPAddress.Parse(parts[0]).GetAddressBytes();
                    uint net = (uint)(nb[0] << 24 | nb[1] << 16 | nb[2] << 8 | nb[3]);
                    uint mask = uint.MaxValue << (32 - int.Parse(parts[1]));
                    if ((v & mask) == (net & mask)) return name;
                }
            return "UNCLASSIFIED";
        }

        // ── data access helpers ────────────────────────────────────────────

        private List<(int Pid, int Ppid, string Created, string Cmd, long R, long W)> QueryProcesses()
        {
            var list = new List<(int, int, string, string, long, long)>();
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, ParentProcessId, CreationDate, CommandLine, ReadTransferCount, WriteTransferCount " +
                "FROM Win32_Process WHERE Name = 'svchost.exe'");
            foreach (ManagementObject o in searcher.Get())
            {
                list.Add((
                    Convert.ToInt32(o["ProcessId"]),
                    Convert.ToInt32(o["ParentProcessId"]),
                    o["CreationDate"]?.ToString() ?? "",
                    o["CommandLine"]?.ToString() ?? "",
                    Convert.ToInt64(o["ReadTransferCount"] ?? 0L),
                    Convert.ToInt64(o["WriteTransferCount"] ?? 0L)));
            }
            return list;
        }

        private static string QueryServices(int pid)
        {
            using var searcher = new ManagementObjectSearcher($"SELECT Name FROM Win32_Service WHERE ProcessId = {pid}");
            var names = new List<string>();
            foreach (ManagementObject o in searcher.Get()) names.Add(o["Name"].ToString());
            return names.Count > 0 ? string.Join(",", names) : null;
        }

        private static string QueryProcessName(int pid)
        {
            using var searcher = new ManagementObjectSearcher($"SELECT Name FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (ManagementObject o in searcher.Get()) return o["Name"].ToString();
            return null;
        }

        /// <summary>All services grouped by hosting PID — one WMI roundtrip for the whole table.</summary>
        private static Dictionary<int, string> QueryServiceMap()
        {
            var map = new Dictionary<int, List<string>>();
            using var searcher = new ManagementObjectSearcher("SELECT Name, ProcessId FROM Win32_Service");
            foreach (ManagementObject o in searcher.Get())
            {
                int pid = Convert.ToInt32(o["ProcessId"]);
                if (pid == 0) continue;
                if (!map.TryGetValue(pid, out var list)) map[pid] = list = new List<string>();
                list.Add(o["Name"].ToString());
            }
            return map.ToDictionary(kv => kv.Key, kv => string.Join(",", kv.Value));
        }

        /// <summary>PID → process name for parent attribution — one WMI roundtrip.</summary>
        private static Dictionary<int, string> QueryNameMap()
        {
            var map = new Dictionary<int, string>();
            using var searcher = new ManagementObjectSearcher("SELECT ProcessId, Name FROM Win32_Process");
            foreach (ManagementObject o in searcher.Get())
                map[Convert.ToInt32(o["ProcessId"])] = o["Name"].ToString();
            return map;
        }

        // ── row + export plumbing ──────────────────────────────────────────

        private void AddRow(TraceRow row)
        {
            _rows.Insert(0, row);
            if (_rows.Count > MaxRows) _rows.RemoveAt(_rows.Count - 1);
        }

        private static string Json(Dictionary<string, object> o)
        {
            o["t"] = DateTime.Now.ToString("o");
            return System.Text.Json.JsonSerializer.Serialize(o);
        }

        private void ExportBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_jsonEvents.Count == 0) { MessageBox.Show("Nothing to export yet.", "Export"); return; }
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "JSONL trace (*.jsonl)|*.jsonl",
                FileName = $"svchost-trace-{DateTime.Now:yyyyMMdd-HHmmss}.jsonl"
            };
            if (dlg.ShowDialog() != true) return;
            File.WriteAllLines(dlg.FileName, _jsonEvents);
            TraceStatusText.Text = $"Exported {_jsonEvents.Count} events → {dlg.FileName} (compatible with analyze-svchost.ps1)";
        }

        // ── capture service management ──────────────────────────────────────
        //
        // Interactive captures run IN-PROCESS through SvchostAnalyzer.Core
        // (the same engine the CLI exe wraps) — no child binary is spawned,
        // so nothing for SmartScreen/Smart App Control to block. They end
        // when the app closes.
        //
        // The headless SvchostAnalyzer.exe remains the opt-in boot-autostart
        // host (survives app close, starts at logon via an HKCU Run key,
        // stops through the sentinel file) for 24/7 recording. It is no longer
        // distributed with the app or its releases; an already-installed copy
        // keeps working. A killed trace is still valid JSONL (every event is
        // its own appended line).

        // Boot auto-start uses an HKCU Run key rather than a scheduled task:
        // task creation is elevation-gated for standard users (schtasks caps
        // /tr at 261 chars; Register-ScheduledTask → Access Denied), while a
        // Run key needs no UAC and starts at logon. The "auto-start instance
        // AND user clicks Start" race is already handled by the collector's
        // Global mutex (second instance exits with code 3).
        private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string RunValueName = "LookSee-SvchostWatch";
        private static readonly string CapturesDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LookSee", "captures");
        private static string StopFilePath => Path.Combine(CapturesDir, "stop.sentinel");

        /// <summary>Where a previously auto-installed analyzer lives (user-writable, no admin).</summary>
        private static readonly string ToolsDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LookSee", "tools");

        /// <summary>
        /// The in-process capture engine. Static: the capture outlives tab
        /// unload/reload within the app session (matching the old exe's
        /// independence from this view's lifetime).
        /// </summary>
        private static CaptureEngine _captureEngine;

        private static string ResolveAnalyzerExe()
        {
            var candidates = new List<string>
            {
                // deployed layout: tools\SvchostAnalyzer.exe next to the app
                Path.Combine(AppContext.BaseDirectory, "tools", "SvchostAnalyzer.exe"),
                Path.Combine(AppContext.BaseDirectory, "SvchostAnalyzer.exe"),
                // auto-installed layout
                Path.Combine(ToolsDir, "SvchostAnalyzer.exe"),
            };
            // dev layout: the vendored engine source lives in the repo at
            // svchost-watch\ — walk up from bin\Debug\... to the repo root
            var dir = AppContext.BaseDirectory;
            for (int i = 0; i < 6 && dir != null; i++, dir = Path.GetDirectoryName(dir))
                candidates.Add(Path.Combine(dir!, "svchost-watch", "SvchostAnalyzer",
                                            "bin", "Debug", "net10.0-windows", "SvchostAnalyzer.exe"));
            return candidates.FirstOrDefault(File.Exists);
        }

        private static string BootCommand(string exe) =>
            $"\"{exe}\" capture --seconds 0 --max-size-mb 200 " +
            $"--out \"{Path.Combine(CapturesDir, "svchost-boot.jsonl")}\" --stop-file \"{StopFilePath}\"";

        private static bool IsAutoStartEnabled() =>
            Microsoft.Win32.Registry.GetValue($@"HKEY_CURRENT_USER\{RunKeyPath}", RunValueName, null) != null;

        private static void SetAutoStart(bool enabled)
        {
            if (enabled)
            {
                using var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(RunKeyPath);
                k.SetValue(RunValueName, BootCommand(ResolveAnalyzerExe()));
            }
            else
            {
                using var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true);
                k?.DeleteValue(RunValueName, throwOnMissingValue: false);
            }
        }

        private static Process GetCaptureProcess()
        {
            return Process.GetProcessesByName("SvchostAnalyzer")
                .FirstOrDefault(p => (SafeCommandLine(p.Id) ?? "").Contains("capture"));
        }

        private static string SafeCommandLine(int pid)
        {
            try
            {
                using var s = new ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (ManagementObject o in s.Get()) return o["CommandLine"]?.ToString();
            }
            catch { }
            return null;
        }

        private void StartCaptureBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_captureEngine is { IsRunning: true })
            {
                MessageBox.Show("An in-app capture is already running.", "Capture");
                return;
            }
            if (GetCaptureProcess() != null)
            {
                MessageBox.Show("The standalone capture engine (boot auto-start) is already recording.", "Capture");
                return;
            }

            Directory.CreateDirectory(CapturesDir);
            var engine = new CaptureEngine(new CaptureOptions
            {
                OutFile = Path.Combine(CapturesDir, $"svchost-{DateTime.Now:yyyyMMdd-HHmmss}.jsonl"),
                Duration = null,               // run until Stop
                MaxSizeMb = 200,
                StopFile = StopFilePath,       // the app's own stop protocol still works
            });
            engine.Status += m => Dispatcher.Invoke(() => TraceStatusText.Text = m);
            engine.Completed += f => Dispatcher.Invoke(() =>
            {
                TraceStatusText.Text = $"Capture complete: {Path.GetFileName(f)}";
                _ = RefreshServiceStatusAsync();
            });
            try
            {
                engine.Start();
            }
            catch (InvalidOperationException ex)
            {
                MessageBox.Show(ex.Message, "Capture", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            _captureEngine = engine;
            TraceStatusText.Text = "In-process capture running — events stream to the captures folder.";
            _ = RefreshServiceStatusAsync();
        }

        private async void StopCaptureBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_captureEngine is { IsRunning: true })
            {
                TraceStatusText.Text = "Stopping in-process capture…";
                var engine = _captureEngine;
                await Task.Run(() => engine.Stop());
                TraceStatusText.Text = "Capture stopped.";
                _ = RefreshServiceStatusAsync();
                return;
            }

            var p = GetCaptureProcess();
            if (p == null) { MessageBox.Show("No capture is running.", "Capture"); return; }
            Directory.CreateDirectory(CapturesDir);
            File.WriteAllText(StopFilePath, DateTime.Now.ToString("o"));
            for (int i = 0; i < 8 && !p.HasExited; i++) { p.Refresh(); await Task.Delay(500); }
            if (!p.HasExited) { try { p.Kill(); } catch { /* already gone */ } }
            try { File.Delete(StopFilePath); } catch { }
            _ = RefreshServiceStatusAsync();
        }

        private void AutoStartToggle_Changed(object sender, RoutedEventArgs e)
        {
            if (_suppressAutoStartEvents) return;
            var exe = ResolveAnalyzerExe();
            if (exe == null)
            {
                MessageBox.Show(
                    "Boot auto-start needs the standalone SvchostAnalyzer.exe, which is no\n" +
                    "longer distributed with LookSee releases.\n\n" +
                    "If you installed it earlier, make sure the exe is still where the app\n" +
                    "can find it: next to LookSee.exe, in a tools\\ folder beside it, or\n" +
                    "in %LOCALAPPDATA%\\LookSee\\tools. An installed copy keeps working.",
                    "Auto-start", MessageBoxButton.OK, MessageBoxImage.Information);
                ForceToggleOff();
                return;
            }
            try
            {
                SetAutoStart(AutoStartToggle.IsChecked == true);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed to update boot auto-start:\n" + ex.Message, "Auto-start");
                ForceToggleOff();
            }
            _ = RefreshServiceStatusAsync();
        }

        private void ForceToggleOff()
        {
            _suppressAutoStartEvents = true;
            AutoStartToggle.IsChecked = false;
            _suppressAutoStartEvents = false;
        }

        private void OpenFolderBtn_Click(object sender, RoutedEventArgs e)
        {
            Directory.CreateDirectory(CapturesDir);
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{CapturesDir}\"") { UseShellExecute = true });
        }

        private async Task RefreshServiceStatusAsync()
        {
            bool inProc = _captureEngine is { IsRunning: true };
            bool external = await Task.Run(() => GetCaptureProcess() != null);
            bool running = inProc || external;
            bool autoOn = await Task.Run(() => { try { return IsAutoStartEnabled(); } catch { return false; } });
            CaptureDot.Fill = new System.Windows.Media.SolidColorBrush(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(
                    running ? "#7ED8A0" : "#6B7280"));
            CaptureStatusText.Text = $"Capture: {(running ? "running" : "stopped")} · auto-start: {(autoOn ? "on" : "off")}";
            if (AutoStartToggle.IsChecked != autoOn)
            {
                _suppressAutoStartEvents = true;
                AutoStartToggle.IsChecked = autoOn;
                _suppressAutoStartEvents = false;
            }
            RefreshTracesList();
        }

        private void RefreshTracesList()
        {
            if (!Directory.Exists(CapturesDir)) return;
            try
            {
                var current = TracesCombo.SelectedItem as string;
                var files = Directory.GetFiles(CapturesDir, "*.jsonl")
                    .OrderByDescending(File.GetLastWriteTime).Take(25).ToList();
                TracesCombo.ItemsSource = files;
                if (current != null && files.Contains(current)) TracesCombo.SelectedItem = current;
                else if (files.Count > 0) TracesCombo.SelectedIndex = 0;
            }
            catch { /* directory contention — next refresh retries */ }
        }

        private async void AnalyzeFileBtn_Click(object sender, RoutedEventArgs e)
        {
            if (TracesCombo.SelectedItem is not string file) { MessageBox.Show("Select a trace file first.", "Analyze"); return; }
            AnalyzeFileBtn.IsEnabled = false;
            try
            {
                // In-process: the engine is linked in, no exe to spawn
                var result = await Task.Run(() => TraceAnalyzer.Analyze(new[] { file }));
                AnalysisBox.Text = result.Report;
            }
            catch (Exception ex) { AnalysisBox.Text = "analysis failed: " + ex.Message; }
            finally { AnalyzeFileBtn.IsEnabled = true; }
        }

        /// <summary>One timeline row. Immutable — bindings are one-shot.</summary>
        private record TraceRow(DateTime At, string Type, int Pid, string Services, string Parent, string Destination, string Detail)
        {
            public string Time => At.ToString("HH:mm:ss");
        }
    }
}
