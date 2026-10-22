using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Threading;
using LookSee.Services;

namespace LookSee.Views
{
    /// <summary>
    /// Black Hole tab — the visible half of the telemetry sinkhole. Shows the
    /// current hosts pins and sinkhole state, a toggle that flips the pins
    /// between silent (0.0.0.0) and logging (127.0.0.1) mode, cumulative
    /// denied-attempt counters, and a live feed of every attempt caught with
    /// process, PID and the hostname from the TLS hello.
    /// </summary>
    public partial class BlackHoleView : UserControl
    {
        private readonly DispatcherTimer _refresh = new() { Interval = TimeSpan.FromSeconds(5) };
        private readonly TelemetryRulesService _rules = new();
        private bool _protectionBusy;
        private bool _toggling;

        private sealed class AttemptRow
        {
            public string TimeLocal { get; set; }
            public string Hostname { get; set; }
            public string ProcessName { get; set; }
            public int Pid { get; set; }
            public string DeniedBy { get; set; }
            public string CommandLine { get; set; }
            public string ProcessImage { get; set; }
            public string PeerEndpoint { get; set; }
        }

        private sealed class HostnameTotal
        {
            public string Hostname { get; set; }
            public int Count { get; set; }
        }

        private sealed class RuleOption
        {
            public string Text { get; set; }
            public TelemetryRuleStatus Status { get; set; }
            public override string ToString() => Text;
        }

        public BlackHoleView()
        {
            InitializeComponent();
        }

        private void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            TelemetryProofService.Instance.Changed += OnProofChanged;
            SinkholeService.Instance.StatusChanged += OnProofChanged;
            _refresh.Tick += (_, _) => RefreshAll();
            _refresh.Start();
            RefreshAll();
        }

        private void OnProofChanged()
        {
            if (!Dispatcher.CheckAccess()) Dispatcher.BeginInvoke(RefreshAll);
            else RefreshAll();
        }

        // ── State refresh ─────────────────────────────────────────────────

        private void RefreshAll()
        {
            RefreshState();
            RefreshFeed();
            RefreshTotals();
            RefreshProtection();
        }

        // ── Protection status: flag state + pin state + still-beaconing ────

        /// <summary>
        /// The card that answers "am I actually protected, and by what?" —
        /// an opt-out flag and a network pin are different promises, and a
        /// process started before a flag change keeps the old setting until
        /// it restarts. Evaluated from the same rules knowledge base the
        /// opt-out flow uses; pin state from the live hosts file.
        /// </summary>
        private async void RefreshProtection()
        {
            if (_protectionBusy) return;
            _protectionBusy = true;
            try
            {
                var statuses = await _rules.EvaluateAllAsync();
                var pins = HostsTelemetryPins.ReadLive();
                var lines = new List<string>();

                foreach (var s in statuses.Where(s => s.Detected))
                {
                    var rule = s.Rule;
                    var pin = pins.FirstOrDefault(p => rule.WatchDomains.Any(d =>
                        p.Hostname.Equals(d, StringComparison.OrdinalIgnoreCase) ||
                        p.Hostname.EndsWith("." + d, StringComparison.OrdinalIgnoreCase)));
                    string network = pin == null
                        ? "no pin — beacons still leave the machine"
                        : pin.IsSinkhole
                            ? "pinned → 127.0.0.1 — this tab catches the attempts"
                            : "pinned → 0.0.0.0 (silent — attempts are denied but cannot be logged)";

                    string flagNote = s.State switch
                    {
                        TelemetryState.Off => "flag: opted out",
                        TelemetryState.Ineffective => "flag: present but NOT honored (wrong type)",
                        TelemetryState.Unknown => "flag: unknown",
                        _ => "flag: telemetry on",
                    };

                    string stale = "";
                    if (rule.Category?.IndexOf("python", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        int older = CountProcessesOlderThanFlag(rule);
                        if (older > 0)
                            stale = $"\n    ⚠ {older} python process(es) started before the flag was applied — still using the old setting until restarted";
                    }

                    lines.Add($"{rule.AppName} — {flagNote} · network: {network}{stale}");
                }

                string text = lines.Count == 0
                    ? "No known-telemetry apps detected on this machine."
                    : string.Join("\n", lines) +
                      "\nA flag stops new processes only; a pin stops everything immediately — and only pinned attempts appear in this tab.";
                if (!Dispatcher.CheckAccess()) _ = Dispatcher.BeginInvoke(() => { ProtectionText.Text = text; PopulateRuleCombo(statuses); });
                else { ProtectionText.Text = text; PopulateRuleCombo(statuses); }
            }
            catch (Exception ex)
            {
                ProtectionText.Text = $"Protection status unavailable: {ex.Message}";
            }
            finally { _protectionBusy = false; }
        }

        /// <summary>
        /// Processes whose start time predates the rule's settings file last
        /// being written — i.e. they loaded the flag before its current value.
        /// </summary>
        private static int CountProcessesOlderThanFlag(TelemetryRule rule)
        {
            try
            {
                string path = Environment.ExpandEnvironmentVariables(rule.Detection?.Path ?? "");
                if (rule.Detection?.Type != "file" || !File.Exists(path)) return 0;
                var flagWrittenUtc = File.GetLastWriteTimeUtc(path);

                int count = 0;
                foreach (var p in System.Diagnostics.Process.GetProcessesByName("python"))
                {
                    try { if (p.StartTime.ToUniversalTime() < flagWrittenUtc) count++; }
                    catch { /* access denied on some processes — count what we can see */ }
                    finally { p.Dispose(); }
                }
                return count;
            }
            catch { return 0; }
        }

        // ── Rule actions — the ladder without leaving this tab ────────────

        private void PopulateRuleCombo(List<TelemetryRuleStatus> statuses)
        {
            string selectedId = (RuleCombo.SelectedItem as RuleOption)?.Status?.Rule?.Id;
            RuleCombo.ItemsSource = statuses
                .Where(s => s.Detected && s.Rule != null)
                .Select(s => new RuleOption { Text = $"{s.Rule.AppName} — {s.StateText}", Status = s })
                .ToList();
            if (RuleCombo.Items.Count > 0)
            {
                RuleCombo.SelectedIndex = Math.Max(0, (RuleCombo.ItemsSource as List<RuleOption>)
                    .FindIndex(o => o.Status.Rule.Id == selectedId));
            }
        }

        private TelemetryRule SelectedRule() =>
            (RuleCombo.SelectedItem as RuleOption)?.Status?.Rule;

        private async void OptOutRuleBtn_Click(object sender, RoutedEventArgs e)
        {
            var rule = SelectedRule();
            if (rule == null) return;
            if (MessageBox.Show(
                    $"Turn off telemetry for {rule.AppName}?\n\n{rule.Mechanism}\n\nRisk: {rule.RiskNote}\n" +
                    "The current setting is snapshotted first and can be reverted.",
                    "Opt out", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK)
                return;

            var (ok, message) = await _rules.ApplyOptOutAsync(rule);
            MessageBox.Show(message, ok ? "Opted out" : "Failed", MessageBoxButton.OK,
                ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
            RefreshAll();
        }

        private async void BlockLogRuleBtn_Click(object sender, RoutedEventArgs e)
        {
            var rule = SelectedRule();
            if (rule?.Enforce == null)
            {
                MessageBox.Show("This rule has no network-block action defined.", "Block & log",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            if (MessageBox.Show(
                    $"Block {rule.AppName} at the network — and log every attempt here?\n\n" +
                    $"This pins {string.Join(", ", rule.Enforce.Domains)} at 127.0.0.1 in the hosts file. Every attempt, " +
                    "from any process including ones started before any opt-out, is denied — and caught in the feed below " +
                    "with its hostname, process, PID and command line.\n\n" +
                    "Know what this touches:\n" +
                    "• System-wide — every program on this PC, including browsers, fails to reach the domain\n" +
                    "• No functional impact on this app — its telemetry sender already treats failure as harmless\n" +
                    "• Reversible here or in Shields Up; DNS is flushed so it applies immediately",
                    "Block & log", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK)
                return;

            var (ok, message) = await _rules.ApplyEnforceAsync(rule, HostsTelemetryPins.SinkholeAddress);
            if (ok) SinkholeService.Instance.EnsureRunningForCurrentPins();
            MessageBox.Show(message, ok ? "Network block" : "Failed", MessageBoxButton.OK,
                ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
            RefreshAll();
        }

        private async void RemoveBlockBtn_Click(object sender, RoutedEventArgs e)
        {
            var rule = SelectedRule();
            if (rule?.Enforce == null) return;
            if (MessageBox.Show(
                    $"Remove the network block for {rule.AppName}?\n\nThe hosts pin is removed (works for pins created " +
                    "here or in Shields Up) and the DNS cache is flushed. Opt-out flags are untouched.",
                    "Remove block", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK)
                return;

            var (ok, message) = await _rules.RevertEnforceAsync(rule);
            MessageBox.Show(message, ok ? "Network block removed" : "Failed", MessageBoxButton.OK,
                ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
            RefreshAll();
        }

        private async void RevertOptOutBtn_Click(object sender, RoutedEventArgs e)
        {
            var rule = SelectedRule();
            if (rule == null) return;
            var (ok, message) = await _rules.RevertAsync(rule);
            MessageBox.Show(message, ok ? "Reverted" : "Revert unavailable", MessageBoxButton.OK,
                ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
            RefreshAll();
        }

        private void RefreshState()
        {
            var pins = HostsTelemetryPins.ReadLive();

            if (pins.Count == 0)
            {
                SinkholeStatusText.Text = "No telemetry pins in the hosts file — nothing is network-blocked.";
                SinkholeDetailText.Text =
                    "Opt-out flags alone (see Protection status above) do not stop beacons from processes started before " +
                    "the flag, and they never show up here. A pin does both: create one from Shields Up's Telemetry tab " +
                    "(\"Block network instead\") or this app's rules engine, then return to catch the attempts.";
                SinkholeToggle.IsEnabled = false;
                SinkholeToggle.IsChecked = false;
                PinListText.Text = "";
                return;
            }

            bool sinkhole = HostsTelemetryPins.AnySinkhole(pins);
            SinkholeToggle.IsEnabled = true;
            SinkholeToggle.IsChecked = sinkhole;

            // A sinkhole pin can appear while the app is already running —
            // created from the rule actions above or by Shields Up's block
            // offer — so engage the listener without waiting for a restart.
            // PortBusy is deliberately left alone: retrying every tick would
            // hammer a port someone else owns.
            if (sinkhole && SinkholeService.Instance.Status is not (SinkholeStatus.Listening or SinkholeStatus.PortBusy))
                SinkholeService.Instance.EnsureRunningForCurrentPins();

            string sink = SinkholeService.Instance.Status switch
            {
                SinkholeStatus.Listening => "listening on 127.0.0.1:443",
                SinkholeStatus.PortBusy => "port 443 busy — see below",
                SinkholeStatus.Error => "error",
                _ => "not running",
            };
            SinkholeStatusText.Text = sinkhole
                ? $"Sinkhole active — {sink}."
                : "Pins are silent (0.0.0.0) — attempts ARE being denied, but invisibly.";
            SinkholeDetailText.Text = sinkhole
                ? SinkholeService.Instance.StatusDetail ??
                  "Every attempt completes a handshake to this app, is logged with its process and intended hostname, then dropped. Nothing is ever sent back."
                : "Silent pins refuse connections before a packet exists — nothing observable remains, which is the point. " +
                  "Turn on Black Hole logging to make each attempt visible: the pin points at 127.0.0.1 and a local listener logs who knocked, then refuses to answer.";

            PinListText.Text = "Pinned: " + string.Join("   ·   ",
                pins.Select(p => $"{p.Hostname} → {p.Address}"));
        }

        private void RefreshTotals()
        {
            var proof = TelemetryProofService.Instance;
            if (proof.TotalDenied == 0)
            {
                TotalsText.Text = "No attempts recorded yet.";
                HostnameTotals.ItemsSource = null;
                return;
            }

            TotalsText.Text =
                $"{proof.TotalDenied:N0} attempt{(proof.TotalDenied == 1 ? "" : "s")} denied since {proof.FirstAttemptUtc?.ToLocalTime():yyyy-MM-dd HH:mm}" +
                $" · last at {proof.LastAttemptUtc?.ToLocalTime():HH:mm:ss}";

            HostnameTotals.ItemsSource = proof.TotalsByHostname()
                .Select(t => new HostnameTotal { Hostname = t.Hostname, Count = t.Count })
                .ToList();
        }

        private void RefreshFeed()
        {
            var rows = TelemetryProofService.Instance.Recent
                .Select(a => new AttemptRow
                {
                    TimeLocal = a.TimeUtc.ToLocalTime().ToString("MM-dd HH:mm:ss"),
                    Hostname = a.Hostname,
                    ProcessName = TelemetryProofService.ProcessKey(a),
                    Pid = a.Pid,
                    DeniedBy = a.DeniedBy,
                    CommandLine = a.CommandLine,
                    ProcessImage = a.ProcessImage,
                    PeerEndpoint = a.PeerEndpoint,
                })
                .ToList();
            AttemptsGrid.ItemsSource = rows;
            if (rows.Count > 0) AttemptsGrid.ScrollIntoView(rows[^1]);
        }

        // ── Sinkhole toggle ───────────────────────────────────────────────

        private async void SinkholeToggle_Click(object sender, RoutedEventArgs e)
        {
            if (_toggling) return;
            var toggle = (ToggleButton)sender;
            bool enable = toggle.IsChecked == true;

            if (enable && !await ConfirmSinkholeAsync())
            {
                toggle.IsChecked = false;
                return;
            }

            _toggling = true;
            try
            {
                string address = enable ? HostsTelemetryPins.SinkholeAddress : HostsTelemetryPins.SilentAddress;
                string path = HostsTelemetryPins.HostsPath();
                string text = File.ReadAllText(path);
                string updated = HostsTelemetryPins.SetPinAddress(text, address);
                File.WriteAllText(path, updated);           // UTF-8 without BOM, like every other writer here
                FlushDns();
                if (enable) SinkholeService.Instance.EnsureRunningForCurrentPins();
                else SinkholeService.Instance.Stop();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Could not update the hosts file: {ex.Message}\n\nThe pins were left unchanged.",
                    "Sinkhole", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            finally
            {
                _toggling = false;
                RefreshAll();
            }
        }

        private Task<bool> ConfirmSinkholeAsync() => Task.Run(() =>
        {
            bool ok = false;
            Dispatcher.Invoke(() =>
            {
                ok = MessageBox.Show(
                    "Turn on sinkhole mode?\n\n" +
                    "The telemetry pins will point at 127.0.0.1 instead of 0.0.0.0, and LookSee listens on " +
                    "loopback port 443 so every attempt is logged — process, PID, and the hostname from the TLS " +
                    "hello — then dropped with no reply. Nothing leaves the machine either way.\n\n" +
                    "Two things to know:\n" +
                    "• Proof is collected while LookSee is running; with the app closed, attempts to the pin " +
                    "still fail instantly (nothing is listening), just unlogged\n" +
                    "• If another local server already owns 127.0.0.1:443 (local HTTPS dev), the sinkhole stays off " +
                    "and the toggle will say so",
                    "Sinkhole mode", MessageBoxButton.OKCancel, MessageBoxImage.Question) == MessageBoxResult.OK;
            });
            return ok;
        });

        private static void FlushDns()
        {
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "ipconfig.exe",
                    Arguments = "/flushdns",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                };
                using var p = System.Diagnostics.Process.Start(psi);
                p?.WaitForExit(5000);
            }
            catch { /* best-effort — the pin applies on next resolution regardless */ }
        }

        // ── Feed interactions ─────────────────────────────────────────────

        private void AttemptsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (AttemptsGrid.SelectedItem is not AttemptRow row)
            {
                DetailText.Text = "";
                return;
            }
            DetailText.Text =
                $"{row.ProcessImage ?? "(process image unavailable)"} (pid {row.Pid}) attempted {row.Hostname} " +
                $"from {row.PeerEndpoint} at {row.TimeLocal} — denied at sinkhole, no reply sent.\n" +
                $"Command line: {row.CommandLine ?? "(unavailable)"}";
        }

        private void ExportBtn_Click(object sender, RoutedEventArgs e)
        {
            var rows = TelemetryProofService.Instance.Recent;
            if (rows.Count == 0)
            {
                MessageBox.Show("Nothing recorded yet — there is no proof to export.", "Export",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Export denied-telemetry proof",
                Filter = "CSV (*.csv)|*.csv",
                FileName = $"telemetry-block-proof-{DateTime.Now:yyyy-MM-dd-HHmm}.csv"
            };
            if (dialog.ShowDialog() != true) return;

            var sb = new StringBuilder();
            sb.AppendLine("Time (local),Hostname,Process,PID,DeniedBy,PeerEndpoint,ProcessImage,CommandLine");
            foreach (var a in rows)
            {
                sb.AppendLine(string.Join(",",
                    new[] {
                        a.TimeUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
                        a.Hostname, TelemetryProofService.ProcessKey(a), a.Pid.ToString(), a.DeniedBy,
                        a.PeerEndpoint, a.ProcessImage, a.CommandLine
                    }.Select(CsvEscape)));
            }
            File.WriteAllText(dialog.FileName, sb.ToString(), Encoding.UTF8);
            MessageBox.Show($"Exported {rows.Count} rows to\n{dialog.FileName}", "Export",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void ClearBtn_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show(
                    "Delete the denied-attempt history (telemetry_proof.jsonl)?\n\nThe hosts pins and the sinkhole " +
                    "itself are untouched — only the record of past attempts is cleared.",
                    "Clear history", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
                return;
            TelemetryProofService.Instance.Clear();
            RefreshAll();
        }

        private static string CsvEscape(string value)
        {
            value ??= "";
            return value.Contains(',') || value.Contains('"') || value.Contains('\n')
                ? "\"" + value.Replace("\"", "\"\"") + "\""
                : value;
        }
    }
}
