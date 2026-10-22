using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using LookSee.Services;

namespace LookSee.Views
{
    /// <summary>
    /// Windows Defender tab — the monitoring surface that earns it a tab (not
    /// just a Settings card): live MsMpEng CPU/memory with a 5-minute sparkline,
    /// engine/scan status, scans with durations paired from Defender's event
    /// log, a live activity feed, and manual scan/definition-update triggers.
    /// The preference knobs (scan CPU cap, idle-only scans) live here too; the
    /// exclusions view stays read-only with its explanation (see
    /// DefenderPreferencesService for the rationale).
    /// </summary>
    public partial class DefenderView : UserControl
    {
        private const string Glyphs = "▁▂▃▄▅▆▇█";

        private readonly DefenderPreferencesService _prefs = new();
        private DefenderMonitoringService _monitor;
        private DispatcherTimer _uiTimer;
        private DispatcherTimer _cpuDebounce;
        private bool _loading;
        private int _appliedCpu = -1;
        private bool _lastTamper;   // last known tamper state: routes sets to the policy path

        public DefenderView()
        {
            InitializeComponent();

            _monitor = new DefenderMonitoringService();
            _monitor.OnError += msg => Dispatcher.BeginInvoke(() =>
                HeaderStatusText.Text = $"⚠ {msg}");
            _monitor.OnActivity += _ => Dispatcher.BeginInvoke(RefreshFeed);

            // CPU-cap changes apply after the user stops dragging for a beat —
            // one Set-MpPreference per settled value, not per tick.
            _cpuDebounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(600) };
            _cpuDebounce.Tick += async (s, e) =>
            {
                _cpuDebounce.Stop();
                await ApplyCpuAsync();
            };

            // UI refresh for the live resource strip and scan list (the feed
            // itself is event-driven).
            _uiTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _uiTimer.Tick += (s, e) => RefreshLive();
        }

        // -----------------------------------------------------------------------
        // Lifecycle: lazy start on tab selection, stop on tab leave
        // -----------------------------------------------------------------------

        private async void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            _monitor.Start();
            _uiTimer.Start();
            RefreshLive();
            RefreshFeed();
            await LoadPreferencesAsync();
        }

        private void UserControl_Unloaded(object sender, RoutedEventArgs e)
        {
            _uiTimer?.Stop();
            _cpuDebounce?.Stop();
            _monitor.Stop();
        }

        private async void RefreshBtn_Click(object sender, RoutedEventArgs e) => await LoadPreferencesAsync();

        // -----------------------------------------------------------------------
        // Preferences (moved from the former Settings card)
        // -----------------------------------------------------------------------

        private async Task LoadPreferencesAsync()
        {
            _loading = true;
            try
            {
                HeaderStatusText.Text = "Reading Defender state…";
                var state = await _prefs.GetStateAsync();
                PopulatePreferences(state);
            }
            finally
            {
                _loading = false;
            }
        }

        private void PopulatePreferences(DefenderPreferencesService.DefenderState state)
        {
            // Hold the guard for the whole population: assigning slider/checkbox
            // values raises their change events, which must not route back into
            // Set-MpPreference while we're only reflecting state.
            _loading = true;
            try
            {
                bool available = state.Available;
                DefenderCpuSlider.IsEnabled = available;
                IdleScanCheck.IsEnabled = available;
                QuickScanBtn.IsEnabled = available;
                FullScanBtn.IsEnabled = available;
                UpdateSigBtn.IsEnabled = available;

                if (!available)
                {
                    PrefStatusText.Text = "⚠ " + state.UnavailableReason;
                    EngineStatusText.Text = "Windows Defender is not managing this machine.";
                    VersionsText.Text = "";
                    DefenderCpuValueText.Text = "—";
                    IdleScanCheck.IsChecked = false;
                    ExclPathsList.ItemsSource = null;
                    ExclProcsList.ItemsSource = null;
                    ExclExtsList.ItemsSource = null;
                    DefenderExclusionSummaryText.Text = "";
                    return;
                }

                string rtp = state.RealTimeProtection == null ? "unknown" : (state.RealTimeProtection == true ? "on" : "off");
                string tamper = state.TamperProtected == null ? "unknown" : (state.TamperProtected == true ? "on" : "off");
                _lastTamper = state.TamperProtected == true;
                PrefStatusText.Text = $"Real-time protection: {rtp} · Tamper protection: {tamper}" +
                    (string.IsNullOrEmpty(state.RunningMode) ? "" : $" · mode: {state.RunningMode}") +
                    (state.PolicyCpuLoadFactor == null && state.PolicyScanOnlyIfIdle == null
                        ? ""
                        : " · policy-set values in effect (tamper-safe route)");

                // Policy values own the setting whenever they exist — Defender
                // applies them over the preference on its next config refresh.
                int cpu = state.PolicyCpuLoadFactor ?? state.ScanCpuLoadFactor;
                _appliedCpu = Math.Clamp(cpu, 5, 100);
                DefenderCpuSlider.Value = _appliedCpu;
                DefenderCpuValueText.Text = cpu == 50
                    ? $"{_appliedCpu}% (Windows default)"
                    : cpu == 0 ? "no cap" : $"{_appliedCpu}%";

                IdleScanCheck.IsChecked = state.PolicyScanOnlyIfIdle ?? state.ScanOnlyIfIdle;

                // Engine card
                EngineStatusText.Text =
                    $"Real-time protection {rtp} · Tamper protection {tamper}" +
                    (string.IsNullOrEmpty(state.RunningMode) ? "" : $" · running mode: {state.RunningMode}") + "\n" +
                    $"Last quick scan: {DescribeScan(state.QuickScanStartUtc, state.QuickScanEndUtc)}\n" +
                    $"Last full scan:  {DescribeScan(state.FullScanStartUtc, state.FullScanEndUtc)}";
                VersionsText.Text =
                    $"Platform {NullDash(state.ProductVersion)} · engine {NullDash(state.EngineVersion)} · " +
                    $"security intelligence {NullDash(state.SignatureVersion)}" +
                    (state.SignatureLastUpdatedUtc == null ? "" : $" (updated {state.SignatureLastUpdatedUtc.Value.ToLocalTime():MM-dd HH:mm})");

                // Exclusions
                if (state.ExclusionsRequireElevation)
                {
                    ExclPathsList.ItemsSource = new[] { "administrator required to list exclusions" };
                    ExclProcsList.ItemsSource = new[] { "administrator required" };
                    ExclExtsList.ItemsSource = new[] { "administrator required" };
                    DefenderExclusionSummaryText.Text = "listing requires elevation";
                }
                else
                {
                    ExclPathsList.ItemsSource = state.ExclusionPaths.Any() ? state.ExclusionPaths : new[] { "none — every path is scanned" };
                    ExclProcsList.ItemsSource = state.ExclusionProcesses.Any() ? state.ExclusionProcesses : new[] { "none" };
                    ExclExtsList.ItemsSource = state.ExclusionExtensions.Any() ? state.ExclusionExtensions : new[] { "none" };
                    DefenderExclusionSummaryText.Text =
                        $"{state.ExclusionPaths.Count} path(s) · {state.ExclusionProcesses.Count} process(es) · {state.ExclusionExtensions.Count} extension(s)";
                }
            }
            finally
            {
                _loading = false;
            }
        }

        private static string NullDash(string value) => string.IsNullOrEmpty(value) ? "—" : value;

        private static string DescribeScan(DateTime? start, DateTime? end)
        {
            if (start == null) return "never";
            string duration = end == null ? " (still running or not recorded)" : $" ({(end.Value - start.Value).TotalSeconds:0}s)";
            return $"{start.Value.ToLocalTime():yyyy-MM-dd HH:mm:ss}{duration}";
        }

        private void DefenderCpuSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (_loading || DefenderCpuValueText == null) return;
            DefenderCpuValueText.Text = $"{DefenderCpuSlider.Value:0}%";
            _cpuDebounce.Stop();
            _cpuDebounce.Start();
        }

        private void DefenderPresetBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_loading || sender is not Button button || button.Tag is not string tag || !int.TryParse(tag, out int value))
                return;
            DefenderCpuSlider.Value = value;   // routed through the debounced apply
        }

        private async Task ApplyCpuAsync()
        {
            int value = (int)DefenderCpuSlider.Value;
            if (value == _appliedCpu) return;

            PrefStatusText.Text = $"Applying scan CPU cap {value}%…";
            // Tamper Protection on this build blocks (and slowly hangs)
            // Set-MpPreference — go straight to the policy value.
            var result = await _prefs.SetScanCpuLoadFactorAsync(value, preferPolicy: _lastTamper);
            if (result.Ok)
            {
                _appliedCpu = value;
                if (result.ViaPolicy)
                {
                    // Tamper-blocked build: the cap landed via the Group Policy
                    // value, and Get-MpPreference can lag the policy until
                    // Defender's next config refresh — hold the requested value
                    // on screen instead of snapping back to the stale read.
                    DefenderCpuSlider.Value = value;
                    DefenderCpuValueText.Text = $"{value}% (via policy)";
                    PrefStatusText.Text =
                        $"✓ Scan CPU cap {value}% applied via the Defender scan policy — Tamper Protection " +
                        "blocks direct preference writes on this build. Defender picks the policy up on its " +
                        "next config refresh (moments, or the next scan at the latest).";
                }
                else
                {
                    PopulatePreferences(result.Fresh);
                    PrefStatusText.Text += $"  ✓ Scans capped at {value}% average CPU (higher values finish faster).";
                }
            }
            else
            {
                // Direct write AND the policy fallback both refused — snap the
                // UI back to whatever Defender actually reports.
                string error = result.Error ?? result.Fresh?.UnavailableReason ?? "unknown error";
                if (result.Fresh?.Available == true) PopulatePreferences(result.Fresh);
                else PrefStatusText.Text = $"⚠ {error}";
                MessageBox.Show(
                    $"Windows Defender refused the change:\n\n{error}\n\n" +
                    "Tamper Protection or a Group Policy may own this setting —\n" +
                    "adjust it in Windows Security → Virus & threat protection settings.",
                    "Defender preference", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private async void IdleScanCheck_Changed(object sender, RoutedEventArgs e)
        {
            if (_loading || IdleScanCheck.IsChecked == null) return;
            bool want = IdleScanCheck.IsChecked == true;

            var result = await _prefs.SetScanOnlyIfIdleAsync(want, preferPolicy: _lastTamper);
            if (result.Ok)
            {
                PrefStatusText.Text = (result.ViaPolicy ? "✓ Applied via the Defender scan policy. " : "✓ ") +
                    (want
                        ? "Scheduled scans now wait for an idle machine."
                        : "Scheduled scans may run at any time.");
            }
            else
            {
                MessageBox.Show(
                    $"Windows Defender refused the change:\n\n{result.Error ?? result.Fresh?.UnavailableReason ?? "unknown error"}\n\n" +
                    "Tamper Protection or a Group Policy may own this setting.",
                    "Defender preference", MessageBoxButton.OK, MessageBoxImage.Warning);
                if (result.Fresh?.Available == true)
                    PopulatePreferences(result.Fresh);
            }
        }

        private void OpenSecurityExclusions_Click(object sender, RoutedEventArgs e)
        {
            // Protocol launch through the shell — lands on Virus & threat
            // protection settings, where "Add or remove exclusions" lives.
            // Windows Security collects the confirmation itself; the app
            // never writes exclusions (read-only stance).
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "windowsdefender://threatsettings",
                    UseShellExecute = true
                });
                HeaderStatusText.Text = "Opened Windows Security — exclusions are under Virus & threat protection settings.";
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Could not open Windows Security:\n\n{ex.Message}\n\nOpen it manually and go to\n" +
                    "Virus & threat protection → Manage settings → Exclusions.",
                    "Windows Security", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        // -----------------------------------------------------------------------
        // Actions: scans + definitions
        // -----------------------------------------------------------------------

        private async void QuickScanBtn_Click(object sender, RoutedEventArgs e) => await TriggerScanAsync("QuickScan");
        private async void FullScanBtn_Click(object sender, RoutedEventArgs e) => await TriggerScanAsync("FullScan");

        private async Task TriggerScanAsync(string scanType)
        {
            string label = scanType == "FullScan" ? "full scan" : "quick scan";
            var confirm = MessageBox.Show(
                $"Start a {label} now?\n\nIt runs in the background — watch it appear under Scans and\n" +
                "in the live resource strip (this is also how you reproduce a\nresource-heavy Defender before/after changing the CPU cap).",
                $"Start {label}", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (confirm != MessageBoxResult.Yes) return;

            HeaderStatusText.Text = $"Starting {label}…";
            var result = await _prefs.TriggerScanAsync(scanType);
            HeaderStatusText.Text = result.Ok
                ? $"✓ {label} launched — progress under Scans / Activity."
                : $"⚠ Could not start {label}: {result.Error ?? "unknown error"}";
        }

        private async void UpdateSigBtn_Click(object sender, RoutedEventArgs e)
        {
            HeaderStatusText.Text = "Updating security intelligence…";
            var result = await _prefs.UpdateSignaturesAsync();
            HeaderStatusText.Text = result.Ok
                ? "✓ Definition update launched — completion shows in Activity."
                : $"⚠ Could not update definitions: {result.Error ?? "unknown error"}";
        }

        // -----------------------------------------------------------------------
        // Live monitoring
        // -----------------------------------------------------------------------

        private void RefreshLive()
        {
            var sample = _monitor.Latest;
            var history = _monitor.HistorySnapshot();

            ResourceText.Text = sample == null
                ? "sampling…"
                : $"MsMpEng: {sample.ProcCpu:0.0}% CPU · machine: {sample.MachineCpu:0.0}% · memory: {sample.WorkingSetPrivate / 1048576.0:0} MB";
            SparkText.Text = Sparkline(history);

            var scans = _monitor.ScanSnapshot();
            ScansText.Visibility = scans.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            ScansList.ItemsSource = scans.Select(s => s.Display).ToList();
        }

        /// <summary>5-minute MsMpEng CPU as 30 ten-second buckets, max per bucket.</summary>
        private static string Sparkline(System.Collections.Generic.List<DefenderMonitoringService.ResourceSample> history)
        {
            if (history == null || history.Count == 0) return "";
            const int buckets = 30;
            var maxes = new double[buckets];
            DateTime newest = history[^1].TimeUtc;
            foreach (var s in history)
            {
                double secondsAgo = (newest - s.TimeUtc).TotalSeconds;
                if (secondsAgo < 0) secondsAgo = 0;
                int bucket = buckets - 1 - (int)Math.Min(buckets - 1, secondsAgo / 10);
                maxes[bucket] = Math.Max(maxes[bucket], s.ProcCpu);
            }
            double max = maxes.Max();
            if (max <= 0) return new string('·', buckets);

            var sb = new StringBuilder(buckets);
            foreach (double v in maxes)
                sb.Append(v <= 0 ? '·' : Glyphs[Math.Min(Glyphs.Length - 1, (int)(v * Glyphs.Length / max))]);
            return sb.ToString();
        }

        private void RefreshFeed()
        {
            ActivityGrid.ItemsSource = _monitor.FeedSnapshot();
        }
    }
}
