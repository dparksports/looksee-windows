using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using LookSee.OneSettingsCadence;

namespace LookSee.Views
{
    /// <summary>
    /// OneSettings tab — GUI face of OneSettingsCadence.Core. Everything the
    /// CLI does is here with the same engine and the same audit trail; the app
    /// manifest already demands administrator, so there is no UAC round-trip.
    /// The tab opens read-only (live state, observed runs); Apply/Restore ask
    /// first, run the engine's backup → register → verify → rollback flow, and
    /// report what actually landed.
    /// </summary>
    public partial class OneSettingsView : UserControl
    {
        private readonly CadenceEngine _engine = new();
        private CadenceEngine.LiveState _live;
        private CadenceEngine.DesiredState _saved;
        private TimeSpan? _pendingInterval;   // selected in the combo/custom box
        private ExternalStartMonitor _liveWatch;

        public OneSettingsView()
        {
            InitializeComponent();
        }

        private void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            _ = RefreshAllAsync();
            StartLiveWatch();
        }

        private void UserControl_Unloaded(object sender, RoutedEventArgs e) => StopLiveWatch();

        private void RefreshBtn_Click(object sender, RoutedEventArgs e) => _ = RefreshAllAsync();

        // ── live external-start watch ───────────────────────────────────────

        private void StartLiveWatch()
        {
            StopLiveWatch();
            _liveWatch = new ExternalStartMonitor();
            _liveWatch.ExternalStart += inst => Dispatcher.Invoke(() =>
            {
                RenderExternalStarts();
                WatchStatusText.Text = $"external start at {DateTime.Now:HH:mm:ss} — see feed below";
            });
            _liveWatch.Changed += () => Dispatcher.Invoke(RenderExternalStarts);
            _liveWatch.Start();

            WatchDot.Fill = FindResource(_liveWatch.SchedulerChannelOk ? "AccentGreenBrush" : "AccentRedBrush") as Brush;
            WatchStatusText.Text = !_liveWatch.SchedulerChannelOk
                ? "cannot read the Task Scheduler history channel — live watch unavailable"
                : _liveWatch.SysmonAvailable
                    ? "watching — launches that fire with no trigger are flagged here within seconds"
                    : "watching — Sysmon is not installed, so starts are flagged but fetch destinations are not (Sysmon Audit tab installs it)";
        }

        private void StopLiveWatch()
        {
            _liveWatch?.Dispose();
            _liveWatch = null;
        }

        private void RenderExternalStarts()
        {
            if (_liveWatch == null) return;
            ExternalStartsList.Items.Clear();
            foreach (var inst in _liveWatch.Correlator.Snapshot().Where(i => i.ConfirmedExternal))
            {
                var destinations = inst.Fetches.Select(f => f.Destination).Distinct().ToList();
                string fetches = destinations.Count == 0
                    ? "no connections recorded"
                    : string.Join(", ", destinations.Take(4)) + (destinations.Count > 4 ? ", …" : "");
                ExternalStartsList.Items.Add(
                    $"{inst.StartedUtc.ToLocalTime():HH:mm:ss}  external start · taskhostw pid {(inst.Pid > 0 ? inst.Pid.ToString() : "?")} · {fetches}" +
                    (inst.ExitedUtc is { } done ? $" · exited {done.ToLocalTime():HH:mm:ss}" : " · running…"));
            }
        }

        // ── refresh ─────────────────────────────────────────────────────────

        private async Task RefreshAllAsync()
        {
            ApplyStatusText.Text = "reading live task…";
            try
            {
                var live = await Task.Run(() => _engine.ReadLive());
                var saved = await Task.Run(() => CadenceEngine.LoadState());
                bool watchdog = await Task.Run(() => _engine.WatchdogInstalled());
                var backups = await Task.Run(() => CadenceEngine.ListBackups());
                var history = await Task.Run(() => RunHistory.Read(7));

                _live = live;
                _saved = saved;
                RenderLive(live, saved, watchdog);
                RenderBackups(backups);
                await RenderComplianceAsync(live, saved, history);
            }
            catch (Exception ex)
            {
                ApplyStatusText.Text = "";
                LiveStateText.Text = $"could not read the task: {ex.Message}";
                LiveStateText.Foreground = FindResource("AccentRedBrush") as Brush;
            }
        }

        private void RenderLive(CadenceEngine.LiveState live, CadenceEngine.DesiredState saved, bool watchdog)
        {
            LiveStateText.Foreground = FindResource("TextPrimaryBrush") as Brush;
            var sb = new StringBuilder();
            sb.Append($"Interval {Fmt(live.Interval)} · random delay {Fmt(live.RandomDelay ?? TimeSpan.Zero)}" +
                      $" · WNF triggers {live.WnfStateNames.Count} · state {live.TaskState} · runs as {live.PrincipalUserId} (SYSTEM)\n");
            sb.Append($"Last run {(live.LastRun?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "never")}" +
                      $"{(live.LastResult is { } r ? $" (result 0x{r:X})" : "")}" +
                      $" · next run {(live.NextRun?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "—")}");
            if (live.Interval is { } iv)
                sb.Append($"\n≈{24.0 / iv.TotalHours:0.#} fetches/day from the timer alone" +
                          (live.WnfStateNames.Count > 0 ? ", plus WNF state-change fetches on top" : ""));
            LiveStateText.Text = sb.ToString();

            // drift banner — the whole reason the watchdog exists
            var drift = saved != null
                ? CadenceEngine.FindMismatches(live, ParsePt(saved.DesiredInterval), saved.KeepWnf, saved.OriginalWnfCount)
                : new System.Collections.Generic.List<string>();
            DriftBanner.Visibility = drift.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            if (drift.Count > 0)
            {
                DriftText.Text = "Windows rewrote this task — it no longer matches your saved cadence:\n" +
                                 string.Join("\n", drift.ConvertAll(d => "· " + d)) +
                                 $"\nSaved: {IntervalParser.ToHuman(ParsePt(saved.DesiredInterval))}, set {saved.SetAtUtc.ToLocalTime():yyyy-MM-dd HH:mm}" +
                                 (saved.LastEnforcedUtc is { } le ? $", last enforced {le.ToLocalTime():MM-dd HH:mm}" : "");
            }

            // reflect the saved state in the controls
            if (saved != null && saved.Watchdog) WatchdogCheck.IsChecked = true;
            WatchdogCheck.IsEnabled = true;
            AuditLink.Visibility = File.Exists(CadenceEngine.AuditFile) ? Visibility.Visible : Visibility.Collapsed;
        }

        private async Task RenderComplianceAsync(CadenceEngine.LiveState live, CadenceEngine.DesiredState saved, RunHistory.History history)
        {
            TimeSpan cadence = saved != null ? ParsePt(saved.DesiredInterval)
                                             : live.Interval ?? TimeSpan.FromHours(3.33);
            var c = await Task.Run(() => RunHistory.Compute(history.Runs, cadence, saved != null, 7, live.WnfStateNames.Count > 0));
            ComplianceText.Text =
                $"{c.TotalRuns} run(s) in the last 7 days — {c.TimerRuns} timer · {c.EventRuns} event/WNF · {c.LogonRuns} logon · {c.ManualRuns} manual — " +
                $"expected ≈{c.ExpectedTimerRuns} timer run(s) at {(saved != null ? $"your saved {IntervalParser.ToHuman(cadence)}" : $"the stock {IntervalParser.ToHuman(cadence)}")}.\n" +
                c.Verdict +
                (history.ChannelWasDisabled ? "\nTask Scheduler history was disabled — the tab enabled it, so the window starts now." : "");
            ComplianceText.Foreground = c.TimerRuns > c.ExpectedTimerRuns + 1
                ? FindResource("AccentAmberBrush") as Brush
                : FindResource("TextPrimaryBrush") as Brush;

            RunsList.Items.Clear();
            foreach (var run in history.Runs)
                RunsList.Items.Add($"{run.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}   {run.Trigger,-16}   result {(run.ResultCode is { } rc ? $"0x{rc:X}" : "—")}");
        }

        private void RenderBackups(System.Collections.Generic.List<CadenceEngine.BackupInfo> backups)
        {
            BackupCombo.Items.Clear();
            BackupCombo.Items.Add("newest backup");
            foreach (var b in backups)
                BackupCombo.Items.Add($"{Path.GetFileName(b.File)}   ({b.Written:yyyy-MM-dd HH:mm:ss}, {b.Size:N0} B)");
            BackupCombo.SelectedIndex = 0;
        }

        // ── cadence selection ───────────────────────────────────────────────

        private void CadenceCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (CadenceCombo.SelectedItem is not ComboBoxItem item) return;
            string tag = item.Tag as string;
            bool custom = tag == "custom";
            CustomCadenceBox.Visibility = custom ? Visibility.Visible : Visibility.Collapsed;
            CustomCadenceHint.Visibility = custom ? Visibility.Visible : Visibility.Collapsed;

            if (tag == "stock" || tag == null)
            {
                _pendingInterval = null;
                RangeWarningText.Visibility = Visibility.Collapsed;
                ApplyBtn.IsEnabled = false;
                ApplyStatusText.Text = "pick an interval to apply, or use Restore stock to return the newest backup";
            }
            else if (custom)
            {
                // validity resolved by the TextChanged handler
                ValidateCustomInterval();
            }
            else
            {
                _pendingInterval = TimeSpan.FromHours(double.Parse(tag));
                EnableApplyWithRangeCheck(_pendingInterval.Value);
            }
        }

        private void CustomCadenceBox_TextChanged(object sender, TextChangedEventArgs e) => ValidateCustomInterval();

        private void ValidateCustomInterval()
        {
            if (CustomCadenceBox.Visibility != Visibility.Visible) return; // not in custom mode yet
            if (IntervalParser.TryParse(CustomCadenceBox.Text, out TimeSpan t, out string err))
            {
                _pendingInterval = t;
                EnableApplyWithRangeCheck(t);
            }
            else
            {
                _pendingInterval = null;
                ApplyBtn.IsEnabled = false;
                RangeWarningText.Visibility = Visibility.Visible;
                RangeWarningText.Text = err;
            }
        }

        private void EnableApplyWithRangeCheck(TimeSpan interval)
        {
            ApplyBtn.IsEnabled = true;
            string warning = IntervalParser.RangeWarning(interval);
            RangeWarningText.Visibility = warning == null ? Visibility.Collapsed : Visibility.Visible;
            RangeWarningText.Text = warning ?? "";
            ApplyStatusText.Text = "";
        }

        // ── actions ─────────────────────────────────────────────────────────

        private async void PreviewBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_live == null) await RefreshAllAsync();
            if (_live == null) return;
            if (_pendingInterval == null)
            {
                MessageBox.Show("Pick a fetch interval first — Preview shows exactly what that choice would change.",
                    "OneSettings preview", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            try
            {
                bool keepWnf = KeepWnfCheck.IsChecked == true;
                var t = await Task.Run(() => CadenceEngine.Transform(_live.Xml, _pendingInterval.Value, keepWnf));
                string summary =
                    $"repetition interval {Fmt(t.OldInterval)}  →  {Fmt(t.NewInterval)}\n" +
                    $"random delay {Fmt(t.OldRandomDelay ?? TimeSpan.Zero)}  →  0 (PT0S)\n" +
                    (t.RemovedWnfNames.Count > 0
                        ? $"removing {t.RemovedWnfNames.Count} WNF state-change trigger(s): {string.Join(", ", t.RemovedWnfNames)}\n"
                        : "WNF triggers kept\n") +
                    string.Join("\n", t.Notes.ConvertAll(n => "· " + n));
                ShowXmlPreview("Preview — the exact XML Apply would register", summary, t.ModifiedXml);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Preview failed: {ex.Message}", "OneSettings preview",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private async void ApplyBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_pendingInterval == null) return;
            bool keepWnf = KeepWnfCheck.IsChecked == true;
            bool watchdog = WatchdogCheck.IsChecked == true;
            TimeSpan interval = _pendingInterval.Value;

            string wnfLine = keepWnf ? "the WNF state-change triggers stay (expect extra fetches when Windows state changes)"
                                     : $"the {(_live?.WnfStateNames.Count.ToString() ?? "?")} WNF state-change triggers are removed";
            var choice = MessageBox.Show(
                $"Apply this cadence to {CadenceEngine.TaskPath}?\n\n" +
                $"· repetition interval → {IntervalParser.ToHuman(interval)} ({IntervalParser.ToTaskForm(interval)}), random delay → 0\n" +
                $"· {wnfLine}\n" +
                (watchdog ? "· watchdog task installed (daily 03:30 + logon, as SYSTEM, re-applies this cadence)\n" : "") +
                $"\nA timestamped backup of the current XML is written first; the live task is re-read and verified after, and rolled back automatically on any mismatch.",
                "Apply OneSettings cadence", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (choice != MessageBoxResult.Yes) return;

            ApplyBtn.IsEnabled = false;
            ApplyStatusText.Text = "applying… (backup → register → verify)";
            try
            {
                // the app itself is the watchdog target — App.OnStartup handles
                // "onesettings-enforce" headlessly, so the GUI never appears at 03:30
                string exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;
                var r = await Task.Run(() => _engine.Apply(interval, keepWnf, watchdog, exePath, "onesettings-enforce"));
                ApplyStatusText.Foreground = FindResource(r.Ok ? "AccentGreenBrush" : "AccentRedBrush") as Brush;
                if (r.Ok)
                {
                    ApplyStatusText.Text =
                        $"verified: every {IntervalParser.ToHuman(r.Interval)}, no jitter, {r.After.WnfStateNames.Count} WNF trigger(s), next run {r.After.NextRun?.ToLocalTime():yyyy-MM-dd HH:mm:ss}" +
                        (r.BackupFile != null ? $" · backup {Path.GetFileName(r.BackupFile)}" : "");
                }
                else
                {
                    ApplyStatusText.Text =
                        (r.FatalError != null ? $"failed: {r.FatalError}" : "verification failed: " + string.Join("; ", r.Problems)) +
                        (r.RollbackFailed ? " — ROLLBACK ALSO FAILED, restore manually from the backups below"
                                          : r.RolledBack ? " — rolled back, the task is unchanged" : " — nothing was changed");
                }
            }
            catch (Exception ex)
            {
                ApplyStatusText.Foreground = FindResource("AccentRedBrush") as Brush;
                ApplyStatusText.Text = $"failed: {ex.Message}";
            }
            await RefreshAllAsync();
        }

        private async void RestoreBtn_Click(object sender, RoutedEventArgs e)
        {
            string file = null;
            if (BackupCombo.SelectedIndex > 0 && BackupCombo.SelectedItem is string s)
                file = s.Split(' ')[0]; // "RefreshCache-….xml   (…)"

            var choice = MessageBox.Show(
                "Restore the stock task definition from " +
                (file ?? "the newest backup") + "?\n\n" +
                "The saved cadence is cleared and the watchdog task removed (it would re-apply the old cadence). A safety backup of the current definition is written first, and the live task is verified after.",
                "Restore stock", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (choice != MessageBoxResult.Yes) return;

            ApplyStatusText.Foreground = FindResource("TextSecondaryBrush") as Brush;
            ApplyStatusText.Text = "restoring…";
            try
            {
                var r = await Task.Run(() => _engine.RestoreFrom(file));
                ApplyStatusText.Foreground = FindResource(r.Ok ? "AccentGreenBrush" : "AccentRedBrush") as Brush;
                if (r.Ok)
                {
                    ApplyStatusText.Text =
                        $"restored {Path.GetFileName(r.BackupFile)} — verified {Fmt(r.After.Interval)}, {r.After.WnfStateNames.Count} WNF trigger(s), next run {r.After.NextRun?.ToLocalTime():yyyy-MM-dd HH:mm:ss}";
                }
                else
                {
                    ApplyStatusText.Text =
                        (r.FatalError != null ? $"failed: {r.FatalError}" : "verification failed: " + string.Join("; ", r.Problems)) +
                        (r.RollbackFailed ? " — ROLLBACK ALSO FAILED, restore manually from the backups below"
                                          : r.RolledBack ? " — pre-restore definition put back" : " — nothing was changed");
                }
            }
            catch (Exception ex)
            {
                ApplyStatusText.Foreground = FindResource("AccentRedBrush") as Brush;
                ApplyStatusText.Text = $"failed: {ex.Message}";
            }
            await RefreshAllAsync();
        }

        private async void ReapplyBtn_Click(object sender, RoutedEventArgs e)
        {
            ApplyStatusText.Foreground = FindResource("TextSecondaryBrush") as Brush;
            ApplyStatusText.Text = "re-applying the saved cadence…";
            try
            {
                var r = await Task.Run(() => _engine.Enforce());
                ApplyStatusText.Foreground = FindResource(r.Applied || !r.DriftFound ? "AccentGreenBrush" : "AccentRedBrush") as Brush;
                ApplyStatusText.Text = r.FatalError != null ? $"failed: {r.FatalError}"
                    : r.Applied ? $"re-applied and verified · next run {r.After.NextRun?.ToLocalTime():yyyy-MM-dd HH:mm:ss}"
                    : !r.DriftFound ? "no drift remained — the live task already matches"
                    : "could not verify the re-applied cadence: " + string.Join("; ", r.Problems);
            }
            catch (Exception ex)
            {
                ApplyStatusText.Foreground = FindResource("AccentRedBrush") as Brush;
                ApplyStatusText.Text = $"failed: {ex.Message}";
            }
            await RefreshAllAsync();
        }

        private void AuditLink_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (File.Exists(CadenceEngine.AuditFile))
                    Process.Start(new ProcessStartInfo(CadenceEngine.AuditFile) { UseShellExecute = true });
                else
                    MessageBox.Show("No changes recorded yet — the audit trail is created by the first Apply/Restore.",
                        "Audit trail", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Could not open the audit trail: {ex.Message}\n({CadenceEngine.AuditFile})",
                    "Audit trail", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        // ── helpers ─────────────────────────────────────────────────────────

        private static TimeSpan ParsePt(string pt) => System.Xml.XmlConvert.ToTimeSpan(pt ?? "PT0S");

        private static string Fmt(TimeSpan? t) =>
            t is { } v ? $"{IntervalParser.ToHuman(v)} ({IntervalParser.ToTaskForm(v)})" : "none";

        /// <summary>A read-only scrollable XML window (the app's disclosure style: show exactly what would be written).</summary>
        private void ShowXmlPreview(string title, string summary, string xml)
        {
            var summaryBlock = new TextBlock
            {
                Text = summary,
                TextWrapping = TextWrapping.Wrap,
                FontSize = 12,
                Margin = new Thickness(12),
                Foreground = FindResource("TextPrimaryBrush") as Brush,
            };
            var xmlBox = new TextBox
            {
                Text = xml,
                IsReadOnly = true,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 11.5,
                TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                Margin = new Thickness(12, 0, 12, 12),
                Padding = new Thickness(8),
                Background = FindResource("SurfaceAltBrush") as Brush,
                Foreground = FindResource("TextPrimaryBrush") as Brush,
                BorderBrush = FindResource("BorderBrush") as Brush,
            };
            var close = new Button
            {
                Content = "Close",
                Padding = new Thickness(16, 4, 16, 4),
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(12),
            };
            var window = new Window
            {
                Title = title,
                Width = 880,
                Height = 700,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = Window.GetWindow(this),
            };
            close.Click += (_, _) => window.Close();

            var grid = new Grid();
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Grid.SetRow(summaryBlock, 0);
            Grid.SetRow(xmlBox, 1);
            Grid.SetRow(close, 2);
            grid.Children.Add(summaryBlock);
            grid.Children.Add(xmlBox);
            grid.Children.Add(close);
            window.Content = grid;
            window.ShowDialog();
        }
    }
}
