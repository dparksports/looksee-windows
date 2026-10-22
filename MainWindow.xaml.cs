using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Windows;
using System.Windows.Media;
using System.Windows.Controls;
using System.Windows.Threading;
using System.IO;
using LookSee.Models;
using LookSee.Services;
using LookSee.Views;
using LookSee.Helpers;

namespace LookSee
{
    public partial class MainWindow : Window
    {
        private SecurityEnforcer _enforcer;
        private TrayNotifier _trayNotifier;

        private static string AppVersion =>
            FileVersionInfo.GetVersionInfo(Environment.ProcessPath).ProductVersion ?? "unknown";

        public MainWindow()
        {
            InitializeComponent();

            // Live version from the assembly instead of a hardcoded string
            VersionText.Text = $"LookSee v{AppVersion}";

            // The theme itself is applied in App.OnStartup before any window
            // loads; here the toggle just shows what clicking it will do.
            UpdateThemeToggleLabel();

            // Layer-3 crash safety: if a previous run died mid-intercept, the
            // journal on disk still describes the hooks it installed — undo
            // them (proxy, firewall rule, CA) before anything else runs.
            Services.InterceptSystemHooks.RecoverAfterCrash();

            InitializeEnforcer();

            // App-level TCP capture + traffic aggregation: one raw socket
            // shared by the Python feed (Who Started It) and Phone Bill; the
            // aggregator runs whenever either captures and persists its
            // (process → destination → bytes) history across sessions.
            Services.TrafficAggregationService.Shared.Attach(Services.TcpStreamCaptureService.Shared);
            Services.TrafficAggregationService.Shared.Start();
        }

        private void InitializeEnforcer()
        {
            // Initialize system tray notifier first so it's ready for callbacks
            string iconPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "app_icon.ico");
            _trayNotifier = new TrayNotifier(iconPath);
            _trayNotifier.ToastActivated += BringWindowToForeground;

            _enforcer = new SecurityEnforcer(OnThreatDetected);
            _enforcer.StatusChanged += OnEnforcerStatusChanged;

            // Wire the tray toast notification for adapter events
            _enforcer.OnAdapterAlert = (title, message) =>
                Dispatcher.Invoke(() => _trayNotifier.ShowSecurityAlert(title, message));

            _enforcer.Start();

            // One-time, one-way import from a sibling AutoCommand install:
            // its ignore lists (so this machine's curated "don't show me"
            // choices carry over) and a read-only snapshot of its block
            // inventory (so rows can wear the ⛔ badge). Silent no-op when
            // AutoCommand isn't on the machine — LookSee is fully standalone.
            _ = RunFirstRunAutoCommandImportAsync();
        }

        private async System.Threading.Tasks.Task RunFirstRunAutoCommandImportAsync()
        {
            try
            {
                if (Services.AutoCommandImportService.AlreadyImported) return;
                var r = await Services.AutoCommandImportService.ImportAsync();
                if (r is { FoundAutoCommand: true } && r.NamesImported + r.ImagesImported > 0)
                    Dispatcher.Invoke(() => _trayNotifier?.ShowSecurityAlert(
                        "⇄ Imported from AutoCommand",
                        $"+{r.NamesImported} ignored process(es), +{r.ImagesImported} ignored app(s) carried over. " +
                        "AutoCommand itself was not changed.",
                        durationMs: 12000));
                // Prime the ⛔ block badges while we're here.
                await System.Threading.Tasks.Task.Run(
                    () => Services.FirewallBlockService.Instance.RefreshSnapshot());
            }
            catch { /* the bridge must never disturb startup */ }
        }

        private void BringWindowToForeground()
        {
            Dispatcher.Invoke(() =>
            {
                if (WindowState == WindowState.Minimized)
                    WindowState = WindowState.Normal;
                Activate();
                Topmost = true;
                Topmost = false;
                Focus();
            });
        }

        private string _currentThreatType;
        private string _currentThreatDetails;

        /// <summary>
        /// Lets tabs surface a finding on the app-level threat status bar
        /// (amber text + Review button) through the same path the Security
        /// Enforcer uses. Currently used by the Deliveries tab for
        /// UPLOAD-type jobs (ATT&CK T1197 exfiltration vector).
        /// </summary>
        public void RaiseExternalThreat(string type, string details) => OnThreatDetected(type, details);

        /// <summary>
        /// Who's Talking tab's encrypted-upload toasts: same Action Center
        /// path as the enforcer's, but activating the toast selects the
        /// Who's Talking tab instead of just raising the window.
        /// </summary>
        public void ShowTransmissionsToast(string title, string message)
        {
            _trayNotifier?.ShowSecurityAlert(title, message, durationMs: 10000, onActivated: () =>
                Dispatcher.Invoke(() => MainTabControl.SelectedItem = TransmissionsNavItem));
        }

        private void OnThreatDetected(string type, string details)
        {
            Dispatcher.Invoke(() =>
            {
                _currentThreatType = type;
                _currentThreatDetails = details;
                ThreatAlertText.Text = $"⚠ {type}: {details}";
                ThreatAlertText.Foreground = new SolidColorBrush(Color.FromRgb(0xE5, 0xA6, 0x31));
                ReviewAlertBtn.Visibility = Visibility.Visible;
            });
        }

        private void ReviewAlertBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_currentThreatType == "Privileged Task")
            {
                string msg = $"{_currentThreatDetails}\n\n" +
                             "This task is running with the highest system privileges. While some third-party updaters (like Edge or Chrome) do this legitimately, malware often uses it for persistence.\n\n" +
                             "Would you like to ignore this task permanently (Whitelist)?\n" +
                             "Click 'No' to keep alerting.";
                var result = MessageBox.Show(msg, "Review Threat", MessageBoxButton.YesNoCancel, MessageBoxImage.Warning);
                if (result == MessageBoxResult.Yes)
                {
                    // Extract task name and whitelist it
                    string taskName = _currentThreatDetails.Replace("High Risk Task detected: ", "").Trim();
                    SecurityEnforcer.WhitelistTask(taskName);
                    ThreatAlertText.Text = "✓ Task added to whitelist.";
                    ThreatAlertText.Foreground = new SolidColorBrush(Color.FromRgb(0x4E, 0xC9, 0x6F));
                    ReviewAlertBtn.Visibility = Visibility.Collapsed;
                }
            }
            else if (_currentThreatType == "Network Adapter")
            {
                string msg = $"Active Adapter Detected: {_currentThreatDetails}\n\n" +
                             "This adapter might be used for unauthorized tunneling or kernel debugging.\n\n" +
                             "Click 'Yes' to Block & Delete (removes device and service).\n" +
                             "Click 'No' to Whitelist (ignore this adapter permanently).\n" +
                             "Click 'Cancel' to ignore for now.";

                var result = MessageBox.Show(msg, "Review Network Adapter", MessageBoxButton.YesNoCancel, MessageBoxImage.Warning);
                if (result == MessageBoxResult.Yes)
                {
                    _enforcer.MitigateAdapter(_currentThreatDetails);
                    ThreatAlertText.Text = "✓ Adapter mitigated.";
                    ThreatAlertText.Foreground = new SolidColorBrush(Color.FromRgb(0x4E, 0xC9, 0x6F));
                    ReviewAlertBtn.Visibility = Visibility.Collapsed;
                }
                else if (result == MessageBoxResult.No)
                {
                    if (_currentThreatDetails.Contains("SSTP")) SecurityEnforcer.IsSstpAllowed = true;
                    if (_currentThreatDetails.Contains("Kernel Debug")) SecurityEnforcer.IsKernelDebugAllowed = true;
                    ThreatAlertText.Text = "✓ Adapter whitelisted.";
                    ThreatAlertText.Foreground = new SolidColorBrush(Color.FromRgb(0x4E, 0xC9, 0x6F));
                    ReviewAlertBtn.Visibility = Visibility.Collapsed;
                }
            }
            else
            {
                MessageBox.Show($"{_currentThreatType}\n\n{_currentThreatDetails}", "Security Alert", MessageBoxButton.OK, MessageBoxImage.Information);
                ReviewAlertBtn.Visibility = Visibility.Collapsed;
            }
        }

        private void OnEnforcerStatusChanged(string status, string colorType)
        {
            Dispatcher.Invoke(() =>
            {
                EnforcerStatusText.Text = $"Watchdog: {status}";
                EnforcerDot.Fill = colorType switch
                {
                    "Red" => new SolidColorBrush(Color.FromRgb(0xE5, 0x53, 0x4B)),
                    "Amber" => new SolidColorBrush(Color.FromRgb(0xE5, 0xA6, 0x31)),
                    _ => new SolidColorBrush(Color.FromRgb(0x4E, 0xC9, 0x6F))
                };
            });
        }

        // ── Theme toggle (status bar) ─────────────────────────────────────
        // Dark ↔ Light, applied live through ThemeService's DynamicResource
        // swap and remembered in HKCU for the next launch.

        private void ThemeToggleBtn_Click(object sender, RoutedEventArgs e)
        {
            bool lightNow = Services.ThemeService.Saved == "Light";
            Services.ThemeService.ApplyTheme(lightNow ? "Dark" : "Light");
            UpdateThemeToggleLabel();
        }

        private void UpdateThemeToggleLabel()
        {
            // The button always offers the look you'd switch TO.
            bool isLight = Services.ThemeService.Saved == "Light";
            ThemeToggleBtn.Content = isLight ? "🌙 Dark" : "☀ Light";
        }

        // ── Emergency internet restore (panic button) ───────────────────────
        //
        // The #1 self-inflicted outage from blocking is blocking svchost/DNS
        // or a Microsoft endpoint. This disables every block rule created by
        // LookSee or AutoCommand (they share one scheme) in one click —
        // reversible, nothing deleted. AutoCommand's Process Monitor ships
        // the same button with the same behavior.

        private async void RestoreInternetBtn_Click(object sender, RoutedEventArgs e)
        {
            var confirm = MessageBox.Show(
                "Restore internet access?\n\n" +
                "This DISABLES every firewall block rule created by LookSee or AutoCommand\n" +
                "(they share one block scheme — IP and process blocks, including legacy ones).\n" +
                "Nothing is deleted; re-enable blocks from wf.msc, or AutoCommand → Blocks\n" +
                "→ Manage all.\n\n" +
                "If this does not restore connectivity, the block came from another tool\n" +
                "or a proxy/VPN — this button only touches LookSee/AutoCommand rules.",
                "🚑 Restore Internet", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (confirm != MessageBoxResult.Yes) return;

            RestoreInternetBtn.IsEnabled = false;
            try
            {
                var result = await Services.FirewallBlockService.Instance
                    .SetAllBlocksEnabledAsync(false);

                // A stale DNS cache keeps sites dead even after the block is
                // lifted — flush it automatically so recovery is one click.
                string dnsNote;
                try
                {
                    var psi = new System.Diagnostics.ProcessStartInfo("ipconfig", "/flushdns")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        RedirectStandardOutput = true
                    };
                    using var p = System.Diagnostics.Process.Start(psi);
                    p.StandardOutput.ReadToEnd();
                    p.WaitForExit(5000);
                    dnsNote = p.ExitCode == 0
                        ? "The DNS cache was flushed automatically — no further steps needed."
                        : $"ipconfig /flushdns returned exit code {p.ExitCode}; run it manually if sites still fail.";
                }
                catch (Exception ex)
                {
                    dnsNote = $"Could not flush DNS automatically ({ex.Message}); run  ipconfig /flushdns  manually.";
                }

                string extra = result.FirstError != null ? $"\nFirst error: {result.FirstError}" : "";
                MessageBox.Show(
                    $"Disabled {result.Changed} of {result.Matched} block rule(s).{extra}\n\n" +
                    $"{dnsNote}\n\n" +
                    "To bring selected blocks back (wf.msc, or AutoCommand → Blocks → Manage all):\n" +
                    "  · 'Restore except Microsoft/Windows' — recommended: brings back your\n" +
                    "    real blocks, leaves the breakage-causing ones (red rows) off\n" +
                    "  · 'Re-enable all' — everything back on",
                    "🚑 Restore Internet", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            finally { RestoreInternetBtn.IsEnabled = true; }
        }

        protected override void OnClosed(EventArgs e)
        {
            _enforcer?.Stop();
            _trayNotifier?.Dispose();

            // Stop the shared capture FIRST so live flows finalize into the
            // aggregator, then persist that final state. (Content Unloaded
            // events fire after OnClosed, so tab-level Release may follow —
            // Stop is idempotent.)
            Services.TcpStreamCaptureService.Shared.Stop();
            Services.TrafficAggregationService.Shared.Shutdown();
            // Transmissions pipeline drains what the capture flush finalized
            // (up to its 3s budget), then releases its capture reference.
            Services.TransmissionsPipelineService.Shared.Stop();

            // Layer 3 must never outlive the app: stop restores the system
            // proxy, removes the QUIC block rule and untrusts the CA.
            Services.InterceptProxyService.Shared.StopSession("app exit");

            Services.TlsKeylogService.CleanupAtExit(); // drop the rotated TLS keylog leftover
            base.OnClosed(e);
        }
    }
}
