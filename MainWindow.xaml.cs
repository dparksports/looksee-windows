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
