using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using LookSee.Helpers;
using LookSee.Models;
using LookSee.Services;

namespace LookSee.Views
{
    public partial class SysmonStatusView : UserControl
    {
        private readonly SysmonDiagnosticsService _diagnostics = new();
        private readonly SysmonInstallerService _installer = new();
        private readonly SysmonProcessAuditService _audit = new();
        private readonly ObservableCollection<SysmonProcessEvent> _events = new();

        private const int MaxFeedRows = 300;
        private bool _isInitialized = false;

        public SysmonStatusView()
        {
            InitializeComponent();
            ProcessGrid.ItemsSource = _events;
            _audit.OnProcessCreated += evt => Dispatcher.Invoke(() => AddFeedRow(evt));
            _audit.OnError += msg => Dispatcher.Invoke(() => FeedStatusText.Text = msg);
        }

        private async void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            if (_isInitialized) return;
            _isInitialized = true;
            await RefreshStatusAsync();

            // If Sysmon is already recording process creations, show history
            // immediately instead of waiting for the next launch. ToggleCapture
            // performs the backfill — doing it here too would duplicate rows.
            var info = await _diagnostics.GetStatusAsync();
            if (info.State == SysmonInstallState.Installed)
                ToggleCapture();
        }

        private async Task RefreshStatusAsync()
        {
            StateText.Text = "Checking…";
            var info = await _diagnostics.GetStatusAsync();

            StateText.Text = info.StateText;
            StateDot.Fill = info.State switch
            {
                SysmonInstallState.Installed => new SolidColorBrush(Color.FromRgb(0x4E, 0xC9, 0x6F)),
                SysmonInstallState.NotInstalled => new SolidColorBrush(Color.FromRgb(0xE5, 0x48, 0x4D)),
                _ => new SolidColorBrush(Color.FromRgb(0xE5, 0xA6, 0x31))
            };
            DetailText.Text = info.State switch
            {
                SysmonInstallState.Installed =>
                    "Every process launch, network connection and DNS lookup is being recorded to the local event log. " +
                    "The svchost Timeline (Who Started It) uses this feed live; this tab shows the raw audit trail.",
                SysmonInstallState.NotInstalled =>
                    "Sysmon is not installed. Without it, processes that exit within seconds (spawned helpers, one-shot " +
                    "scripts, DLL-task hosts like taskhostw.exe) leave no trace of who launched them or what they ran. " +
                    "Install to start recording — without it, nothing is kept to look back on.",
                _ => "Sysmon is half-installed: leftovers of a failed install (a stale event-manifest registration " +
                     "and/or a stray Sysmon64.exe) will make every install attempt fail. Repair removes them and reinstalls."
            };

            VersionText.Text = $"Version: {info.Version ?? "—"}";
            ServiceText.Text = $"Service: {(info.State == SysmonInstallState.NotInstalled ? "—" : info.ServiceRunning ? "Running" : "Stopped")}";
            ChannelText.Text = $"Event channel: {(info.State == SysmonInstallState.NotInstalled ? "—" : info.ChannelHealthy ? "Healthy" : "Unreadable")}";
            EventsText.Text = $"Events (24h): {(info.State == SysmonInstallState.NotInstalled ? "—" : info.EventsLast24h.ToString("N0"))}";
            var (archiveDays, archiveEvents) = Services.SysmonArchiveService.StatusSummary();
            ArchiveText.Text = archiveEvents > 0
                ? $"Archive: {archiveEvents.ToString("N0")} events · {archiveDays} day file(s) · {Services.SysmonArchiveService.DefaultRetainDays}-day retention"
                : "Archive: not started yet (fills at the next elevated start)";
            NewestText.Text = $"Newest event: {info.NewestEventTime?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "—"}";
            HashText.Text = $"Config hash: {info.ConfigHash ?? "—"}";

            InstallBtn.Visibility = info.State == SysmonInstallState.NotInstalled ? Visibility.Visible : Visibility.Collapsed;
            RepairBtn.Visibility = info.State == SysmonInstallState.Inconsistent ? Visibility.Visible : Visibility.Collapsed;
            ApplyConfigBtn.Visibility = info.State == SysmonInstallState.Installed ? Visibility.Visible : Visibility.Collapsed;

            FeedStatusText.Text = info.State == SysmonInstallState.Installed
                ? (_audit.IsRunning ? "Capturing process creations live." : "Press Start Capture to load recent history and follow new launches.")
                : "Capture requires Sysmon to be installed.";
        }

        private void RefreshBtn_Click(object sender, RoutedEventArgs e)
        {
            _ = RefreshStatusAsync();
        }

        private async void InstallBtn_Click(object sender, RoutedEventArgs e)
        {
            InstallBtn.IsEnabled = false;
            RepairBtn.IsEnabled = false;
            try
            {
                // Inconsistent = leftovers of a failed install that abort every
                // "-i" attempt; RepairAsync clears them and reinstalls
                bool inconsistent = _installer.DetectInstallState() == SysmonInstallState.Inconsistent;
                StateText.Text = inconsistent ? "Repairing…" : "Installing…";

                bool success;
                string error;
                bool rebootRequired;
                if (inconsistent)
                {
                    var r = await _installer.RepairAsync();
                    (success, error, rebootRequired) = (r.Success, r.ErrorMessage, r.RebootRequired);
                }
                else
                {
                    var r = await _installer.InstallAndConfigureAsync();
                    (success, error, rebootRequired) = (r.Success, r.ErrorMessage, false);
                }

                if (success)
                {
                    MessageBox.Show(
                        "Sysmon installed and configured to record process creations, network connections and DNS queries.",
                        "Sysmon installed", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else if (rebootRequired)
                {
                    var restart = MessageBox.Show(
                        "Windows still holds a stale Sysmon registration that only a restart can clear.\n\n" +
                        "Restart now? LookSee will finish and verify the install automatically after the restart.",
                        "Restart required", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
                    if (restart == MessageBoxResult.Yes)
                        ProcessRunner.RunDetached("shutdown.exe",
                            "/r /t 10 /c \"LookSee: restarting to complete the Sysmon install\"");
                    return;
                }
                else
                {
                    MessageBox.Show($"Sysmon setup failed.\n\nDetails: {error}",
                        "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            finally
            {
                InstallBtn.IsEnabled = true;
                RepairBtn.IsEnabled = true;
                await RefreshStatusAsync();
            }
        }

        private async void ApplyConfigBtn_Click(object sender, RoutedEventArgs e)
        {
            ApplyConfigBtn.IsEnabled = false;
            try
            {
                var (success, error) = await _installer.UpdateConfigAsync();
                MessageBox.Show(success
                    ? "Recommended config applied. Process creations, network connections and DNS queries are now recorded."
                    : $"Could not apply config.\n\nDetails: {error}",
                    "Sysmon config", MessageBoxButton.OK,
                    success ? MessageBoxImage.Information : MessageBoxImage.Error);
            }
            finally
            {
                ApplyConfigBtn.IsEnabled = true;
                await RefreshStatusAsync();
            }
        }

        // -----------------------------------------------------------------------
        // Process-creation feed
        // -----------------------------------------------------------------------

        private void CaptureBtn_Click(object sender, RoutedEventArgs e) => ToggleCapture();

        private void ToggleCapture()
        {
            if (!_audit.IsRunning)
            {
                _audit.Start();
                if (_audit.IsRunning)
                {
                    BackfillFeed();
                    CaptureBtn.Content = "Stop Capture";
                    FeedStatusText.Text = "Capturing process creations live.";
                }
            }
            else
            {
                _audit.Stop();
                CaptureBtn.Content = "Start Capture";
                FeedStatusText.Text = "Capture stopped.";
            }
        }

        private void BackfillFeed()
        {
            foreach (var evt in _audit.ReadRecent(MaxFeedRows))
                _events.Add(evt);
            TrimFeed();
        }

        private void AddFeedRow(SysmonProcessEvent evt)
        {
            _events.Insert(0, evt);
            TrimFeed();
        }

        private void TrimFeed()
        {
            // Newest rows sit at index 0; drop from the bottom until capped
            while (_events.Count > MaxFeedRows)
                _events.RemoveAt(_events.Count - 1);
        }

    }
}
