using System.Linq;
using System.Windows;

namespace LookSee
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // ── headless OneSettings watchdog path (no UI) ──────────────
            // The \LookSee\OneSettingsCadenceWatchdog SYSTEM task (installed
            // from the Windows Check-Ins tab with the watchdog box checked)
            // launches LookSee.exe with this argument daily 03:30 and at
            // logon to re-apply the saved RefreshCache cadence if Windows
            // servicing reverted it. Silent; every action lands in the
            // machine-readable audit trail under
            // %ProgramData%\LookSee\onesettings-cadence.
            var args = e.Args ?? System.Array.Empty<string>();
            if (args.Any(a => string.Equals(a, "onesettings-enforce", System.StringComparison.OrdinalIgnoreCase)))
            {
                RunOneSettingsEnforce();
                return;
            }

            // Apply the saved theme before any window loads (brushes are
            // DynamicResource, so this also re-themes live when changed later)
            Services.ThemeService.ApplyTheme(Services.ThemeService.Saved);

            // Handle UI thread exceptions
            this.DispatcherUnhandledException += (s, args) =>
            {
                LogCrash(args.Exception, "Dispatcher");
                args.Handled = true; // Prevent app from closing
                MessageBox.Show($"A UI error occurred: {args.Exception.Message}\n\nDetails saved to crash.log.",
                    "LookSee Error", MessageBoxButton.OK, MessageBoxImage.Error);
            };

            // Handle background thread exceptions
            AppDomain.CurrentDomain.UnhandledException += (s, args) =>
            {
                if (args.ExceptionObject is System.Exception ex)
                {
                    LogCrash(ex, "AppDomain");
                }
            };

            // Handle async Task exceptions
            System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (s, args) =>
            {
                LogCrash(args.Exception, "TaskScheduler");
                args.SetObserved();
            };

            // Finish a Sysmon repair that was waiting for a Windows restart
            FinishSysmonRepairIfPending();

            // Grow the Sysmon channel to its sized retention on machines
            // where Sysmon predates the sizing — the 64 MB default wraps in
            // ~4 h on an active box, which silently shorts the forensic
            // history the Recorder promises. No-op when already sized,
            // not installed, or the session is not elevated.
            //
            // Then the Sysmon archive: prune past retention, backfill
            // everything the live channel still holds, and follow it live.
            // The channel is a rolling window; the archive is what makes
            // "every spawn retroactively traceable" true for weeks.
            PrepareSysmonAtStartup();

            // Telemetry sinkhole: when hosts pins point at 127.0.0.1 (sinkhole
            // mode, toggled from the Black Hole tab), start the logging
            // listener immediately so proof accumulates even if that tab is
            // never opened this session. Touching the proof store also wires
            // its recorder to the sinkhole. No sinkhole pins → both are no-ops.
            Services.SinkholeService.Instance.EnsureRunningForCurrentPins();
            _ = Services.TelemetryProofService.Instance.TotalDenied;

            // Anonymous usage ping (opt-in, off by default): sends the user's
            // answer into effect — consented installs ping once a day, everyone
            // else is never asked again after the bounded offer. Fully inert
            // while UsagePingService.Endpoint is unconfigured. Spec and server
            // code: telemetry/ in the repository.
            _ = Services.UsagePingService.RunStartupFlowAsync();
        }

        // Headless watchdog run: same cadence engine the Windows Check-Ins
        // tab starts, minus the UI. Runs until done. Mutating tools are
        // always off here — nothing can confirm an action without the app UI.
        private void RunOneSettingsEnforce()
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            try
            {
                // Engine handles the no-saved-state case as a no-op (normal
                // after a restore), and audits both success and failure — a
                // failed watchdog run must never block app shutdown.
                new OneSettingsCadence.CadenceEngine().Enforce();
            }
            catch { /* audited inside the engine where possible; always exit */ }
            Shutdown();
        }

        private async void FinishSysmonRepairIfPending()
        {
            try
            {
                var installer = new LookSee.Services.SysmonInstallerService();
                var (verified, message) = await installer.CompletePendingRepairIfAnyAsync();
                if (message == null) return; // no repair was pending

                if (verified)
                {
                    MessageBox.Show($"Sysmon repair verified after the restart.\n\n{message}",
                        "Sysmon repair complete", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show($"Sysmon repair could not be verified after the restart.\n\nDetails: {message}\n\n" +
                        "Use the setup button in the Recorder tab to retry the repair.",
                        "Sysmon repair", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (System.Exception ex)
            {
                LogCrash(ex, "SysmonRepair");
            }
        }

        // Off the UI thread: DetectInstallState probes sc.exe/wevtutil, the
        // backfill can scan the whole retained channel, and none of it must
        // stall startup. Every step degrades silently when unelevated.
        private async void PrepareSysmonAtStartup()
        {
            try
            {
                await System.Threading.Tasks.Task.Run(() =>
                {
                    var installer = new Services.SysmonInstallerService();
                    if (installer.DetectInstallState() != Services.SysmonInstallState.Installed)
                        return; // nothing installed — the install path sizes and archives it
                    Services.SysmonInstallerService.EnsureChannelSize();
                    Services.SysmonArchiveService.Prune();
                    Services.SysmonArchiveService.Backfill();
                    Services.SysmonArchiveService.StartLiveWatch();
                });
            }
            catch (System.Exception ex)
            {
                LogCrash(ex, "SysmonStartup");
            }
        }

        private void LogCrash(System.Exception ex, string source)
        {
            try
            {
                string logPath = System.IO.Path.Combine(System.AppDomain.CurrentDomain.BaseDirectory, "crash.log");
                string logEntry = $"\n[{System.DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{source}]\n{ex.ToString()}\n";
                System.IO.File.AppendAllText(logPath, logEntry);
            }
            catch { /* Failsafe */ }
        }
    }
}
