using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using LookSee.Models;
using LookSee.Services;

namespace LookSee.Views
{
    /// <summary>
    /// Data &amp; Privacy tab — transparency and agency over what Windows
    /// security shares. Three jobs, kept read-only where writing would be
    /// the wrong call:
    ///   • Live settings with plain-English meaning + deep links to change
    ///     them in Windows Security/Settings (the supported place — several
    ///     values are tamper/policy-protected)
    ///   • Curated "who can receive this data" catalog, with sources to
    ///     re-verify (no background fetching; honest about what Microsoft
    ///     does not publish)
    ///   • Draft-letter builder for US privacy requests (CCPA/state law to
    ///     Microsoft, FOIA+Privacy Act to agencies — different tools for
    ///     different targets) plus a local-only tracker with statutory due
    ///     dates. Everything generated is a draft the user reviews and
    ///     sends themselves; LookSee never sends anything.
    /// </summary>
    public partial class PrivacyView : UserControl
    {
        private readonly DefenderPrivacyService _privacy = new();
        private DefenderPrivacyService.PrivacyState _state;
        private List<PrivacyRequestBuilder.RequestRecord> _requests = new();
        private bool _loading;

        private sealed class SettingRow
        {
            public string Title { get; init; }
            public string Value { get; init; }
            public string Plain { get; init; }
            public string ChangeLabel { get; init; }
            public string ChangeUri { get; init; }
        }

        public PrivacyView()
        {
            InitializeComponent();

            StateCombo.ItemsSource = PrivacyRequestBuilder.StateLaws;
            StateCombo.SelectedIndex = 0;
            AgencyCombo.ItemsSource = PrivacyRequestBuilder.FoiaAgencies;
            AgencyCombo.SelectedIndex = 0;
            VendorList.ItemsSource = VendorCatalog.Categories;
        }

        private async void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            await LoadStateAsync();
            await LoadTrackerAsync();
        }

        private async void RefreshBtn_Click(object sender, RoutedEventArgs e) => await LoadStateAsync();

        private async Task LoadStateAsync()
        {
            _loading = true;
            try
            {
                HeaderStatusText.Text = "Reading data-sharing settings…";
                _state = await _privacy.GetStateAsync();
                PopulateSettings(_state);
                HeaderStatusText.Text = _state.Available
                    ? $"Settings read {DateTime.Now:HH:mm:ss} · click any change button to open the supported settings page"
                    : $"⚠ {_state.UnavailableReason}";
            }
            finally
            {
                _loading = false;
            }
        }

        private void PopulateSettings(DefenderPrivacyService.PrivacyState state)
        {
            if (!state.Available)
            {
                SettingsList.ItemsSource = new[]
                {
                    new SettingRow
                    {
                        Title = "Settings unreadable",
                        Value = "—",
                        Plain = state.UnavailableReason,
                        ChangeLabel = "↗ Open Windows Security",
                        ChangeUri = "windowsdefender://threatsettings"
                    }
                };
                OrgManagedBanner.Visibility = Visibility.Collapsed;
                ReadTimestampText.Text = "";
                return;
            }

            string samplesPlain = state.SubmitSamplesConsent switch
            {
                0 => "Defender asks you before uploading any file copy for analysis.",
                1 => "Defender automatically uploads copies of files it deems 'safe samples' (no obvious personal data) for analysis; it prompts for the rest. This is the Windows default.",
                2 => "Defender never uploads file copies. Cloud verdicts still use file metadata (hashes, names, certificates).",
                _ => "Defender automatically uploads copies of ALL suspicious files, including ones that may contain personal data."
            };
            string samplesValue = state.SubmitSamplesConsent switch
            {
                0 => "Always prompt",
                1 => "Safe samples auto (default)",
                2 => "Never send",
                3 => "All samples auto",
                _ => state.SubmitSamplesConsent.ToString()
            };
            if (state.PolicySubmitSamples is { } pol)
                samplesValue += $" · policy {pol}";

            string mapsPlain = state.MapsReporting switch
            {
                0 => "Cloud-delivered protection is OFF: unknown files can't get fast cloud verdicts and no reputation lookups are made.",
                1 => "Basic membership: unknown files get cloud verdicts using file metadata (hash, name, certificates) — not file contents.",
                _ => "Advanced membership: unknown files get cloud verdicts using file metadata, and richer information about Defender's reactions to them is reported back."
            };
            string mapsValue = state.MapsReporting switch
            {
                0 => "Off",
                1 => "Basic",
                2 => "Advanced",
                _ => state.MapsReporting.ToString()
            };
            if (state.PolicyMapsReporting is { } polMaps)
                mapsValue += $" · policy {polMaps}";

            string telemetryValue = state.AllowTelemetry switch
            {
                null => "Settings-controlled",
                0 => "Security (lowest)",
                1 => "Required",
                2 => "Enhanced",
                3 => "Full",
                _ => state.AllowTelemetry.ToString()
            };
            string telemetryPlain = state.AllowTelemetry switch
            {
                null => "No policy pins the level — choose it under Settings → Privacy & security → Diagnostics & feedback. (Home/Pro editions floor this at Required.)",
                0 => "Lowest level. On Home/Pro editions Windows floors this at Required (1) — 0 only fully applies on Enterprise/Education.",
                1 => "Required diagnostic data: info Windows needs to stay secure, updated and working. The level Windows considers the minimum.",
                2 => "Enhanced: extra data about how features and apps are used.",
                3 => "Full: everything Windows can collect, used to find problems. Largest data footprint.",
                _ => "Unrecognized value."
            };

            string smartScreenValue = state.PolicySmartScreen switch
            {
                null => "On (default)",
                0 => "Off (policy)",
                1 => "On (policy)",
                _ => "Unknown"
            };

            string sacValue = state.SmartAppControl switch
            {
                0 => "Off",
                1 => "Enforcement",
                2 => "Evaluation",
                _ => "Unknown"
            };

            SettingsList.ItemsSource = new[]
            {
                new SettingRow
                {
                    Title = "Cloud-delivered protection (MAPS)",
                    Value = mapsValue,
                    Plain = mapsPlain,
                    ChangeLabel = "↗ Windows Security → Virus & threat protection",
                    ChangeUri = "windowsdefender://threatsettings"
                },
                new SettingRow
                {
                    Title = "Automatic sample submission",
                    Value = samplesValue,
                    Plain = samplesPlain,
                    ChangeLabel = "↗ Windows Security → Virus & threat protection",
                    ChangeUri = "windowsdefender://threatsettings"
                },
                new SettingRow
                {
                    Title = "Cloud protection level",
                    Value = state.CloudBlockLevel switch { 2 => "High", 4 => "High+", 6 => "Zero tolerance", _ => "Default" },
                    Plain = "How aggressive cloud verdicts are: higher levels block more unknown files (more lookups, more false positives possible); zero tolerance blocks anything not yet cleared.",
                    ChangeLabel = "↗ Windows Security → Virus & threat protection",
                    ChangeUri = "windowsdefender://threatsettings"
                },
                new SettingRow
                {
                    Title = "Windows diagnostic data",
                    Value = telemetryValue,
                    Plain = telemetryPlain,
                    ChangeLabel = "↗ Settings → Diagnostics & feedback",
                    ChangeUri = "ms-settings:privacy-feedback"
                },
                new SettingRow
                {
                    Title = "SmartScreen (reputation checks)",
                    Value = smartScreenValue,
                    Plain = "Checks downloaded files, apps and web content against Microsoft reputation: sends file name, hash, download origin and digital certificates for files it checks — not file contents.",
                    ChangeLabel = "↗ Windows Security → App & browser control",
                    ChangeUri = "ms-settings:apps-apps"
                },
                new SettingRow
                {
                    Title = "Smart App Control",
                    Value = sacValue,
                    Plain = sacValue switch
                    {
                        "1" => "Enforcement: only apps with known-good reputation run. Unknown apps are blocked — the strongest guarantee, the least flexibility.",
                        "2" => "Evaluation: Windows is deciding whether enforcement fits how you use the PC; it can leave this mode but never return to it after turning off.",
                        "0" => "Off: no reputation gate on which apps run.",
                        _ => "State could not be read on this build."
                    },
                    ChangeLabel = "↗ Settings → App & browser control",
                    ChangeUri = "ms-settings:apps-apps"
                }
            };

            // Management banner — an org-managed machine can own these over the user
            if (state.OrgManaged)
            {
                var flags = new List<string>();
                if (state.DomainJoined) flags.Add("domain-joined");
                if (state.MdmEnrolled) flags.Add("MDM-enrolled");
                if (state.DefenderPolicyManaged) flags.Add("Defender Group-Policy keys present");
                OrgManagedText.Text =
                    $"Detected: {string.Join(", ", flags)}. Your administrator may control these settings, and " +
                    "local changes can be reverted by policy sync. On a work/school PC, data handling follows your " +
                    "organization's agreement with Microsoft — your admin, not this tab, is the first stop.";
                OrgManagedBanner.Visibility = Visibility.Visible;
            }
            else
            {
                OrgManagedBanner.Visibility = Visibility.Collapsed;
            }

            ReadTimestampText.Text = $"Read live at {state.ReadAtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} — press ↻ Refresh to re-check.";
        }

        // ── Deep links / sources ────────────────────────────────────────────

        private void SettingChange_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button { Tag: string uri }) OpenShell(uri, "settings page");
        }

        private void OpenSource_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button { Tag: string uri }) OpenShell(uri, "source page");
        }

        private void OpenDashboard_Click(object sender, RoutedEventArgs e) =>
            OpenShell("https://account.microsoft.com/privacy", "privacy dashboard");

        private void OpenDdvDocs_Click(object sender, RoutedEventArgs e) =>
            OpenShell("https://learn.microsoft.com/en-us/windows/privacy/diagnostic-data-viewer-overview", "docs page");

        private void OpenRecipient_Click(object sender, RoutedEventArgs e)
        {
            if (ModeCorporate.IsChecked == true)
                OpenShell("https://www.microsoft.com/en-us/concern/privacy", "Microsoft privacy request page");
            else if (AgencyCombo.SelectedItem is PrivacyRequestBuilder.FoiaAgency agency)
                OpenShell(agency.PortalUrl, "agency FOIA portal");
        }

        private static void OpenShell(string uri, string what)
        {
            try
            {
                Process.Start(new ProcessStartInfo { FileName = uri, UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Could not open the {what}:\n\n{ex.Message}\n\nURI: {uri}",
                    "Open", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        // ── Export ──────────────────────────────────────────────────────────

        private void ExportSnapshot_Click(object sender, RoutedEventArgs e)
        {
            if (_state is not { Available: true })
            {
                MessageBox.Show("Settings have not been read successfully yet — press Refresh first.",
                    "Export", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Export privacy settings snapshot",
                Filter = "JSON (*.json)|*.json",
                FileName = $"defender-privacy-snapshot-{DateTime.Now:yyyy-MM-dd-HHmm}.json"
            };
            if (dialog.ShowDialog() != true) return;

            var payload = new Dictionary<string, object>
            {
                ["tool"] = "LookSee Data & Privacy tab",
                ["readAtUtc"] = _state.ReadAtUtc,
                ["submitSamplesConsent"] = _state.SubmitSamplesConsent,
                ["policySubmitSamples"] = _state.PolicySubmitSamples,
                ["mapsReporting"] = _state.MapsReporting,
                ["policyMapsReporting"] = _state.PolicyMapsReporting,
                ["cloudBlockLevel"] = _state.CloudBlockLevel,
                ["allowTelemetry"] = _state.AllowTelemetry,
                ["policySmartScreen"] = _state.PolicySmartScreen,
                ["smartAppControl"] = _state.SmartAppControl,
                ["domainJoined"] = _state.DomainJoined,
                ["mdmEnrolled"] = _state.MdmEnrolled,
                ["defenderPolicyManaged"] = _state.DefenderPolicyManaged,
                ["machine"] = Environment.MachineName,
                ["os"] = Environment.OSVersion.VersionString
            };
            File.WriteAllText(dialog.FileName,
                JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
            HeaderStatusText.Text = $"✓ Snapshot saved to {dialog.FileName}";
        }

        // ── Request builder ─────────────────────────────────────────────────

        private void Mode_Changed(object sender, RoutedEventArgs e)
        {
            if (CorporatePanel == null || FoiaPanel == null) return;   // radio events during InitializeComponent
            bool corporate = ModeCorporate.IsChecked == true;
            CorporatePanel.Visibility = corporate ? Visibility.Visible : Visibility.Collapsed;
            FoiaPanel.Visibility = corporate ? Visibility.Collapsed : Visibility.Visible;
        }

        private void StateCombo_Changed(object sender, SelectionChangedEventArgs e)
        {
            if (StateLawNoteText == null || _loading) return;
            if (StateCombo.SelectedItem is not PrivacyRequestBuilder.StatePrivacyLaw law) return;
            StateLawNoteText.Text = law.StatuteName == null
                ? "Your state is not in the list — the letter will be a general privacy request without a statutory deadline. You can still send it; honesty beats a citation you can't back."
                : $"{law.StatuteName} ({law.Citation}) · response due in {law.ResponseDays} days, one {law.ExtensionDays}-day extension allowed. Requests cover data Microsoft's vendors process on Microsoft's behalf — the statute routes you through the business, not to each vendor.";
        }

        private async void GenerateBtn_Click(object sender, RoutedEventArgs e)
        {
            if (ModeCorporate.IsChecked == true)
            {
                var law = (PrivacyRequestBuilder.StatePrivacyLaw)StateCombo.SelectedItem;
                if (string.IsNullOrWhiteSpace(CorpNameBox.Text))
                {
                    MessageBox.Show("Enter your full name — the letter must identify you.", "Missing name",
                        MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }
                var input = new PrivacyRequestBuilder.CorporateInput
                {
                    Law = law,
                    FullName = CorpNameBox.Text.Trim(),
                    Email = CorpEmailBox.Text.Trim(),
                    Devices = CorpDevicesBox.Text.Trim(),
                    FromDate = FromDatePick.SelectedDate,
                    ToDate = ToDatePick.SelectedDate,
                    RightToKnowCategories = RightKnowCats.IsChecked == true,
                    RightToKnowSpecific = RightKnowSpecific.IsChecked == true,
                    RightToDelete = RightDelete.IsChecked == true,
                    RightToCorrect = RightCorrect.IsChecked == true,
                    RightToOptOut = RightOptOut.IsChecked == true,
                    IncludeSettingsSnapshot = IncludeSnapshotCheck.IsChecked == true,
                    Snapshot = _state
                };
                LetterBox.Text = PrivacyRequestBuilder.BuildCorporateLetter(input);
            }
            else
            {
                var agency = (PrivacyRequestBuilder.FoiaAgency)AgencyCombo.SelectedItem;
                if (string.IsNullOrWhiteSpace(FoiaNameBox.Text))
                {
                    MessageBox.Show("Enter your full name — the request must identify you.", "Missing name",
                        MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }
                LetterBox.Text = PrivacyRequestBuilder.BuildFoiaLetter(new PrivacyRequestBuilder.FoiaInput
                {
                    Agency = agency,
                    FullName = FoiaNameBox.Text.Trim(),
                    Email = FoiaEmailBox.Text.Trim(),
                    Description = FoiaDescBox.Text.Trim(),
                    FeeWaiver = FeeWaiverCheck.IsChecked == true,
                    Expedited = ExpeditedCheck.IsChecked == true
                });
            }
            await TrackGeneratedDraftAsync();
        }

        private async Task TrackGeneratedDraftAsync()
        {
            bool corporate = ModeCorporate.IsChecked == true;
            var law = StateCombo.SelectedItem as PrivacyRequestBuilder.StatePrivacyLaw;
            var agency = AgencyCombo.SelectedItem as PrivacyRequestBuilder.FoiaAgency;
            _requests.Insert(0, new PrivacyRequestBuilder.RequestRecord
            {
                Kind = corporate ? "Corporate" : "FOIA",
                Recipient = corporate
                    ? $"Microsoft Corporation — {law?.State}"
                    : agency?.Name ?? "agency",
                Statute = corporate ? law?.Citation : "5 U.S.C. § 552 / § 552a",
                ResponseDays = corporate ? law?.ResponseDays ?? 0 : 20
            });
            await PrivacyRequestBuilder.SaveRequestsAsync(_requests);
            RefreshTracker();
        }

        // ── Letter actions ──────────────────────────────────────────────────

        private void CopyLetter_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Clipboard.SetText(LetterBox.Text);
                HeaderStatusText.Text = "✓ Letter copied — paste it into the recipient's request form or an email.";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Clipboard copy failed: {ex.Message}", "Copy", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private async void SaveLetter_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(LetterBox.Text))
            {
                MessageBox.Show("Generate a letter first.", "Save", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Save draft letter",
                Filter = "Text (*.txt)|*.txt",
                FileName = $"privacy-request-{DateTime.Now:yyyy-MM-dd-HHmm}.txt"
            };
            if (dialog.ShowDialog() != true) return;
            File.WriteAllText(dialog.FileName, LetterBox.Text);
            HeaderStatusText.Text = $"✓ Letter saved to {dialog.FileName} — review it, then send it yourself.";

            if (RequestsGrid.SelectedItem is PrivacyRequestBuilder.RequestRecord record)
            {
                record.LetterFile = dialog.FileName;
                await PrivacyRequestBuilder.SaveRequestsAsync(_requests);
                RefreshTracker();
            }
        }

        // ── Tracker ─────────────────────────────────────────────────────────

        private async Task LoadTrackerAsync()
        {
            _requests = await PrivacyRequestBuilder.LoadRequestsAsync();
            RefreshTracker();
        }

        private void RefreshTracker()
        {
            RequestsGrid.ItemsSource = null;
            RequestsGrid.ItemsSource = _requests
                .OrderBy(r => r.Status == "Answered")
                .ThenByDescending(r => r.CreatedUtc)
                .ToList();
        }

        private async void MarkSent_Click(object sender, RoutedEventArgs e)
        {
            if (RequestsGrid.SelectedItem is not PrivacyRequestBuilder.RequestRecord record) return;
            record.Status = "Sent";
            record.SentUtc = DateTime.UtcNow;
            record.DueUtc = DateTime.UtcNow.AddDays(
                record.Kind == "FOIA" ? 20 : Math.Max(record.ResponseDays, 1));
            await PrivacyRequestBuilder.SaveRequestsAsync(_requests);
            RefreshTracker();
        }

        private async void MarkAnswered_Click(object sender, RoutedEventArgs e)
        {
            if (RequestsGrid.SelectedItem is not PrivacyRequestBuilder.RequestRecord record) return;
            record.Status = "Answered";
            await PrivacyRequestBuilder.SaveRequestsAsync(_requests);
            RefreshTracker();
        }

        private async void RemoveRequest_Click(object sender, RoutedEventArgs e)
        {
            if (RequestsGrid.SelectedItem is not PrivacyRequestBuilder.RequestRecord record) return;
            if (MessageBox.Show($"Remove the tracker entry for\n\n{record.Recipient}\n\n(created {record.CreatedUtc.ToLocalTime():yyyy-MM-dd})?",
                    "Remove entry", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
                return;
            _requests.Remove(record);
            await PrivacyRequestBuilder.SaveRequestsAsync(_requests);
            RefreshTracker();
        }
    }
}
