using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using LookSee.Models;
using LookSee.Services;

namespace LookSee.Views
{
    /// <summary>
    /// Transmissions tab: the visible half of the pipeline. Every finalized
    /// TLS conversation becomes a row (decrypted content, or the honest
    /// "encrypted (no keys)" status), every decoded HTTP message is
    /// selectable and viewable as pretty / text / hex / headers, and the
    /// full untruncated bodies live in the local archive with a SHA-256 so
    /// "what was sent" stays provable after the fact.
    ///
    /// Watching deliberately outlives tab navigation (same recorder rule as
    /// the Spawns feeds); it stops on Stop Watch or app exit.
    /// </summary>
    public partial class TransmissionsView : UserControl
    {
        private const int RowCap = 5000;

        private readonly ObservableCollection<TransmissionRecord> _rows = new();
        private readonly Dictionary<string, TransmissionRecord> _rowById = new();
        private int _zeroReplyCount;

        private TransmissionsPipelineService _pipeline;
        private bool _initialized;
        private bool _watching;
        private bool _backfilled;
        private Regex _filter;
        private bool _bigOnly = true;
        private bool _zeroReplyOnly;

        private TransmissionRecord _selected;
        private List<HttpStreamDecoder.HttpMessage> _messages = new();
        private DateTime _archiveStatusAt = DateTime.MinValue;
        private (int Days, long Bytes) _archiveStatus;
        private System.Windows.Threading.DispatcherTimer _bannerTimer;

        private const int TextCapBytes = 512 * 1024;
        private const int HexCapBytes = 256 * 1024;

        public TransmissionsView()
        {
            InitializeComponent();
            FlowGrid.ItemsSource = _rows;

            var view = (ListCollectionView)CollectionViewSource.GetDefaultView(_rows);
            view.SortDescriptions.Add(new System.ComponentModel.SortDescription(
                nameof(TransmissionRecord.TsUtc), System.ComponentModel.ListSortDirection.Descending));
            view.Filter = FilterRow;
        }

        // -----------------------------------------------------------------------
        // Lifecycle — lazy start on first show, keeps watching afterwards
        // -----------------------------------------------------------------------

        private void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            if (!_initialized)
            {
                _initialized = true;
                InitializeServices();
            }
            if (!_watching) StartWatching();
        }

        private void UserControl_Unloaded(object sender, RoutedEventArgs e)
        {
            // Deliberately keeps watching (recorder rule — see class doc).
        }

        public bool IsWatching => _watching;

        private void InitializeServices()
        {
            _pipeline = TransmissionsPipelineService.Shared;
            _pipeline.OnRecord += OnRecord;
            _pipeline.OnError += ShowError;
            _pipeline.OnBigEncryptedUpload += OnBigEncryptedUpload;

            // Block states power the ⛔ badges and the menu's
            // block/unblock flip — prime them off the UI thread so the
            // first row already knows what is blocked.
            _ = Task.Run(() => FirewallBlockService.Instance.RefreshSnapshot());

            InterceptProxyService.Shared.OnSessionEnded += OnInterceptSessionEnded;
            InterceptProxyService.Shared.OnStatus += message =>
                Dispatcher.BeginInvoke(() => StatusText.Text = $"🛡 {message}");

            SystemKeylogCheck.IsChecked = TransmissionKeyService.IsSystemKeylogEnabled();
            SystemKeylogCheck.ToolTip = TransmissionKeyService.CoverageNote;
            BigOnlyCheck.IsChecked = _bigOnly;

            _bannerTimer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _bannerTimer.Tick += (_, _) =>
            {
                UpdateInterceptBanner();
                UpdateCaptureBanner();
            };
            UpdateInterceptBanner();
            UpdateCaptureBanner();
        }

        private void StartWatching()
        {
            _pipeline.Start();
            _watching = true;
            ToggleWatchBtn.Content = "Stop Watch";
            UpdateStatus();
            BackfillArchive();
            if (_bannerTimer != null && !_bannerTimer.IsEnabled) _bannerTimer.Start();
        }

        private void StopWatching()
        {
            _pipeline.Stop();
            _watching = false;
            ToggleWatchBtn.Content = "Start Watch";
            UpdateStatus();
        }

        private void ToggleWatchBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_watching) StopWatching();
            else StartWatching();
        }

        /// <summary>Previous sessions' archived rows load behind the live
        /// feed so "what did this machine send yesterday" is answered in the
        /// same grid.</summary>
        private void BackfillArchive()
        {
            if (_backfilled) return;
            _backfilled = true;
            System.Threading.Tasks.Task.Run(() =>
            {
                var archived = TransmissionsArchiveService.Read(max: 500);
                Dispatcher.BeginInvoke(() =>
                {
                    foreach (var record in archived) // already newest-first
                        AddRow(record);
                    if (archived.Count > 0)
                        StatusText.Text = $"Loaded {archived.Count} archived transmission(s) from previous sessions";
                });
            });
        }

        private void ShowError(string message)
        {
            Dispatcher.Invoke(() => StatusText.Text = $"⚠ {message}");
        }

        // -----------------------------------------------------------------------
        // Rows
        // -----------------------------------------------------------------------

        private void OnRecord(TransmissionRecord record)
        {
            Dispatcher.BeginInvoke(() => AddRow(record));
        }

        private void AddRow(TransmissionRecord record)
        {
            if (_rowById.ContainsKey(record.Id)) return;
            // ⛔ badge: destination covered by an active AC-BLOCK rule
            // (created here or by AutoCommand — same scheme, live states).
            record.BlockedByRule =
                FirewallBlockService.Instance.IpState(record.RemoteIp) == FirewallBlockService.BlockState.Active ||
                FirewallBlockService.Instance.AppState(record.Image) == FirewallBlockService.BlockState.Active;
            _rowById[record.Id] = record;
            _rows.Add(record);
            if (IsZeroReply(record)) _zeroReplyCount++;
            while (_rows.Count > RowCap)
            {
                var oldest = _rows[^1];
                _rows.RemoveAt(_rows.Count - 1);
                if (IsZeroReply(oldest)) _zeroReplyCount--;
                if (_rowById.TryGetValue(oldest.Id, out var row) && row == oldest) _rowById.Remove(oldest.Id);
            }
            UpdateStatus();
        }

        /// <summary>The lens the checkbox names: sent something, never
        /// heard one word back. That shape is what a blocked outbound call
        /// or a dead-end beacon looks like — a lens, not a verdict.</summary>
        private static bool IsZeroReply(TransmissionRecord record) =>
            record.ClientBytes > 0 && record.ServerBytes == 0;

        private void ClearBtn_Click(object sender, RoutedEventArgs e)
        {
            _rows.Clear();
            _rowById.Clear();
            _zeroReplyCount = 0;
            _selected = null;
            _messages = new();
            DetailRecordPanel.Children.Clear();
            MessageCombo.ItemsSource = null;
            ContentText.Text = string.Empty;
            ContentFooter.Text = string.Empty;
            UpdateStatus();
        }

        // -----------------------------------------------------------------------
        // Filter
        // -----------------------------------------------------------------------

        private void FilterBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            string pattern = FilterBox.Text.Trim();
            try
            {
                _filter = pattern.Length > 0
                    ? new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled)
                    : null;
            }
            catch (ArgumentException) { /* mid-typing: keep the last valid filter */ }
            if (FlowGrid != null)
                CollectionViewSource.GetDefaultView(_rows).Refresh();
        }

        private void ApplyFilter(object sender, RoutedEventArgs e)
        {
            _bigOnly = BigOnlyCheck.IsChecked == true;
            _zeroReplyOnly = ZeroReplyCheck.IsChecked == true;
            CollectionViewSource.GetDefaultView(_rows).Refresh();
        }

        private bool FilterRow(object obj)
        {
            if (obj is not TransmissionRecord record) return false;
            if (_bigOnly && !record.BigUpload) return false;
            if (_zeroReplyOnly && !IsZeroReply(record)) return false;
            if (_filter == null) return true;
            return _filter.IsMatch($"{record.Image} {record.Sni} {record.RemoteIp} {record.Provider} {record.Status}");
        }

        // -----------------------------------------------------------------------
        // Detail pane
        // -----------------------------------------------------------------------

        private void FlowGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            RenderDetail(FlowGrid.SelectedItem as TransmissionRecord);
        }

        private void FlowGrid_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.OriginalSource is DependencyObject source &&
                ItemsControl.ContainerFromElement(FlowGrid, source) is DataGridRow row)
                row.IsSelected = true;
        }

        private void CopyRowMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (FlowGrid.SelectedItem is TransmissionRecord record)
                Clipboard.SetText(JsonSerializer.Serialize(record, new JsonSerializerOptions { WriteIndented = true }));
        }

        private void RenderDetail(TransmissionRecord record)
        {
            DetailRecordPanel.Children.Clear();
            _selected = record;
            _messages = new();
            MessageCombo.ItemsSource = null;

            // Encrypted rows get their remediation actions right in the pane.
            bool encryptedNoKeys = record?.Status != null && record.Status.Contains("no keys");
            EncryptedActionsPanel.Visibility = encryptedNoKeys ? Visibility.Visible : Visibility.Collapsed;
            if (encryptedNoKeys)
            {
                RestartBtn.Visibility = RestartBlockReason(record.Image) == null
                    ? Visibility.Visible : Visibility.Collapsed;
                bool ignoredApp = TransmissionsIgnoreList.IsIgnored(record.Image);
                IgnoreBtn.Visibility = ignoredApp ? Visibility.Collapsed : Visibility.Visible;
                UnignoreBtn.Visibility = ignoredApp ? Visibility.Visible : Visibility.Collapsed;
            }

            if (record == null)
            {
                ContentText.Text = string.Empty;
                ContentFooter.Text = string.Empty;
                return;
            }

            AddDetail("Time (local)", record.TsUtc == default ? "—" : record.TsUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.fff"));
            AddDetail("PID", record.Pid > 0 ? record.Pid.ToString() : "unattributed");
            AddDetail("Image", record.Image ?? "—");
            AddDetail("Destination", record.ServerEndpoint);
            AddDetail("Host (SNI)", record.HostDisplay);
            AddDetail("Provider", record.ProviderAndCountry);
            AddDetail("TLS", $"{record.TlsVersion ?? "?"}{(string.IsNullOrEmpty(record.Alpn) ? "" : $" · ALPN {record.Alpn}")}");
            AddDetail("Cipher", record.CipherSuite ?? "—");
            AddDetail("Wire bytes", $"{record.UpDisplay} up / {record.DownDisplay} down");
            AddDetail("Decrypted app bytes", record.AppBytesDisplay);
            AddDetail("Status", record.Status);
            AddDetail("Messages", record.MessageCount.ToString());
            AddDetail("Content kinds", string.IsNullOrEmpty(record.ContentKinds) ? "—" : record.ContentKinds);
            AddDetail("SHA-256 (both directions)", record.Sha256 ?? "(no decrypted content)");

            if (!record.Decrypted)
            {
                ContentText.Text = record.Status.Contains("no keys")
                    ? "Encrypted conversation — this app did not write TLS session keys.\n\n" +
                      "To see its contents: launch it with 🚀 Launch under watch…, or enable 🔑 System-wide key capture\n" +
                      "(works for Chromium/Electron apps, curl, git, OpenSSL- and Python-based tools; Schannel-based\n" +
                      "system components never write keys)."
                    : $"No content to show — {record.Status}.";
                ContentFooter.Text = $"Wire evidence retained: {record.UpDisplay} up, {record.DownDisplay} down to {record.ServerEndpoint}.";
                return;
            }

            byte[] request, response;
            if (!_pipeline.TryGetBodies(record.Id, out request, out response) && record.HasContent)
            {
                var loaded = _pipeline.LoadFromArchive(record);
                request = loaded.Request;
                response = loaded.Response;
            }

            var messages = new List<HttpStreamDecoder.HttpMessage>();
            messages.AddRange(HttpStreamDecoder.Decode(request, fromClient: true, alpn: record.Alpn));
            messages.AddRange(HttpStreamDecoder.Decode(response, fromClient: false, alpn: record.Alpn));
            _messages = messages;

            MessageCombo.ItemsSource = messages.Select(m => m.Display).ToList();
            MessageCombo.SelectedIndex = messages.Count > 0 ? 0 : -1;
            if (messages.Count == 0)
            {
                ContentText.Text = "Decrypted, but the plaintext carried no parseable bytes.";
                ContentFooter.Text = $"App bytes: {record.ClientAppBytes} up / {record.ServerAppBytes} down.";
            }
        }

        private void AddDetail(string label, string value)
        {
            var panel = new StackPanel { Margin = new Thickness(0, 0, 0, 8) };
            var labelBlock = new TextBlock
            {
                Text = label,
                Foreground = FindResource("TextSecondaryBrush") as Brush,
                FontSize = 10
            };
            var valueBlock = new TextBlock
            {
                Text = string.IsNullOrEmpty(value) ? "—" : value,
                TextWrapping = TextWrapping.Wrap,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 11,
                ToolTip = value
            };
            panel.Children.Add(labelBlock);
            panel.Children.Add(valueBlock);
            DetailRecordPanel.Children.Add(panel);
        }

        // -----------------------------------------------------------------------
        // Content viewer
        // -----------------------------------------------------------------------

        private void MessageCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ContentText == null) return; // during InitializeComponent
            RenderContent();
        }

        private void ViewModeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ContentText == null || MessageCombo == null) return;
            RenderContent();
        }

        private void RenderContent()
        {
            if (MessageCombo == null || ContentText == null) return;
            int index = MessageCombo.SelectedIndex;
            if (index < 0 || index >= _messages.Count)
            {
                if (_selected != null && _selected.Decrypted)
                    ContentText.Text = "Select a message to view its content.";
                return;
            }
            var message = _messages[index];
            byte[] body = message.Body ?? Array.Empty<byte>();

            string text = ViewModeCombo.SelectedIndex switch
            {
                3 => message.HeaderText(),
                2 => HexDump(body, HexCapBytes),
                1 => AsText(body, TextCapBytes),
                _ => Pretty(body, message.Kind),
            };
            ContentText.Text = text;

            var footer = new StringBuilder();
            footer.Append(message.FromClient ? "↑ sent by this machine" : "↓ received");
            footer.Append($" · {body.Length:N0} byte body");
            if (message.ContentEncoding != null) footer.Append($" · {message.ContentEncoding} decoded");
            if (message.Chunked) footer.Append(" · chunked decoded");
            if (!message.IsHttp) footer.Append(" · non-HTTP stream (raw bytes shown)");
            if (body.Length > (ViewModeCombo.SelectedIndex == 2 ? HexCapBytes : TextCapBytes))
                footer.Append($" · view truncated, full body on disk / 💾 Save body");
            if (_selected?.Sha256 != null) footer.Append($" · flow SHA-256 {_selected.Sha256[..16]}…");
            ContentFooter.Text = footer.ToString();
        }

        private static string Pretty(byte[] body, string kind)
        {
            if (body.Length == 0) return "(empty body)";
            if (kind == "json")
            {
                try
                {
                    var node = System.Text.Json.Nodes.JsonNode.Parse(body);
                    if (node != null)
                        return node.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
                }
                catch { /* fall through to raw text */ }
            }
            if (kind == "form")
                return UrlDecodeForm(AsText(body, TextCapBytes));
            return AsText(body, TextCapBytes);
        }

        private static string UrlDecodeForm(string form)
        {
            try
            {
                var sb = new StringBuilder();
                foreach (var pair in form.Split('&', ';'))
                {
                    int eq = pair.IndexOf('=');
                    if (eq < 0) { sb.AppendLine(pair); continue; }
                    sb.Append(Uri.UnescapeDataString(pair[..eq].Replace('+', ' ')))
                      .Append(" = ")
                      .AppendLine(Uri.UnescapeDataString(pair[(eq + 1)..].Replace('+', ' ')));
                }
                return sb.ToString();
            }
            catch { return form; }
        }

        private static string AsText(byte[] data, int cap)
        {
            int take = Math.Min(data.Length, cap);
            var sb = new StringBuilder(take);
            for (int i = 0; i < take; i++)
            {
                char c = (char)data[i];
                sb.Append(c == '\r' || c == '\n' || (c >= 32 && c < 127) || c == '\t' ? c : '·');
            }
            if (data.Length > take) sb.Append($" … (+{data.Length - take} B)");
            return sb.ToString();
        }

        private static string HexDump(byte[] data, int cap)
        {
            int take = Math.Min(data.Length, cap);
            var sb = new StringBuilder(take * 4);
            for (int i = 0; i < take; i += 16)
            {
                sb.Append(i.ToString("X6")).Append("  ");
                for (int j = 0; j < 16; j++)
                    sb.Append(i + j < take ? data[i + j].ToString("X2") : "  ").Append(' ');
                sb.Append(' ');
                for (int j = 0; j < 16 && i + j < take; j++)
                {
                    char c = (char)data[i + j];
                    sb.Append(c >= 32 && c < 127 ? c : '.');
                }
                sb.AppendLine();
            }
            if (data.Length > take) sb.AppendLine($"… (+{data.Length - take} B)");
            return sb.ToString();
        }

        private void SaveBodyBtn_Click(object sender, RoutedEventArgs e)
        {
            int index = MessageCombo?.SelectedIndex ?? -1;
            if (index < 0 || index >= _messages.Count)
            {
                MessageBox.Show("Select a message first.", "Save body", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            var message = _messages[index];
            byte[] body = message.Body ?? Array.Empty<byte>();
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "All files (*.*)|*.*",
                FileName = $"transmission-{(_selected?.Id[..12] ?? "body")}-{(message.FromClient ? "request" : "response")}.bin"
            };
            if (dialog.ShowDialog() != true) return;
            try
            {
                File.WriteAllBytes(dialog.FileName, body);
                MessageBox.Show($"Saved {body.Length:N0} byte(s) to:\n{dialog.FileName}",
                    "Save body", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Save failed: {ex.Message}", "Save body", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // -----------------------------------------------------------------------
        // Export
        // -----------------------------------------------------------------------

        private void ExportBtn_Click(object sender, RoutedEventArgs e)
        {
            var visible = _rows
                .Cast<TransmissionRecord>()
                .Where(FilterRow)
                .ToList();
            if (visible.Count == 0)
            {
                MessageBox.Show("Nothing to export yet.", "Export", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "JSONL files (*.jsonl)|*.jsonl|All files (*.*)|*.*",
                FileName = $"transmissions-{DateTime.Now:yyyyMMdd-HHmmss}.jsonl"
            };
            if (dialog.ShowDialog() != true) return;

            try
            {
                var options = new JsonSerializerOptions { WriteIndented = false };
                using var writer = new StreamWriter(dialog.FileName, append: false);
                foreach (var row in visible) // newest-first, as displayed
                    writer.WriteLine(JsonSerializer.Serialize(row, options));
                MessageBox.Show($"Exported {visible.Count} transmission row(s) (metadata) to:\n{dialog.FileName}",
                    "Export", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Export failed: {ex.Message}", "Export", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // -----------------------------------------------------------------------
        // Key acquisition
        // -----------------------------------------------------------------------

        private void SystemKeylogCheck_Changed(object sender, RoutedEventArgs e)
        {
            if (_pipeline == null) return; // event during InitializeComponent
            bool want = SystemKeylogCheck.IsChecked == true;
            bool current = TransmissionKeyService.IsSystemKeylogEnabled();
            if (want == current) return;

            try
            {
                if (want)
                {
                    var confirm = MessageBox.Show(
                        "Turn on system-wide TLS key capture?\n\n" +
                        "SSLKEYLOGFILE will point at LookSee's key file (current-user-only ACL,\n" +
                        "rotated at 5 MB). Apps that honor it — Chromium/Electron browsers and apps,\n" +
                        "curl, git, OpenSSL- and Python-based tools — write TLS session keys from their\n" +
                        "next launch on, and the Who's Talking tab shows their traffic decrypted.\n\n" +
                        "The key file decrypts your own TLS traffic: it stays local, and turning this\n" +
                        "off wipes it. Windows system components using Schannel ignore the variable —\n" +
                        "their flows keep the 'encrypted (no keys)' status.",
                        "System-wide key capture", MessageBoxButton.YesNo, MessageBoxImage.Question);
                    if (confirm != MessageBoxResult.Yes)
                    {
                        SystemKeylogCheck.IsChecked = false;
                        return;
                    }
                    TransmissionKeyService.EnableSystemKeylog();
                }
                else
                {
                    var confirm = MessageBox.Show(
                        "Turn off system-wide TLS key capture?\n\n" +
                        "The environment variable is removed and the key file is wiped — apps launched\n" +
                        "afterwards stop writing TLS secrets, so their future traffic cannot be\n" +
                        "decrypted here (existing captures stay ciphertext).",
                        "System-wide key capture", MessageBoxButton.YesNo, MessageBoxImage.Question);
                    if (confirm != MessageBoxResult.Yes)
                    {
                        SystemKeylogCheck.IsChecked = true;
                        return;
                    }
                    TransmissionKeyService.DisableSystemKeylog();
                }
                UpdateStatus();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "System-wide key capture", MessageBoxButton.OK, MessageBoxImage.Warning);
                SystemKeylogCheck.IsChecked = TransmissionKeyService.IsSystemKeylogEnabled();
            }
        }

        private void LaunchBtn_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Choose a program to launch under watch",
                Filter = "Programs (*.exe;*.bat;*.cmd)|*.exe;*.bat;*.cmd|All files (*.*)|*.*"
            };
            if (dialog.ShowDialog() != true) return;

            string arguments = PromptForArguments(dialog.FileName, Window.GetWindow(this));
            try
            {
                var proc = TransmissionKeyService.LaunchUnderWatch(dialog.FileName, arguments, null);
                StatusText.Text = $"Launched '{Path.GetFileName(dialog.FileName)}' (PID {proc?.Id}) under watch — " +
                                  $"its TLS traffic decrypts as soon as it connects.";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Launch failed: {ex.Message}", "Launch under watch",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        /// <summary>Minimal arguments prompt — built in code so the tab
        /// stays one file.</summary>
        private static string PromptForArguments(string exePath, Window owner)
        {
            var window = new Window
            {
                Title = "🚀 Launch under watch",
                Width = 520,
                SizeToContent = SizeToContent.Height,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = owner,
                Background = (Application.Current?.TryFindResource("SurfaceBrush") as Brush) ?? SystemColors.ControlBrush
            };
            var panel = new StackPanel { Margin = new Thickness(16) };
            panel.Children.Add(new TextBlock
            {
                Text = $"Launching:\n{exePath}\n\nSSLKEYLOGFILE will be set for this program only.",
                TextWrapping = TextWrapping.Wrap
            });
            var box = new TextBox
            {
                Margin = new Thickness(0, 10, 0, 10),
                FontFamily = new FontFamily("Consolas")
            };
            panel.Children.Add(box);
            var launch = new Button
            {
                Content = "Launch",
                Width = 90,
                HorizontalAlignment = HorizontalAlignment.Right,
                IsDefault = true
            };
            string arguments = null;
            launch.Click += (_, _) =>
            {
                arguments = box.Text;
                window.Close();
            };
            panel.Children.Add(launch);
            window.Content = panel;
            box.Focus();
            window.ShowDialog();
            return arguments ?? "";
        }

        // -----------------------------------------------------------------------
        // Layer 3: intercept sessions (Schannel apps, system components)
        // -----------------------------------------------------------------------

        private void InterceptBtn_Click(object sender, RoutedEventArgs e)
        {
            var record = _selected;
            if (record == null) return;

            if (InterceptProxyService.Shared.IsRunning)
            {
                MessageBox.Show("An intercept session is already active. Stop it first (⏹ Stop now in the banner).",
                    "🛡 Intercept", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            string image = record.Image;
            string display = record.ProcessDisplay;
            var confirm = MessageBox.Show(
                $"🛡 Intercept this process?\n\nTarget: {display} (PID {record.Pid})\n\n" +
                "For the next 15 minutes (auto-reverts; fully reversible):\n" +
                "  • A temporary 'LookSee Intercept CA' is trusted machine-wide, and removed\n" +
                "    when the session ends.\n" +
                "  • The system proxy (WinHTTP for services, WinINET for apps) points at a local\n" +
                "    loopback proxy on this machine. Other apps' traffic is tunneled through\n" +
                "    untouched — only the target PID is decrypted.\n" +
                "  • The target's QUIC (UDP 443) is blocked so it falls back to TCP/TLS.\n" +
                "  • Decrypted traffic appears in this tab as 'decrypted · intercept'.\n\n" +
                "Certificate-pinned apps will fail their connections during the session — recorded\n" +
                "here as 'refused intercept (pinning)'. Stop now restores proxy, firewall rule and\n" +
                "CA immediately if anything misbehaves.",
                "🛡 Intercept this process", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (confirm != MessageBoxResult.Yes) return;

            string error = InterceptProxyService.Shared.StartSession(record.Pid, image);
            if (error != null)
            {
                MessageBox.Show(error, "🛡 Intercept", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            UpdateInterceptBanner();
        }

        private void InterceptStopBtn_Click(object sender, RoutedEventArgs e) =>
            InterceptProxyService.Shared.StopSession("stopped by user");

        private void OnInterceptSessionEnded(string reason)
        {
            Dispatcher.BeginInvoke(() =>
            {
                UpdateInterceptBanner();
                StatusText.Text = $"🛡 Intercept ended ({reason}) — proxy, firewall rule and CA restored.";
            });
        }

        private void UpdateInterceptBanner()
        {
            if (InterceptBanner == null) return; // during InitializeComponent
            var intercept = InterceptProxyService.Shared;
            if (!intercept.IsRunning)
            {
                InterceptBanner.Visibility = Visibility.Collapsed;
                if (!TcpStreamCaptureService.Shared.IsRunning)
                    _bannerTimer?.Stop();
                return;
            }

            InterceptBanner.Visibility = Visibility.Visible;
            TimeSpan left = intercept.EndsAtUtc - DateTime.UtcNow;
            if (left < TimeSpan.Zero) left = TimeSpan.Zero;
            InterceptBannerText.Text =
                $"🛡 INTERCEPT ACTIVE — {intercept.TargetDisplay} · local proxy 127.0.0.1:{intercept.Port} · " +
                $"ends in {(int)left.TotalMinutes:00}:{left:ss} · other apps tunneled untouched · decrypted rows tagged 'decrypted · intercept'";
            if (_bannerTimer != null && !_bannerTimer.IsEnabled) _bannerTimer.Start();
        }

        /// <summary>
        /// Honest-UX gate for the Down column: when the capture session has
        /// seen plenty of outbound TCP but not one inbound packet, the
        /// adapter/driver is delivering a one-way view and a 0 in Down means
        /// "not observed", not "nothing came back". The banner says exactly
        /// that; it clears the moment a single reply is seen.
        /// </summary>
        private void UpdateCaptureBanner()
        {
            if (CaptureHealthBanner == null) return; // during InitializeComponent
            var capture = TcpStreamCaptureService.Shared;
            bool oneWayView = capture.IsRunning &&
                              capture.OutboundPackets > 500 &&
                              !capture.InboundSeen;
            if (!oneWayView)
            {
                CaptureHealthBanner.Visibility = Visibility.Collapsed;
                return;
            }
            CaptureHealthBannerText.Text =
                $"⚠ This capture session sees what your PC sends but not the replies — a 0 in Down means \"not observed\", " +
                $"not \"nothing came back\". ({capture.OutboundPackets:N0} packets out, 0 in · mode: {capture.CaptureMode})";
            CaptureHealthBanner.Visibility = Visibility.Visible;
        }

        // -----------------------------------------------------------------------
        // Encrypted-upload toasts + "Apps without keys" + restart under watch
        // -----------------------------------------------------------------------

        /// <summary>
        /// Every &gt;10KB encrypted upload, unthrottled by design — except
        /// the user's ignore list and LookSee itself. The toast jumps
        /// straight to this tab when activated.
        /// </summary>
        private void OnBigEncryptedUpload(TransmissionRecord record)
        {
            if (string.IsNullOrEmpty(record.Image)) return;
            if (TransmissionsIgnoreList.IsIgnored(record.Image)) return;
            if (string.Equals(record.Image, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase)) return;

            Dispatcher.BeginInvoke(() =>
            {
                (Window.GetWindow(this) as MainWindow)?.ShowTransmissionsToast(
                    $"🔒 {record.ProcessDisplay} sent {record.UpDisplay} — encrypted, no keys",
                    $"→ {record.ServerEndpoint} [{record.HostDisplay}] · {record.ProviderAndCountry}\n" +
                    "Review for: restart the app under watch, or turn on key capture.");
                UpdateStatus();
            });
        }

        private static bool IsSelfImage(string image) =>
            string.Equals(image, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase);

        private int NoKeysAppCount() =>
            _pipeline?.GetImageStatsSnapshot().Count(s =>
                s.EncryptedFlows > 0 &&
                !TransmissionsIgnoreList.IsIgnored(s.Image) &&
                !IsSelfImage(s.Image)) ?? 0;

        private void NoKeysBtn_Click(object sender, RoutedEventArgs e)
        {
            if (NoKeysPopup.IsOpen) { NoKeysPopup.IsOpen = false; return; }
            RebuildNoKeysPopup();
            NoKeysPopup.IsOpen = true;
        }

        private void RebuildNoKeysPopup()
        {
            var items = _pipeline.GetImageStatsSnapshot()
                .Where(s => s.EncryptedFlows > 0 &&
                            !TransmissionsIgnoreList.IsIgnored(s.Image) &&
                            !IsSelfImage(s.Image))
                .Take(30)
                .Select(s => new NoKeysItem
                {
                    Image = s.Image,
                    ImageDisplay = Path.GetFileName(s.Image),
                    Summary = $"{s.EncryptedFlows} encrypted · {s.DecryptedFlows} decrypted · " +
                              $"last {s.LastEncryptedUtc.ToLocalTime():MM-dd HH:mm} · " +
                              $"biggest upload {FormatBytes(s.LastEncryptedBiggestUpload)}",
                    Pid = s.LastEncryptedPid,
                    TsUtc = s.LastEncryptedUtc,
                })
                .ToList();
            NoKeysList.ItemsSource = items;

            var ignored = TransmissionsIgnoreList.All();
            IgnoredHeader.Visibility = ignored.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            IgnoredList.ItemsSource = ignored;
        }

        private void NoKeysRestart_Click(object sender, RoutedEventArgs e)
        {
            if (((FrameworkElement)sender).DataContext is NoKeysItem item)
                RestartUnderWatch(item.Image, item.Pid, item.TsUtc);
        }

        private void NoKeysIgnore_Click(object sender, RoutedEventArgs e)
        {
            if (((FrameworkElement)sender).DataContext is NoKeysItem item)
            {
                TransmissionsIgnoreList.Ignore(item.Image);
                RebuildNoKeysPopup();
                UpdateStatus();
            }
        }

        private void IgnoredUnignore_Click(object sender, RoutedEventArgs e)
        {
            if (((FrameworkElement)sender).DataContext is string image)
            {
                TransmissionsIgnoreList.Unignore(image);
                RebuildNoKeysPopup();
                UpdateStatus();
            }
        }

        private void EnableKeysBtn_Click(object sender, RoutedEventArgs e)
        {
            // Routes through the checkbox so the confirm dialog + hygiene
            // path stays single-sourced.
            SystemKeylogCheck.IsChecked = true;
        }

        private void IgnoreBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_selected?.Image == null) return;
            TransmissionsIgnoreList.Ignore(_selected.Image);
            RenderDetail(_selected);
            UpdateStatus();
        }

        private void UnignoreBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_selected?.Image == null) return;
            TransmissionsIgnoreList.Unignore(_selected.Image);
            RenderDetail(_selected);
            UpdateStatus();
        }

        private void RestartBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_selected != null)
                RestartUnderWatch(_selected.Image, _selected.Pid, _selected.TsUtc);
        }

        /// <summary>
        /// The one-click path from "encrypted, no keys" to "decrypts": kill
        /// the app's running instance(s), relaunch the recorded image with
        /// the Sysmon-archived command line and SSLKEYLOGFILE applied.
        /// Single-instance apps (browsers, Electron) get every instance
        /// killed, or the relaunch would just forward to a survivor and
        /// inherit nothing.
        /// </summary>
        private void RestartUnderWatch(string image, int pid, DateTime tsUtc)
        {
            string reason = RestartBlockReason(image);
            if (reason != null)
            {
                MessageBox.Show(reason, "🚀 Restart under watch", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            string commandLine = null, workingDir = null;
            try
            {
                foreach (var createEvent in SysmonArchiveService.SearchCreateEvents(pid, 5)) // newest-first
                {
                    if (tsUtc != default && createEvent.TsUtc > tsUtc.AddMinutes(2))
                        continue; // this PID's later owner (reuse), not the one that sent
                    commandLine = createEvent.Data.GetValueOrDefault("CommandLine");
                    workingDir = createEvent.Data.GetValueOrDefault("CurrentDirectory");
                    if (!string.IsNullOrEmpty(commandLine)) break;
                }
            }
            catch { /* archive unavailable — relaunch bare, without arguments */ }
            string args = SplitArgsFromImage(image, commandLine);

            Process[] running = Array.Empty<Process>();
            try { running = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(image)); }
            catch { }
            string killNote = running.Length > 0
                ? $"This terminates {running.Length} running instance(s) — unsaved work in them is lost."
                : "The app is not running right now.";

            var confirm = MessageBox.Show(
                $"Restart under watch:\n\n{image}\n" +
                (args.Length > 0 ? $"arguments: {args}\n" : "(no arguments recorded)\n") +
                $"\n{killNote}\n" +
                "It relaunches immediately with TLS key capture applied, so its traffic\n" +
                "decrypts here from the next connection on.",
                "🚀 Restart under watch", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (confirm != MessageBoxResult.Yes) return;

            foreach (var proc in running)
            {
                try { proc.Kill(); } catch { /* already exiting or protected — the relaunch still proceeds */ }
            }
            try
            {
                var started = TransmissionKeyService.LaunchUnderWatch(image, args, workingDir);
                StatusText.Text = $"Launched '{Path.GetFileName(image)}' (PID {started?.Id}) under watch — " +
                                  "its next TLS flow will decrypt.";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Relaunch failed: {ex.Message}", "🚀 Restart under watch",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        /// <summary>Why this image can never be restarted under watch, or
        /// null when it can. System components get the honest Schannel
        /// explanation instead of a broken offer.</summary>
        private static string RestartBlockReason(string image)
        {
            if (string.IsNullOrEmpty(image))
                return "No process image was recorded for this flow, so there is nothing to relaunch.";
            if (IsSelfImage(image))
                return "This is LookSee itself — it is not restarted from here.";

            string windowsRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (image.StartsWith(windowsRoot + "\\", StringComparison.OrdinalIgnoreCase) ||
                image.StartsWith(windowsRoot + "/", StringComparison.OrdinalIgnoreCase))
                return $"This is a Windows system component (under {windowsRoot}).\n\n" +
                       "System components use Schannel, which never writes TLS session keys — restarting\n" +
                       "cannot make their traffic decryptable. Use 🛡 Intercept this process instead: it is\n" +
                       "the layer built for exactly these apps, time-boxed and fully reversible.";

            if (image.IndexOf("\\WindowsApps\\", StringComparison.OrdinalIgnoreCase) >= 0)
                return "This is a Store (UWP) app — Windows starts those through app activation,\n" +
                       "so they cannot be relaunched with key capture from here.";
            return null;
        }

        /// <summary>
        /// Strips the exe token from a Sysmon command line, returning just
        /// the arguments. Handles the quoted form, the bare-prefix form, and
        /// a loader-embedded form; anything unrecognizable yields "" rather
        /// than a mangled relaunch.
        /// </summary>
        private static string SplitArgsFromImage(string image, string commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine)) return "";
            string cmd = commandLine.Trim();

            if (cmd.StartsWith('"'))
            {
                int close = cmd.IndexOf('"', 1);
                if (close > 0 &&
                    string.Equals(cmd[1..close], image, StringComparison.OrdinalIgnoreCase))
                    return cmd[(close + 1)..].Trim();
            }
            if (cmd.StartsWith(image, StringComparison.OrdinalIgnoreCase))
                return cmd[image.Length..].Trim().TrimStart('"');

            int embedded = cmd.IndexOf(image, StringComparison.OrdinalIgnoreCase);
            if (embedded >= 0)
                return cmd[(embedded + image.Length)..].Trim().TrimStart('"');
            return "";
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes}B";
            if (bytes < 1048576) return $"{bytes / 1024.0:F1}KB";
            return $"{bytes / 1048576.0:F1}MB";
        }

        /// <summary>One row of the "Apps without keys" popup.</summary>
        public sealed class NoKeysItem
        {
            public string Image { get; set; }
            public string ImageDisplay { get; set; }
            public string Summary { get; set; }
            public int Pid { get; set; }
            public DateTime TsUtc { get; set; }
        }

        // -----------------------------------------------------------------------
        // Status + audit
        // -----------------------------------------------------------------------

        private void UpdateStatus()
        {
            if (ZeroReplyCheck != null)
                ZeroReplyCheck.Content = _zeroReplyOnly
                    ? "⚪ zero-reply (on)"
                    : $"⚪ zero-reply ({_zeroReplyCount})";
            if (StatusText == null || _pipeline == null) return;
            if (!_watching)
            {
                StatusText.Text = "Watcher is stopped.";
                return;
            }
            // Archive size walks the disk — cache it briefly instead of on
            // every incoming row.
            if (DateTime.UtcNow - _archiveStatusAt > TimeSpan.FromSeconds(10))
            {
                _archiveStatusAt = DateTime.UtcNow;
                _archiveStatus = TransmissionsArchiveService.StatusSummary();
            }
            var (days, bytes) = _archiveStatus;
            string size = bytes >= 1024 * 1024 ? $"{bytes / 1024.0 / 1024.0:F0} MB" : $"{bytes / 1024.0:F0} KB";
            StatusText.Text =
                $"Watching: {_rows.Count} transmission(s) · {_pipeline.DecryptedCount} decrypted · " +
                $"{_pipeline.EncryptedNoKeysCount} encrypted-no-keys · queue {_pipeline.LiveQueueDepth}" +
                (days > 0 ? $" · archive {days} day(s), {size} on disk" : "") +
                (_pipeline.DroppedCount > 0 ? $" · {_pipeline.DroppedCount} dropped (busy)" : "");

            int noKeysApps = NoKeysAppCount();
            NoKeysBtn.Content = noKeysApps > 0
                ? $"🔓 Apps without keys ({noKeysApps})"
                : "🔓 Apps without keys";
            bool keysOn = TransmissionKeyService.IsSystemKeylogEnabled();
            EnableKeysBtn.Visibility = _watching && !keysOn ? Visibility.Visible : Visibility.Collapsed;
            if (PopupEnableKeysBtn != null)
                PopupEnableKeysBtn.Visibility = keysOn ? Visibility.Collapsed : Visibility.Visible;
        }

        // -----------------------------------------------------------------------
        // Row menu — the exact Process Monitor action set, copied from
        // AutoCommand: Block/Unblock IP (2-rule v2 scheme), Block/Unblock
        // process, Ignore, Trace, Kill. Same confirmations, same per-class
        // "don't ask again", same rule names — so AutoCommand's Blocks tab
        // manages LookSee's blocks and vice versa.
        // -----------------------------------------------------------------------

        private void RowMenu_Opened(object sender, RoutedEventArgs e)
        {
            var record = FlowGrid.SelectedItem as TransmissionRecord;
            FirewallBlockService.Instance.RefreshSnapshot(); // one COM pass — states are live

            string procName = record == null || string.IsNullOrEmpty(record.Image)
                ? "" : Path.GetFileName(record.Image);

            TraceMenuItem.IsEnabled = record is { Pid: > 0 };
            TraceMenuItem.Header = record is { Pid: > 0 }
                ? $"🔎 Trace PID {record.Pid}…" : "🔎 Trace (unattributed row)";

            IgnoreProcMenuItem.IsEnabled = procName.Length > 0;
            IgnoreProcMenuItem.Header = procName.Length > 0
                ? $"🚫 Ignore process '{procName}'" : "🚫 Ignore process (no row selected)";

            // Block items tell the current state: flip to Unblock when a
            // block exists, and explain (disabled) when it is only paused —
            // re-blocking a paused target would silently not block anything.
            bool validIp = record != null && !string.IsNullOrEmpty(record.RemoteIp) &&
                           System.Net.IPAddress.TryParse(record.RemoteIp, out _);
            var ipState = record == null ? FirewallBlockService.BlockState.None
                                         : FirewallBlockService.Instance.IpState(record.RemoteIp);
            if (validIp && ipState == FirewallBlockService.BlockState.Active)
            {
                BlockIpMenuItem.IsEnabled = true;
                BlockIpMenuItem.Header = $"✅ Unblock remote IP {record.RemoteIp} — traffic resumes";
            }
            else if (validIp && ipState == FirewallBlockService.BlockState.Paused)
            {
                BlockIpMenuItem.IsEnabled = false;
                BlockIpMenuItem.Header = $"⏸ IP block for {record.RemoteIp} is paused — re-enable from AutoCommand → Blocks → Manage all (or wf.msc)";
            }
            else
            {
                BlockIpMenuItem.IsEnabled = validIp;
                BlockIpMenuItem.Header = validIp
                    ? $"⛔ Block remote IP {record.RemoteIp} in Firewall"
                    : "⛔ Block Remote IP in Firewall";
            }

            bool blockableProcess = record is { Pid: > 0 } && !string.IsNullOrEmpty(record.Image);
            var appState = record == null ? FirewallBlockService.BlockState.None
                                          : FirewallBlockService.Instance.AppState(record.Image);
            if (blockableProcess && appState == FirewallBlockService.BlockState.Active)
            {
                BlockAppMenuItem.IsEnabled = true;
                BlockAppMenuItem.Header = $"✅ Unblock process '{procName}' — traffic resumes";
            }
            else if (blockableProcess && appState == FirewallBlockService.BlockState.Paused)
            {
                BlockAppMenuItem.IsEnabled = false;
                BlockAppMenuItem.Header = "⏸ Process block is paused — re-enable from AutoCommand → Blocks → Manage all (or wf.msc)";
            }
            else
            {
                BlockAppMenuItem.IsEnabled = blockableProcess;
                BlockAppMenuItem.Header = blockableProcess
                    ? $"⛔ Block process '{procName}' in Firewall" : "⛔ Block Process in Firewall";
            }

            KillMenuItem.IsEnabled = record is { Pid: > 0 };
            KillMenuItem.Header = KillMenuItem.IsEnabled && procName.Length > 0
                ? $"💀 Kill process '{procName}' (PID {record.Pid})" : "💀 Kill process";
        }

        private void TraceMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (FlowGrid.SelectedItem is not TransmissionRecord { Pid: > 0 } record) return;
            string name = string.IsNullOrEmpty(record.Image)
                ? "" : Path.GetFileNameWithoutExtension(record.Image);
            var win = new ProcessTraceWindow(record.Pid, name, record.Image, null,
                record.TsUtc, record.TsUtc)
            { Owner = Window.GetWindow(this) };
            win.Show();
        }

        private void IgnoreProcMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (FlowGrid.SelectedItem is not TransmissionRecord record ||
                string.IsNullOrEmpty(record.Image)) return;
            string name = Path.GetFileName(record.Image);
            if (MessageBox.Show(
                    $"Ignore '{name}' everywhere?\n\n" +
                    "· This tab: no more encrypted-upload toasts or suggestions (rows stay)\n" +
                    "· Every other feed and the Phone Bill: the process stops being listed\n\n" +
                    "Reversible any time from 🔕 Ignore lists….",
                    "Ignore this app", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
                return;
            TransmissionsIgnoreList.Ignore(record.Image);
            SysmonWatcherService.AddToIgnoreFile(name);
            StatusText.Text = $"🔕 '{name}' ignored everywhere (undo: Ignore lists…).";
            RenderDetail(record); // refresh the detail pane's ignore buttons
        }

        private async void BlockIpMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (FlowGrid.SelectedItem is not TransmissionRecord record) return;

            string ip = record.RemoteIp;
            if (!System.Net.IPAddress.TryParse(ip, out _))
            {
                MessageBox.Show($"'{ip}' is not a valid IP address.", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            // The menu flips to "Unblock" once a block exists — the same
            // item removes it again.
            var state = FirewallBlockService.Instance.IpState(ip);
            if (state == FirewallBlockService.BlockState.Active)
            {
                await ConfirmAndRemoveBlockAsync("ip", ip, record.Image);
                return;
            }
            if (state == FirewallBlockService.BlockState.Paused)
            {
                StatusText.Text = $"⏸ The block for {ip} is paused (traffic flows). Re-enable it from AutoCommand → Blocks → Manage all.";
                return;
            }

            string msWarning = IpClassifier.WarningText(ip); // "" when not Microsoft infrastructure
            bool msApplies = msWarning.Length > 0;

            // Per-class suppression: the prompt is skipped only when the
            // generic confirm AND (if applicable) the Microsoft-infra warning
            // are both silenced — a silenced generic confirm still shows the
            // dialog when the infra warning itself is not silenced.
            bool confirmSuppressed =
                ConfirmPrefs.IsSuppressed(ConfirmPrefs.ConfirmIp) &&
                (!msApplies || ConfirmPrefs.IsSuppressed(ConfirmPrefs.WarnMsInfra));

            if (!confirmSuppressed)
            {
                string warning = msApplies && !ConfirmPrefs.IsSuppressed(ConfirmPrefs.WarnMsInfra)
                    ? msWarning + "\n\n⚠ Think twice: this IP is Microsoft infrastructure."
                    : "";
                string detail = $"Contacted by '{record.ProcessDisplay}'.\n\n" +
                                "2 rules are created: outbound TCP and UDP — inbound is already covered by the\n" +
                                "firewall's stateful filtering.\n" +
                                "Undo anytime: right-click this row again, the 🚑 Restore Internet button in\nthe status bar, or AutoCommand → Blocks → Manage all.";
                string key = warning.Length > 0 ? ConfirmPrefs.WarnMsInfra : ConfirmPrefs.ConfirmIp;
                string label = warning.Length > 0
                    ? "Don't warn me about Microsoft-infrastructure IPs — I know what I'm doing"
                    : "Don't ask again before blocking remote IPs";
                if (!ConfirmBlockWithDialog($"Block all outbound traffic to remote IP {ip}?", warning, detail, key, label))
                    return;
            }

            try
            {
                string note = BuildProvenance(record, $"→ {ip}", confirmSuppressed);
                var (created, updated) = await FirewallBlockService.Instance.AddIpBlockAsync(ip, note);
                await RefreshBlockStateAsync();
                StatusText.Text = created > 0
                    ? $"⛔ Blocked remote IP {ip} — 2 rules (outbound TCP/UDP). Provenance written to the rule description (visible in wf.msc)."
                    : $"Block for {ip} already existed — refreshed its provenance (no duplicate rules).";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to block remote IP: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void BlockAppMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (FlowGrid.SelectedItem is not TransmissionRecord { Pid: > 0 } record) return;

            // A flow's process may have exited long ago — the rule matches
            // the exe path and arms for the next run. The full path is right
            // on the row (captured at flow time), so no archive recovery is
            // needed; a recycled PID cannot be mistaken for the suspect.
            string path = record.Image;
            if (string.IsNullOrEmpty(path))
            {
                MessageBox.Show(
                    "This row carries no executable path, so there is nothing to arm the block on.\n" +
                    "You can still act on the infrastructure it used: right-click the row →\n" +
                    $"'⛔ Block Remote IP in Firewall' for {record.RemoteIp}.",
                    "Cannot block — no path", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var state = FirewallBlockService.Instance.AppState(path);
            if (state == FirewallBlockService.BlockState.Active)
            {
                await ConfirmAndRemoveBlockAsync("proc", path, path);
                return;
            }
            if (state == FirewallBlockService.BlockState.Paused)
            {
                StatusText.Text = $"⏸ The block for {path} is paused (traffic flows). Re-enable it from AutoCommand → Blocks → Manage all.";
                return;
            }

            string procName = Path.GetFileNameWithoutExtension(path);
            string warning = "";
            if (procName.Equals("svchost", StringComparison.OrdinalIgnoreCase) ||
                procName.Equals("taskhostw", StringComparison.OrdinalIgnoreCase))
                warning = $"'{procName}.exe' hosts Windows SERVICES. One instance carries DNS (Dnscache),\n" +
                          "DHCP, diagnostics and more — blocking it is the #1 cause of 'I blocked something\n" +
                          "and lost my internet'. If a specific connection looks bad, block the IP, not this process.";
            else if (path.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase))
                warning = $"'{procName}' is a Windows component. Blocking it can break shell features,\n" +
                          "widgets, or web content in Start/Settings.";

            bool coreApplies = warning.Length > 0;
            bool confirmSuppressed =
                ConfirmPrefs.IsSuppressed(ConfirmPrefs.ConfirmProcess) &&
                (!coreApplies || ConfirmPrefs.IsSuppressed(ConfirmPrefs.WarnWindowsCore));

            // The exited note is information, not a warning class: it rides
            // whichever surface the user sees.
            string exitedNote = "";
            try
            {
                using var probe = System.Diagnostics.Process.GetProcessById(record.Pid);
                if (string.Equals(probe.ProcessName, procName, StringComparison.OrdinalIgnoreCase)) probe.Dispose();
                else exitedNote = "⚠ This PID now runs a different process (PID reuse) — the block arms on the\n" +
                                  $"exe path captured when the row was recorded:\n\n";
            }
            catch (ArgumentException)
            {
                exitedNote = "⚠ This process has already exited — the block is preventive:\n" +
                             "the rule takes effect on the exe's NEXT run. A copy of the exe at a\n" +
                             "different path is NOT covered.\n\n";
            }

            if (!confirmSuppressed)
            {
                string shownWarning = coreApplies && !ConfirmPrefs.IsSuppressed(ConfirmPrefs.WarnWindowsCore) ? warning : "";
                string detail = exitedNote + $"{path}\n\n(1 outbound rule)\n" +
                                "Undo anytime: right-click the row again, the 🚑 Restore Internet button in\nthe status bar, or AutoCommand → Blocks → Manage all.";
                string key = shownWarning.Length > 0 ? ConfirmPrefs.WarnWindowsCore : ConfirmPrefs.ConfirmProcess;
                string label = shownWarning.Length > 0
                    ? "Don't warn me about blocking Windows service hosts / components — I know what I'm doing"
                    : "Don't ask again before blocking processes";
                if (!ConfirmBlockWithDialog($"Block all outbound traffic from '{procName}'?", shownWarning, detail, key, label))
                    return;
            }

            try
            {
                string note = BuildProvenance(record, $"app: {path}", confirmSuppressed);
                var (created, updated) = await FirewallBlockService.Instance.AddAppBlockAsync(path, note);
                await RefreshBlockStateAsync();
                StatusText.Text = created > 0
                    ? $"⛔ Blocked process '{procName}' — 1 outbound rule on its exe path. Provenance written to the rule description (visible in wf.msc)."
                    : $"Block for '{procName}' already existed — refreshed its provenance (no duplicate rules).";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to block process: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void KillMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (FlowGrid.SelectedItem is not TransmissionRecord { Pid: > 0 } record) return;

            try
            {
                var proc = System.Diagnostics.Process.GetProcessById(record.Pid);

                // PID reuse guard: the row may be stale — the original process
                // exited and Windows recycled the PID to something else.
                // Verify the live identity before pulling the trigger.
                string liveName = string.Empty;
                try { liveName = proc.ProcessName; } catch { }

                string knownName = Path.GetFileNameWithoutExtension(record.Image ?? string.Empty);
                string confirmName = Path.GetFileName(record.Image ?? string.Empty);
                if (knownName.Length > 0 && !liveName.Equals(knownName, StringComparison.OrdinalIgnoreCase))
                {
                    confirmName = liveName;
                    var stale = MessageBox.Show(
                        $"This row is stale: PID {record.Pid} now runs '{liveName}', not '{knownName}'.\n\n" +
                        $"Kill the running process '{liveName}' (PID {record.Pid}) anyway?\n" +
                        "This forcefully terminates the application.",
                        "PID reused — confirm kill", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
                    if (stale != MessageBoxResult.Yes) return;
                }
                else if (MessageBox.Show(
                    $"Kill process '{confirmName}' (PID {record.Pid})?\nThis forcefully terminates the application.",
                    "Confirm Kill", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
                {
                    return;
                }

                proc.Kill();
                await Task.Delay(500); // Give it a moment to release ports
                StatusText.Text = $"💀 Killed '{confirmName}' (PID {record.Pid}).";
            }
            catch (ArgumentException)
            {
                MessageBox.Show($"Process {record.Pid} is no longer running (it already exited).",
                    "Info", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to kill process: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task ConfirmAndRemoveBlockAsync(string kind, string key, string imageForNote)
        {
            if (MessageBox.Show($"Remove the firewall block for\n{key}?\n\nIts rules are deleted and traffic resumes immediately.",
                "Confirm Unblock", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
            try
            {
                int removed = kind == "ip"
                    ? await FirewallBlockService.Instance.RemoveBlockRulesForIpAsync(key)
                    : await FirewallBlockService.Instance.RemoveBlockRulesForAppAsync(key);
                await RefreshBlockStateAsync();
                StatusText.Text = $"✅ Removed {removed} rule(s) for {key} — traffic resumes.";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to remove block: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>Provenance written into the rule Description — the audit
        /// trail visible in wf.msc (same format AutoCommand writes).</summary>
        private static string BuildProvenance(TransmissionRecord record, string what, bool confirmSuppressed)
        {
            string proc = record.ProcessDisplay;
            return $"[blocked {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC] {proc}" +
                   (record.Pid > 0 ? $" (PID {record.Pid})" : "") +
                   $" {what} · ↑{record.UpDisplay} ↓{record.DownDisplay}" +
                   (string.IsNullOrEmpty(record.Sni) ? "" : $" · SNI {record.Sni}") +
                   $" · LookSee Who's Talking" +
                   (confirmSuppressed ? " · confirm suppressed (don't-ask-again)" : "");
        }

        private bool ConfirmBlockWithDialog(string headline, string warning, string detail,
                                            string suppressKey, string suppressLabel)
        {
            var win = new BlockConfirmWindow(headline, warning, detail, suppressKey, suppressLabel)
            { Owner = Window.GetWindow(this) };
            bool confirmed = win.ShowDialog() == true && win.Confirmed;
            if (confirmed && win.Suppress && win.SuppressKey != null)
                ConfirmPrefs.Suppress(win.SuppressKey);
            return confirmed;
        }

        /// <summary>Re-derives block states and re-badges every row (new and
        /// old) after any block add/remove.</summary>
        private async Task RefreshBlockStateAsync()
        {
            await Task.Run(() => FirewallBlockService.Instance.RefreshSnapshot());
            foreach (var row in _rows)
                row.BlockedByRule =
                    FirewallBlockService.Instance.IpState(row.RemoteIp) == FirewallBlockService.BlockState.Active ||
                    FirewallBlockService.Instance.AppState(row.Image) == FirewallBlockService.BlockState.Active;
            CollectionViewSource.GetDefaultView(_rows).Refresh();
        }

        // ── AutoCommand bridge button ────────────────────────────────────

        private async void ImportAcBtn_Click(object sender, RoutedEventArgs e)
        {
            ImportAcBtn.IsEnabled = false;
            try
            {
                StatusText.Text = "Importing ignore lists from AutoCommand…";
                var r = await AutoCommandImportService.ImportAsync();
                await RefreshBlockStateAsync(); // badges track live rules, whatever made them
                StatusText.Text = r.FoundAutoCommand
                    ? $"⇄ Imported from AutoCommand: +{r.NamesImported} ignored process(es), +{r.ImagesImported} ignored app(s). AutoCommand was not changed."
                    : "⇄ AutoCommand not found on this machine — nothing to import (LookSee works fully without it).";
            }
            finally { ImportAcBtn.IsEnabled = true; }
        }

        private void IgnoreListsBtn_Click(object sender, RoutedEventArgs e)
        {
            var win = new IgnoredProcessesWindow { Owner = Window.GetWindow(this) };
            win.ShowDialog();
            CollectionViewSource.GetDefaultView(_rows).Refresh(); // un-ignoring may reveal rows
        }
    }
}
