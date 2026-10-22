using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
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
using System.Windows.Threading;
using LookSee.Models;
using LookSee.Services;

namespace LookSee.Views
{
    /// <summary>
    /// BITS Transfers tab: every Background Intelligent Transfer job with
    /// where it connects (host → resolved IPs → owner org), what it moves
    /// (direction, bytes, per-file names + local paths + SHA-256), how
    /// often (per creator→host pattern rollups), why (reason-catalog
    /// explanation + verdict), and whether the traffic bypasses the
    /// firewall rules (default outbound action + BITS-scoped allow rules
    /// + the structural svchost/T1197 fact). Content preview is the one
    /// explicit, per-file opt-in action — nothing about it is persisted
    /// or exported. The tracer itself is read-only: it never creates,
    /// cancels or modifies jobs (BITS delivers Windows Update).
    /// </summary>
    public partial class BitsView : UserControl
    {
        private const int RowCap = 3000;

        private readonly ObservableCollection<BitsJobItem> _rows = new();
        private readonly Dictionary<string, BitsJobItem> _rowByJob = new();

        private BitsWatcherService _watcher;
        private BitsFirewallContextService _firewall;
        private DateTime _firewallFetchedUtc = DateTime.MinValue;

        private bool _initialized;
        private bool _watching;
        private bool _paused;
        private readonly Queue<BitsJobItem> _pauseBuffer = new();
        private Regex _filter;
        private BitsJobItem _selected;
        private DispatcherTimer _refreshTimer;

        public BitsView()
        {
            InitializeComponent();
            JobsGrid.ItemsSource = _rows;

            var view = (ListCollectionView)CollectionViewSource.GetDefaultView(_rows);
            view.SortDescriptions.Add(new System.ComponentModel.SortDescription(
                nameof(BitsJobItem.FirstSeenUtc), System.ComponentModel.ListSortDirection.Descending));
            view.Filter = FilterRow;
        }

        // -----------------------------------------------------------------------
        // Lifecycle — auto-start on first view; keeps tracing across tab
        // switches (the v2026.10.16.1 Svchost Trace lesson). Only the UI
        // refresh timer parks on Unloaded; the watcher keeps stitching.
        // -----------------------------------------------------------------------

        private void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            if (!_initialized)
            {
                _initialized = true;
                _watcher = new BitsWatcherService();
                _watcher.OnError += ShowError;
                _watcher.OnJobUpserted += OnJobUpserted;
                _watcher.OnUploadJob += ForwardUploadAlert;

                _firewall = new BitsFirewallContextService();

                _refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(10) };
                _refreshTimer.Tick += (s, _) => PeriodicRefresh();
            }

            if (!_watching) StartWatching();
            _refreshTimer.Start();
            RefreshFirewallBanner();
        }

        private void UserControl_Unloaded(object sender, RoutedEventArgs e)
        {
            _refreshTimer?.Stop();
        }

        private void StartWatching()
        {
            _watcher.Start();
            _watching = true;
            ToggleWatchBtn.Content = "Stop Watch";
            UpdateStatus();
        }

        private void StopWatching()
        {
            _watcher.Stop();
            _watching = false;
            ToggleWatchBtn.Content = "Start Watch";
            UpdateStatus();
        }

        private void ToggleWatchBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_watching) StopWatching();
            else StartWatching();
        }

        private void ShowError(string message) => Dispatcher.BeginInvoke(() => StatusText.Text = $"⚠ {message}");

        // -----------------------------------------------------------------------
        // Rows
        // -----------------------------------------------------------------------

        private void OnJobUpserted(BitsJobItem item)
        {
            Dispatcher.BeginInvoke(() =>
            {
                if (item == null) return;
                string key = RowKey(item);
                if (_rowByJob.TryGetValue(key, out var existing))
                {
                    if (existing == item && _selected == item) RenderDetail(item);   // in-place enrichment landed
                    return;
                }

                if (_paused)
                {
                    _pauseBuffer.Enqueue(item);
                    UpdateStatus();
                    return;
                }
                AddRow(item);
            });
        }

        private static string RowKey(BitsJobItem item) =>
            item.JobId ?? $"name:{item.Name?.ToLowerInvariant()}";

        private void AddRow(BitsJobItem item)
        {
            _rowByJob[RowKey(item)] = item;
            _rows.Insert(0, item);
            while (_rows.Count > RowCap)
            {
                var oldest = _rows[^1];
                _rows.RemoveAt(_rows.Count - 1);
                if (_rowByJob.TryGetValue(RowKey(oldest), out var row) && row == oldest) _rowByJob.Remove(RowKey(oldest));
            }
            UpdateStatus();
        }

        /// <summary>UPLOAD-type job: forward to the app-level threat status bar.</summary>
        private void ForwardUploadAlert(BitsJobItem item)
        {
            Dispatcher.BeginInvoke(() =>
            {
                string who = string.IsNullOrEmpty(item.CreatorImage)
                    ? item.OwnerAccount ?? "unknown creator"
                    : $"{Path.GetFileName(item.CreatorImage)} (PID {item.CreatorPid})";
                string where = $"{item.HostDisplay ?? "unknown host"}" +
                               (string.IsNullOrEmpty(item.Org) ? "" : $" · {item.Org}");
                if (Window.GetWindow(this) is MainWindow mw)
                    mw.RaiseExternalThreat("BITS Upload Job",
                        $"\"{item.Name}\" created by {who} is UPLOADING data to {where}. " +
                        "BITS upload jobs are the documented exfiltration vector (ATT&CK T1197) — review it in the BITS Transfers tab.");
                StatusText.Text = $"⚠ BITS UPLOAD job \"{item.Name}\" → {where} — flagged for review";
            });
        }

        // -----------------------------------------------------------------------
        // Toolbar
        // -----------------------------------------------------------------------

        private void PauseBtn_Click(object sender, RoutedEventArgs e)
        {
            _paused = !_paused;
            PauseBtn.Content = _paused ? "▶ Resume" : "⏸ Pause";
            if (!_paused)
                while (_pauseBuffer.Count > 0)
                    AddRow(_pauseBuffer.Dequeue());
            UpdateStatus();
        }

        private void ClearBtn_Click(object sender, RoutedEventArgs e)
        {
            _rows.Clear();
            _rowByJob.Clear();
            _pauseBuffer.Clear();
            _selected = null;
            DetailRecordPanel.Children.Clear();
            FilesPanel.Children.Clear();
            ResetDetailPane();
            UpdateStatus();
        }

        private void ExportBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_rows.Count == 0)
            {
                MessageBox.Show("Nothing to export yet.", "Export", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "JSONL files (*.jsonl)|*.jsonl|All files (*.*)|*.*",
                FileName = $"bits-jobs-{DateTime.Now:yyyyMMdd-HHmmss}.jsonl"
            };
            if (dialog.ShowDialog() != true) return;

            try
            {
                var options = new JsonSerializerOptions { WriteIndented = false };
                using var writer = new StreamWriter(dialog.FileName, append: false);
                foreach (var row in _rows)
                    writer.WriteLine(JsonSerializer.Serialize(row, options));
                MessageBox.Show($"Exported {_rows.Count} BITS job record(s) to:\n{dialog.FileName}\n\nMetadata only — file content is never exported.",
                    "Export", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Export failed: {ex.Message}", "Export", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ShowJobsBtn_Click(object sender, RoutedEventArgs e)
        {
            JobsGrid.Visibility = Visibility.Visible;
            PatternsGrid.Visibility = Visibility.Collapsed;
        }

        private void ShowPatternsBtn_Click(object sender, RoutedEventArgs e)
        {
            JobsGrid.Visibility = Visibility.Collapsed;
            PatternsGrid.Visibility = Visibility.Visible;
            if (_watcher != null) PatternsGrid.ItemsSource = _watcher.StatsSnapshot();
        }

        // -----------------------------------------------------------------------
        // Firewall banner
        // -----------------------------------------------------------------------

        private void RefreshFirewallBanner(bool force = false)
        {
            if (_firewall == null) return;
            System.Threading.Tasks.Task.Run(() =>
            {
                var facts = _firewall.Get(force);
                var verdict = BitsFirewallContextService.BuildSummary(facts);
                Dispatcher.BeginInvoke(() =>
                {
                    _firewallFetchedUtc = DateTime.UtcNow;
                    FirewallBannerText.Text = $"🛡 Firewall: {verdict.Headline}";
                    FirewallBannerText.Foreground = verdict.Bypassed
                        ? new SolidColorBrush(Color.FromRgb(0xE5, 0xA6, 0x31))
                        : new SolidColorBrush(Color.FromRgb(0x4E, 0xC9, 0x6F));
                    if (_selected != null) RenderFirewallSection(verdict);
                });
            });
        }

        private void RefreshFirewallMenuItem_Click(object sender, RoutedEventArgs e) => RefreshFirewallBanner(force: true);

        // -----------------------------------------------------------------------
        // Periodic refresh
        // -----------------------------------------------------------------------

        private void PeriodicRefresh()
        {
            UpdateStatus();
            if (PatternsGrid.Visibility == Visibility.Visible && _watcher != null)
                PatternsGrid.ItemsSource = _watcher.StatsSnapshot();
            if (DateTime.UtcNow - _firewallFetchedUtc > TimeSpan.FromMinutes(5))
                RefreshFirewallBanner();
        }

        private void UpdateStatus()
        {
            if (!_watching)
            {
                StatusText.Text = "Tracer is stopped.";
                return;
            }
            string paused = _paused ? $" · paused ({_pauseBuffer.Count} buffered)" : "";
            int uploads = _rows.Count(r => r.IsUpload);
            int review = _rows.Count(r => r.Verdict == "Review");
            int hosts = _rows.Select(r => r.Host).Where(h => !string.IsNullOrEmpty(h)).Distinct().Count();
            StatusText.Text = $"Tracing: {_rows.Count} job(s) · {hosts} host(s) · {uploads} upload(s) · {review} review{paused}";
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
            catch (ArgumentException) { /* incomplete pattern mid-typing: keep the last valid filter */ }
            CollectionViewSource.GetDefaultView(_rows).Refresh();
        }

        private bool FilterRow(object obj)
        {
            if (obj is not BitsJobItem item) return false;
            if (_filter == null) return true;
            return _filter.IsMatch($"{item.Name} {item.Url} {item.Host} {item.Org} {item.CreatorImage} {item.Direction} {item.OwnerAccount}");
        }

        // -----------------------------------------------------------------------
        // Detail pane
        // -----------------------------------------------------------------------

        private void JobsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _selected = JobsGrid.SelectedItem as BitsJobItem;
            RenderDetail(_selected);
        }

        private void JobsGrid_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.OriginalSource is DependencyObject source &&
                ItemsControl.ContainerFromElement(JobsGrid, source) is DataGridRow row)
                row.IsSelected = true;
        }

        private void RenderDetail(BitsJobItem item)
        {
            DetailRecordPanel.Children.Clear();
            FilesPanel.Children.Clear();
            if (item == null)
            {
                ResetDetailPane();
                return;
            }

            AddDetail("Job ID", item.JobId);
            AddDetail("Name", item.Name);
            AddDetail("First seen (local)", item.FirstSeenUtc == default ? "—" : item.FirstSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"));
            AddDetail("Last event (local)", item.LastSeenUtc == default ? "—" : item.LastSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"));
            AddDetail("Created by", item.CreatorDisplay);
            AddDetail("Creator image", item.CreatorImage);
            AddDetail("Creator signature", string.IsNullOrEmpty(item.CreatorSigner) ? "…" : item.CreatorSigner);
            AddDetail("Job owner", item.OwnerAccount);
            AddDetail("Direction", string.IsNullOrEmpty(item.Direction)
                ? "— (history-only job; direction needs the live COM queue)"
                : (item.IsUpload ? item.Direction + "  ⚠ exfil vector" : item.Direction));
            AddDetail("URL", item.Url);
            AddDetail("Host : port", string.IsNullOrEmpty(item.Host) ? "—" : $"{item.Host} : {item.Port}");
            AddDetail("Resolved IP(s)", string.IsNullOrEmpty(item.ResolvedIps) ? "…" : item.ResolvedIps);
            AddDetail("Destination owner", string.IsNullOrEmpty(item.Org) ? "…" : item.Org);
            AddDetail("Bytes", item.BytesDisplay);
            AddDetail("State", string.IsNullOrEmpty(item.State) ? "—" : item.State);
            AddDetail("Status", string.IsNullOrEmpty(item.StatusText) ? "—" : item.StatusText);
            AddDetail("Verdict", item.Verdict);

            RenderFiles(item);

            WhyText.Text = string.IsNullOrEmpty(item.ReasonText)
                ? "Explanation pending enrichment (DNS owner + catalog)…"
                : item.ReasonText;

            var verdict = BitsFirewallContextService.BuildSummary(_firewall?.Cached());
            RenderFirewallSection(verdict);

            TimelineList.ItemsSource = item.Timeline
                .Select(t => t.Display)
                .Reverse()
                .ToList();
        }

        private void RenderFirewallSection(BitsFirewallContextService.Verdict verdict)
        {
            if (verdict == null)
            {
                FirewallHeadlineText.Text = "Firewall: does BITS bypass the rules here? (checking…)";
                FirewallDetailText.Text = "";
                return;
            }
            FirewallHeadlineText.Text = $"🛡 {verdict.Headline}";
            string creatorNote = string.IsNullOrEmpty(_selected?.CreatorImage)
                ? ""
                : $"\n\nFor this job specifically: it was created by {_selected.CreatorDisplay}, but the connection is made by the BITS service inside svchost — a block on the creator's image would not stop this transfer.";
            FirewallDetailText.Text = $"{verdict.Detail}{creatorNote}\n\n{BitsFirewallContextService.StructuralNote}";
        }

        private void RenderFiles(BitsJobItem item)
        {
            lock (item.Files)
            {
                if (item.Files.Count == 0)
                {
                    FilesPanel.Children.Add(new TextBlock
                    {
                        Text = "(no per-file records — local paths only exist for jobs observed live via the COM queue)",
                        Foreground = FindResource("TextSecondaryBrush") as Brush,
                        FontSize = 11,
                        TextWrapping = TextWrapping.Wrap
                    });
                    return;
                }

                foreach (var file in item.Files)
                {
                    var panel = new StackPanel { Margin = new Thickness(0, 0, 0, 10) };

                    var remote = new TextBlock
                    {
                        Text = $"⬇ {file.RemoteDisplay}",
                        FontFamily = new FontFamily("Consolas"),
                        FontSize = 11,
                        TextTrimming = TextTrimming.CharacterEllipsis,
                        ToolTip = file.RemoteName
                    };
                    panel.Children.Add(remote);

                    var local = new TextBlock
                    {
                        Text = $"→ {file.LocalDisplay}",
                        FontFamily = new FontFamily("Consolas"),
                        FontSize = 11,
                        Foreground = FindResource("TextSecondaryBrush") as Brush,
                        TextTrimming = TextTrimming.CharacterEllipsis,
                        ToolTip = file.LocalName
                    };
                    panel.Children.Add(local);

                    var meta = new TextBlock
                    {
                        Text = $"{file.SizeDisplay} · SHA-256 {file.HashDisplay}",
                        FontFamily = new FontFamily("Consolas"),
                        FontSize = 10,
                        Foreground = FindResource("TextSecondaryBrush") as Brush,
                        TextTrimming = TextTrimming.CharacterEllipsis,
                        ToolTip = file.Sha256 ?? file.HashStatus
                    };
                    panel.Children.Add(meta);

                    var previewBtn = new Button
                    {
                        Content = "🔎 Preview content (explicit opt-in)",
                        Style = FindResource("PrimaryButton") as Style,
                        Margin = new Thickness(0, 4, 0, 0),
                        FontSize = 11,
                        Padding = new Thickness(8, 2, 8, 2),
                        IsEnabled = !string.IsNullOrEmpty(file.LocalName) && File.Exists(file.LocalName),
                        ToolTip = string.IsNullOrEmpty(file.LocalName)
                            ? "Local path unknown for this job"
                            : File.Exists(file.LocalName)
                                ? "Opens a read-only text/hex view of the first bytes. This is the only action that reads content; nothing is stored or exported."
                                : "File no longer exists at its destination path"
                    };
                    previewBtn.Click += (s, e) =>
                    {
                        var win = new BitsContentPreviewWindow(file, item.Name) { Owner = Window.GetWindow(this) };
                        win.Show();
                    };
                    panel.Children.Add(previewBtn);

                    FilesPanel.Children.Add(panel);
                }
            }
        }

        private void AddDetail(string label, string value)
        {
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
            var panel = new StackPanel { Margin = new Thickness(0, 0, 0, 8) };
            panel.Children.Add(labelBlock);
            panel.Children.Add(valueBlock);
            DetailRecordPanel.Children.Add(panel);
        }

        private void ResetDetailPane()
        {
            WhyText.Text = "Select a job row — the explanation, firewall context and event timeline appear here.";
            FirewallHeadlineText.Text = "Firewall: does BITS bypass the rules here?";
            FirewallDetailText.Text = "";
            TimelineList.ItemsSource = null;
        }

        // -----------------------------------------------------------------------
        // Context menu actions
        // -----------------------------------------------------------------------

        private void CopyRowMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (JobsGrid.SelectedItem is BitsJobItem item)
                Clipboard.SetText(JsonSerializer.Serialize(item, new JsonSerializerOptions { WriteIndented = true }));
        }

        /// <summary>
        /// The whole job investigation as markdown on the clipboard: record,
        /// creator + signature, destination attribution, reason verdict,
        /// firewall-bypass verdict, per-file hashes and the event timeline —
        /// the same evidence chain as the pane, in shareable form (metadata only).
        /// </summary>
        private void InvestigateMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (JobsGrid.SelectedItem is not BitsJobItem item) return;

            var fw = BitsFirewallContextService.BuildSummary(_firewall?.Cached());
            var sb = new StringBuilder();
            sb.AppendLine($"# BITS job investigation — {item.Name ?? item.JobId}");
            sb.AppendLine($"First seen (local): {(item.FirstSeenUtc == default ? "—" : item.FirstSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"))}");
            sb.AppendLine($"Job ID: {item.JobId}");
            sb.AppendLine($"Created by: {item.CreatorDisplay}  ·  owner: {item.OwnerAccount}");
            sb.AppendLine($"Creator signature: {(string.IsNullOrEmpty(item.CreatorSigner) ? "(pending)" : item.CreatorSigner)}");
            sb.AppendLine($"Direction: {(item.Direction ?? "— (history-only)")}  ·  state: {item.State ?? "—"}  ·  {item.StatusText ?? ""}");
            sb.AppendLine($"URL: {item.Url ?? "—"}");
            sb.AppendLine($"Destination: {item.Host ?? "—"}:{item.Port}  →  IP(s) {item.ResolvedIps ?? "…"}  ·  owner {item.Org ?? "…"}");
            sb.AppendLine($"Bytes: {item.BytesDisplay}");
            sb.AppendLine();
            sb.AppendLine($"Why: {item.ReasonText ?? "(explanation pending)"}");
            sb.AppendLine($"Verdict: {item.Verdict}");
            sb.AppendLine();
            sb.AppendLine($"Firewall bypass: {(fw == null ? "(not checked)" : fw.Headline)}");
            if (fw != null) sb.AppendLine(fw.Detail);
            sb.AppendLine(BitsFirewallContextService.StructuralNote);
            sb.AppendLine();
            lock (item.Files)
            {
                if (item.Files.Count == 0) sb.AppendLine("Files: no per-file records (job predates live tracing).");
                foreach (var f in item.Files)
                    sb.AppendLine($"File: {f.RemoteName} → {f.LocalName}  ({f.SizeDisplay}, SHA-256 {f.HashDisplay})");
            }
            sb.AppendLine();
            sb.AppendLine("Event timeline (Bits-Client operational log):");
            foreach (var t in item.Timeline)
                sb.AppendLine($"  {t.Display}");
            sb.AppendLine();
            sb.AppendLine($"Collected {DateTime.Now:yyyy-MM-dd HH:mm:ss} by LookSee · BITS Transfers (metadata only — content never exported)");

            Clipboard.SetText(sb.ToString());
            StatusText.Text = $"📋 Investigation for \"{item.Name}\" copied to the clipboard";
        }
    }
}
