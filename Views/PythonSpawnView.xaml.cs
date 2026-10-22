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
using LookSee.Models;
using LookSee.Services;

namespace LookSee.Views
{
    /// <summary>
    /// Python Spawns feed (the "Python" segment of the Spawns tab):
    /// Sysmon-backed spawn tracing (who/what/when), the
    /// audit-hook join for the Python stack at spawn (why), and per-flow TLS
    /// plaintext (what they send) for instrumented environments.
    /// </summary>
    public partial class PythonSpawnView : UserControl
    {
        private const int RowCap = 5000;

        private readonly ObservableCollection<SpawnItem> _rows = new();
        private readonly Dictionary<int, SpawnItem> _rowByPid = new();
        private readonly Dictionary<int, List<TcpFlowRecord>> _flowsByPid = new();

        private ImageSpawnWatcherService _watcher;
        private PyTraceReaderService _traceReader;
        private TcpStreamCaptureService _capture;
        private TlsKeylogService _keylog;

        private bool _initialized;
        private bool _watching;
        private bool _paused;
        private bool _backfilled;
        private readonly Queue<SpawnItem> _pauseBuffer = new();
        private Regex _filter;
        private SpawnItem _selected;
        private TcpFlowRecord _selectedFlow;
        private TlsDecryptResult _decryptResult;
        private string _settingsPath;

        public PythonSpawnView()
        {
            InitializeComponent();
            SpawnGrid.ItemsSource = _rows;

            var view = (ListCollectionView)CollectionViewSource.GetDefaultView(_rows);
            view.SortDescriptions.Add(new System.ComponentModel.SortDescription(
                nameof(SpawnItem.TimeUtc), System.ComponentModel.ListSortDirection.Descending));
            view.Filter = FilterRow;
        }

        // -----------------------------------------------------------------------
        // Lifecycle: lazy start on first show; a recorder must not stop
        // because the user looked at another tab or another Spawns feed.
        // Coverage runs until the user presses Stop Watch (or the app exits);
        // the shared raw-socket capture is refcounted, so the AddRef taken
        // here is balanced by an explicit Stop Watch or app shutdown.
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
            // Deliberately keeps watching (see above).
        }

        /// <summary>Live state for the Spawns host's feed indicator.</summary>
        public bool IsWatching => _watching;

        private void InitializeServices()
        {
            _watcher = new ImageSpawnWatcherService(ImageSpawnWatcherService.IsPythonImage, "python", venvPairing: true);
            _traceReader = new PyTraceReaderService();
            // Shared app-level capture (one raw socket for the whole app,
            // refcounted across tabs). Its settings (PersistFlows, budgets,
            // idle timeout) are per-instance and therefore now app-wide.
            _capture = TcpStreamCaptureService.Shared;
            _keylog = new TlsKeylogService();

            _watcher.OnError += ShowError;
            _watcher.OnSpawn += OnSpawn;
            _watcher.OnNetworkConnect += OnNetworkConnect;

            _traceReader.OnError += ShowError;
            _traceReader.OnRecord += OnTraceRecord;

            _capture.OnError += ShowError;
            _capture.OnFlowFinalized += OnFlowFinalized;

            LoadSettings();
            TlsKeylogService.EnsureHygiene();
        }

        private void StartWatching()
        {
            _watcher.Start();
            _traceReader.Start();
            _capture.AddRef();
            _keylog.Refresh();
            _watching = true;
            ToggleWatchBtn.Content = "Stop Watch";
            UpdateStatus();
            BackfillHistory();
        }

        /// <summary>
        /// The live watchers only deliver what happens while this tab is the
        /// selected one — pythons that ran while the user was elsewhere would
        /// otherwise never appear. Replays the last hours of Sysmon EID 1/5
        /// through the same handlers (parentage, venv pairing, Exited stamps),
        /// deduped against rows that already arrived live. Same pattern as the
        /// taskhostw tab.
        /// </summary>
        private void BackfillHistory()
        {
            if (_backfilled) return;
            _backfilled = true;
            System.Threading.Tasks.Task.Run(() =>
            {
                int seeded = _watcher.Backfill(TimeSpan.FromHours(6));
                Dispatcher.BeginInvoke(() =>
                {
                    if (seeded > 0)
                        StatusText.Text = $"Loaded {seeded} recent spawn(s) from the last 6 h of Sysmon history";
                });
            });
        }

        private void StopWatching()
        {
            _watcher.Stop();
            _traceReader.Stop();
            _capture.Release();
            _watching = false;
            ToggleWatchBtn.Content = "Start Watch";
            UpdateStatus();
        }

        private void ToggleWatchBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_watching) StopWatching();
            else StartWatching();
        }

        private void ShowError(string message)
        {
            Dispatcher.Invoke(() =>
                StatusText.Text = $"⚠ {message}");
        }

        // -----------------------------------------------------------------------
        // Spawn rows
        // -----------------------------------------------------------------------

        private void OnSpawn(SpawnItem item)
        {
            Dispatcher.BeginInvoke(() =>
            {
                if (_paused && item.VenvLauncher == null)
                {
                    _pauseBuffer.Enqueue(item);
                    UpdateStatus();
                    return;
                }

                AddRow(item);
            });
        }

        private void AddRow(SpawnItem item)
        {
            // A venv pair collapses to the interpreter row; the launcher row
            // (added a moment earlier) leaves the grid and lives in the pane.
            if (item.VenvLauncher != null && _rowByPid.TryGetValue(item.VenvLauncher.Pid, out var launcherRow))
            {
                _rows.Remove(launcherRow);
                _rowByPid.Remove(launcherRow.Pid);
            }
            if (item.IsAbsorbedLauncher) return;

            if (_traceReader.HasTraceForPid(item.Pid)) item.HasTrace = true;

            _rowByPid[item.Pid] = item;
            _rows.Insert(0, item);
            while (_rows.Count > RowCap)
            {
                var oldest = _rows[^1];
                _rows.RemoveAt(_rows.Count - 1);
                if (_rowByPid.TryGetValue(oldest.Pid, out var row) && row == oldest) _rowByPid.Remove(oldest.Pid);
            }
            UpdateStatus();
        }

        private void OnNetworkConnect(SpawnNetworkEvent evt)
        {
            // Endpoint-at-connect-time attribution (Sysmon EID 3 → live flow)
            _capture.TagFlow(evt.SourceIp, evt.SourcePort, evt.DestIp, evt.DestPort, evt.Pid, evt.Image);
        }

        private void OnTraceRecord(PyTraceRecord record)
        {
            Dispatcher.BeginInvoke(() =>
            {
                if (_rowByPid.TryGetValue(record.Pid, out var row)) row.HasTrace = true;
                if (_selected != null && record.Pid == _selected.Pid) RenderStackSection(_selected);
            });
        }

        private void OnFlowFinalized(TcpFlowRecord flow)
        {
            Dispatcher.BeginInvoke(() =>
            {
                if (flow.Pid <= 0) return;
                if (!_flowsByPid.TryGetValue(flow.Pid, out var list))
                    _flowsByPid[flow.Pid] = list = new List<TcpFlowRecord>();
                list.Insert(0, flow);
                while (list.Count > 50) list.RemoveAt(list.Count - 1);

                if (_rowByPid.TryGetValue(flow.Pid, out var row)) row.FlowCount = list.Count;
                if (_selected != null && flow.Pid == _selected.Pid) RenderFlowList(_selected);
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
            {
                while (_pauseBuffer.Count > 0)
                    AddRow(_pauseBuffer.Dequeue());
            }
            UpdateStatus();
        }

        private void ClearBtn_Click(object sender, RoutedEventArgs e)
        {
            _rows.Clear();
            _rowByPid.Clear();
            _flowsByPid.Clear();
            _pauseBuffer.Clear();
            _selected = null;
            _selectedFlow = null;
            _decryptResult = null;
            DetailRecordPanel.Children.Clear();
            StackText.Text = string.Empty;
            FlowList.ItemsSource = null;
            PlainText.Text = string.Empty;
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
                FileName = $"python-spawns-{DateTime.Now:yyyyMMdd-HHmmss}.jsonl"
            };
            if (dialog.ShowDialog() != true) return;

            try
            {
                var options = new JsonSerializerOptions { WriteIndented = false };
                using var writer = new StreamWriter(dialog.FileName, append: false);
                foreach (var row in _rows) // newest-first, as displayed
                    writer.WriteLine(JsonSerializer.Serialize(row, options));
                MessageBox.Show($"Exported {_rows.Count} spawn record(s) to:\n{dialog.FileName}",
                    "Export", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Export failed: {ex.Message}", "Export", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void InstrumentBtn_Click(object sender, RoutedEventArgs e)
        {
            // The watcher feeds passive discovery: every python image actually
            // seen spawning becomes an offer in the dialog's list.
            var dialog = new PythonInstrumentDialog(_watcher) { Owner = Window.GetWindow(this) };
            dialog.ShowDialog();
            LoadSettings(); // the keylog flag may have been toggled elsewhere
        }

        private void SpawnGrid_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.OriginalSource is DependencyObject source &&
                ItemsControl.ContainerFromElement(SpawnGrid, source) is DataGridRow row)
                row.IsSelected = true;
        }

        private void CopyRowMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (SpawnGrid.SelectedItem is SpawnItem item)
                Clipboard.SetText(JsonSerializer.Serialize(item, new JsonSerializerOptions { WriteIndented = true }));
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
            catch (ArgumentException)
            {
                // Incomplete pattern mid-typing: keep the last valid filter
            }
            CollectionViewSource.GetDefaultView(_rows).Refresh();
        }

        private bool FilterRow(object obj)
        {
            if (obj is not SpawnItem item) return false;
            if (item.IsAbsorbedLauncher) return false;
            if (_filter == null) return true;
            return _filter.IsMatch($"{item.CommandLine} {item.ParentCommandLine} {item.Image}");
        }

        // -----------------------------------------------------------------------
        // Detail pane
        // -----------------------------------------------------------------------

        private void SpawnGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _selected = SpawnGrid.SelectedItem as SpawnItem;
            RenderDetail(_selected);
        }

        private void RenderDetail(SpawnItem item)
        {
            DetailRecordPanel.Children.Clear();
            if (item == null)
            {
                StackText.Text = string.Empty;
                FlowList.ItemsSource = null;
                PlainText.Text = string.Empty;
                return;
            }

            AddDetail("Time (local)", item.TimeUtc == default ? "—" : item.TimeUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.fff"));
            AddDetail("PID", item.Pid.ToString());
            AddDetail("Image", item.Image);
            AddDetail("Command line", item.CommandLine);
            AddDetail("Parent", $"{item.ParentDisplay}");
            AddDetail("Parent image", item.ParentImage);
            AddDetail("Parent command line", item.ParentCommandLine);
            AddDetail("User", item.User);
            AddDetail("Integrity", item.IntegrityLevel);
            AddDetail("Hashes", item.Hashes);
            AddDetail("Source", item.Source);
            AddDetail("Lifecycle", item.LifeDisplay);
            AddDetail("Flows", item.FlowCount.ToString());

            if (item.VenvLauncher != null)
            {
                AddDetail("venv launcher", $"PID {item.VenvLauncher.Pid}: {item.VenvLauncher.Image}");
                AddDetail("launcher cmdline", item.VenvLauncher.CommandLine);
            }

            RenderStackSection(item);
            RenderFlowList(item);
            _decryptResult = null;
            PlainText.Text = string.Empty;
        }

        private void AddDetail(string label, string value)
        {
            var panel = new StackPanel { Margin = new Thickness(0, 0, 0, 8) };
            var labelBlock = new TextBlock
            {
                Text = label,
                Foreground = FindResource("TextSecondaryBrush") as System.Windows.Media.Brush,
                FontSize = 10
            };
            var valueBlock = new TextBlock
            {
                Text = string.IsNullOrEmpty(value) ? "—" : value,
                TextWrapping = TextWrapping.Wrap,
                FontFamily = new System.Windows.Media.FontFamily("Consolas"),
                FontSize = 11,
                ToolTip = value
            };
            panel.Children.Add(labelBlock);
            panel.Children.Add(valueBlock);
            DetailRecordPanel.Children.Add(panel);
        }

        private void RenderStackSection(SpawnItem item)
        {
            var records = _traceReader.GetForPid(item.Pid);
            if (records.Count == 0)
            {
                StackText.Text = item.Exited
                    ? "No trace records for this pid — the environment is not instrumented, or the process predates the watcher.\nInstrument it via the 🐍 Instrument… button."
                    : "Not instrumented — stacks appear once the environment runs the audit hook (🐍 Instrument… button).";
                return;
            }

            var sb = new StringBuilder();
            foreach (var record in records)
            {
                sb.Append("── ").Append(record.Header).AppendLine(" ──");
                sb.AppendLine(record.Stack);
                sb.AppendLine();
            }
            StackText.Text = sb.ToString().TrimEnd();
        }

        private void RenderFlowList(SpawnItem item)
        {
            FlowList.ItemsSource = _flowsByPid.TryGetValue(item.Pid, out var list)
                ? list.Select(f => f.Display).ToList()
                : null;
        }

        private void FlowList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_flowsByPid.TryGetValue(_selected?.Pid ?? 0, out var list) &&
                FlowList.SelectedIndex >= 0 && FlowList.SelectedIndex < list.Count)
                _selectedFlow = list[FlowList.SelectedIndex];
            else
                _selectedFlow = null;
        }

        // -----------------------------------------------------------------------
        // TLS plaintext
        // -----------------------------------------------------------------------

        private void DecryptBtn_Click(object sender, RoutedEventArgs e)
        {
            FlowList_SelectionChanged(null, null);
            if (_selectedFlow == null)
            {
                MessageBox.Show("Select a flow of this pid first.", "Decrypt",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            _keylog.Refresh();
            _decryptResult = TlsDecryptor.Decrypt(_selectedFlow, _keylog);
            RenderPlainText();
        }

        private void PlainViewCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // SelectedIndex="0" makes WPF select the first item during
            // InitializeComponent — before the PlainText textbox later in the
            // XAML exists. Bail out until the view is fully parsed.
            if (PlainText == null || StackText == null) return;
            RenderPlainText();
        }

        private void RenderPlainText()
        {
            if (_decryptResult == null)
            {
                PlainText.Text = "Pick a flow and press Decrypt.";
                return;
            }

            var result = _decryptResult;
            bool hex = PlainViewCombo.SelectedIndex == 1;

            var sb = new StringBuilder();
            sb.AppendLine(result.HeaderLine);
            if (!string.IsNullOrEmpty(result.HttpSummary)) sb.AppendLine().Append(result.HttpSummary);
            sb.AppendLine().AppendLine($"{result.Status} · app bytes: {result.ClientAppBytes}↑ {result.ServerAppBytes}↓" +
                (result.Truncated ? " · capture truncated" : ""));

            foreach (var record in result.Records)
            {
                sb.Append(record.FromClient ? "→ " : "← ")
                    .Append(record.ContentType)
                    .Append("  (").Append(record.Length).Append(" B)")
                    .AppendLine();

                if (!record.Decrypted)
                {
                    sb.AppendLine($"    [{record.Note}]");
                    continue;
                }
                if (record.ContentType != "application_data") continue;

                sb.AppendLine(hex ? HexDump(record.Data, 2048) : AsText(record.Data, 4096));
            }
            PlainText.Text = sb.ToString();
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
                sb.Append(i.ToString("X4")).Append("  ");
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

        // -----------------------------------------------------------------------
        // Settings persistence
        // -----------------------------------------------------------------------

        private sealed class TabSettings
        {
            public bool KeylogEnabled { get; set; } = true;
            public bool PersistFlows { get; set; } = false;
            public long MaxBytesPerDirection { get; set; } = 8 * 1024 * 1024;
            public int IdleTimeoutSec { get; set; } = 60;
        }

        private void LoadSettings()
        {
            _settingsPath = Path.Combine(PyTraceReaderService.TraceDir, "settings.json");
            TabSettings settings = null;
            try
            {
                if (File.Exists(_settingsPath))
                    settings = JsonSerializer.Deserialize<TabSettings>(File.ReadAllText(_settingsPath));
            }
            catch { /* unreadable settings fall back to defaults */ }
            settings ??= new TabSettings();

            // The flag file is the source of truth for the hook; the checkbox mirrors it
            KeylogCheck.IsChecked = TlsKeylogService.KeylogEnabled;
            PersistFlowsCheck.IsChecked = settings.PersistFlows;
            _capture.PersistFlows = settings.PersistFlows;
            if (settings.MaxBytesPerDirection >= 64 * 1024)
                _capture.MaxBytesPerDirection = settings.MaxBytesPerDirection;
            if (settings.IdleTimeoutSec is >= 5 and <= 3600)
                _capture.IdleTimeout = TimeSpan.FromSeconds(settings.IdleTimeoutSec);
        }

        private void SaveSettings()
        {
            try
            {
                Directory.CreateDirectory(PyTraceReaderService.TraceDir);
                var settings = new TabSettings
                {
                    KeylogEnabled = TlsKeylogService.KeylogEnabled,
                    PersistFlows = PersistFlowsCheck.IsChecked == true,
                    MaxBytesPerDirection = _capture.MaxBytesPerDirection,
                    IdleTimeoutSec = (int)_capture.IdleTimeout.TotalSeconds
                };
                File.WriteAllText(_settingsPath, JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { /* persistence is best-effort */ }
        }

        private void KeylogCheck_Changed(object sender, RoutedEventArgs e)
        {
            if (_keylog == null) return; // event during InitializeComponent
            bool want = KeylogCheck.IsChecked == true;
            try
            {
                if (want) TlsKeylogService.EnableKeylogging();
                else
                {
                    var confirm = MessageBox.Show(
                        "Disable TLS keylogging?\n\nThe key file is wiped and instrumented pythons stop writing TLS\nsecrets — decryption of future traffic becomes impossible (existing\ncaptures stay ciphertext). Re-enable anytime.",
                        "Disable TLS keylogging", MessageBoxButton.YesNo, MessageBoxImage.Question);
                    if (confirm != MessageBoxResult.Yes)
                    {
                        KeylogCheck.IsChecked = true;
                        return;
                    }
                    TlsKeylogService.DisableKeylogging();
                }
                SaveSettings();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "TLS keylogging", MessageBoxButton.OK, MessageBoxImage.Warning);
                KeylogCheck.IsChecked = TlsKeylogService.KeylogEnabled;
            }
        }

        private void PersistFlows_Changed(object sender, RoutedEventArgs e)
        {
            if (_capture == null) return;
            _capture.PersistFlows = PersistFlowsCheck.IsChecked == true;
            SaveSettings();
        }

        // -----------------------------------------------------------------------
        // Status + audit
        // -----------------------------------------------------------------------

        private void UpdateStatus()
        {
            string paused = _paused ? $" · paused ({_pauseBuffer.Count} buffered)" : "";
            string malformed = _traceReader != null && _traceReader.MalformedCount > 0
                ? $" · {_traceReader.MalformedCount} malformed trace line(s)"
                : "";
            StatusText.Text = _watching
                ? $"Watching: {_rows.Count} python spawn(s) · {_capture.LiveFlowCount} live flow(s) · {_keylog.SessionCount} TLS session key(s){paused}{malformed}"
                : "Watcher is stopped.";
        }

    }
}
