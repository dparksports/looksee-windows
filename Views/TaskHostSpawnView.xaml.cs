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
using System.Windows.Threading;
using LookSee.Models;
using LookSee.Services;

namespace LookSee.Views
{
    /// <summary>
    /// Taskhostw Spawns feed (the "Scheduled Tasks" segment of the Spawns
    /// tab): the same Sysmon spawn tracing the Python feed uses
    /// (ImageSpawnWatcherService with the taskhostw filter), answering
    /// who/what/when — with the "why" being the scheduled task. There is no
    /// instrumentation story here (no audit hook, no TLS): taskhostw is a
    /// Windows binary, so the attribution pane joins TaskAttributionService
    /// data to each row instead.
    /// </summary>
    public partial class TaskHostSpawnView : UserControl
    {
        private const int RowCap = 3000;

        private readonly ObservableCollection<SpawnItem> _rows = new();
        private readonly Dictionary<int, SpawnItem> _rowByPid = new();

        private ImageSpawnWatcherService _watcher;
        private TaskAttributionService _taskAttribution;

        private bool _initialized;
        private bool _watching;
        private bool _paused;
        private readonly Queue<SpawnItem> _pauseBuffer = new();
        private Regex _filter;
        private SpawnItem _selected;
        private DispatcherTimer _attributionTimer;
        private bool _backfilled;

        // "$(Arg0)"-style Task Scheduler placeholders, seen unexpanded when a
        // trigger-fired start carries no argument — the tab explains them
        // instead of leaving them to look like an error.
        private static readonly Regex PlaceholderArgRegex =
            new Regex(@"\$\(Arg\d+\)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public TaskHostSpawnView()
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
        // Coverage runs until the user presses Stop Watch (or the app exits)
        // — same lifetime policy as the svchost trace feed.
        // -----------------------------------------------------------------------

        private void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            if (!_initialized)
            {
                _initialized = true;
                _watcher = new ImageSpawnWatcherService(ImageSpawnWatcherService.IsTaskhostwImage, "taskhostw");
                _watcher.OnError += ShowError;
                _watcher.OnSpawn += OnSpawn;

                _taskAttribution = new TaskAttributionService();
                _taskAttribution.OnError += _ => { }; // attribution gaps are non-fatal
                _taskAttribution.OnAttributionUpdated += TaskAttribution_Updated;

                // Task attribution lags the spawn event by seconds (separate
                // event log); re-poll rows still missing their task name.
                _attributionTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(10) };
                _attributionTimer.Tick += (s, _) => EnrichUnattributed();
            }
            if (!_watching) StartWatching();
        }

        private void UserControl_Unloaded(object sender, RoutedEventArgs e)
        {
            // Deliberately keeps watching. The watcher and the attribution
            // timer are event/Dispatcher-driven and safe to run while the
            // view is out of the tree; Stop Watching remains the only stop.
        }

        /// <summary>Live state for the Spawns host's feed indicator.</summary>
        public bool IsWatching => _watching;

        private void StartWatching()
        {
            _watcher.Start();
            _taskAttribution.Start();
            _attributionTimer.Start();
            _watching = true;
            ToggleWatchBtn.Content = "Stop Watch";
            BackfillHistory();
            UpdateStatus();
        }

        private void StopWatching()
        {
            _watcher.Stop();
            _taskAttribution.Stop();
            _attributionTimer.Stop();
            _watching = false;
            ToggleWatchBtn.Content = "Start Watch";
            UpdateStatus();
        }

        private void ToggleWatchBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_watching) StopWatching();
            else StartWatching();
        }

        private void ShowError(string message) => StatusText.Text = $"⚠ {message}";

        // -----------------------------------------------------------------------
        // Rows + task attribution
        // -----------------------------------------------------------------------

        private void OnSpawn(SpawnItem item)
        {
            Dispatcher.BeginInvoke(() =>
            {
                if (_paused)
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
            _rowByPid[item.Pid] = item;
            _rows.Insert(0, item);
            while (_rows.Count > RowCap)
            {
                var oldest = _rows[^1];
                _rows.RemoveAt(_rows.Count - 1);
                if (_rowByPid.TryGetValue(oldest.Pid, out var row) && row == oldest) _rowByPid.Remove(oldest.Pid);
            }
            TryEnrichRow(item);
            UpdateStatus();
        }

        /// <summary>
        /// Replay the last few hours of both logs once, so the tab shows the
        /// spawns that happened before it was opened — rows arrive with their
        /// attribution already stitched on wherever the logs still retain it.
        /// </summary>
        private void BackfillHistory()
        {
            if (_backfilled) return;
            _backfilled = true;
            System.Threading.Tasks.Task.Run(() =>
            {
                var history = _taskAttribution.Backfill(TimeSpan.FromHours(6));
                Dispatcher.BeginInvoke(() =>
                {
                    if (_paused)
                    {
                        foreach (var item in history) _pauseBuffer.Enqueue(item);
                        return;
                    }
                    foreach (var item in history)
                    {
                        if (_rowByPid.ContainsKey(item.Pid)) continue; // already arrived live
                        AddRow(item);
                    }
                    UpdateStatus();
                });
            });
        }

        /// <summary>Live attribution facts landing on a row we already show (watcher thread → UI).</summary>
        private void TaskAttribution_Updated(TaskLaunchInfo info)
        {
            Dispatcher.BeginInvoke(() =>
            {
                if (info != null && _rowByPid.TryGetValue(info.ProcessId, out var row))
                    TryEnrichRow(row);
            });
        }

        /// <summary>
        /// Pulls the latest attribution into the row — task badge, verdict
        /// chip, outcome — and refreshes the pane when the row is selected.
        /// </summary>
        private void TryEnrichRow(SpawnItem item)
        {
            var info = _taskAttribution.GetTaskFor(item);
            if (info == null) return;

            if (string.IsNullOrEmpty(item.Badge) && !string.IsNullOrEmpty(info.TaskPath))
                item.SetDetailBadge(ShortTaskName(info.TaskPath));
            if (!string.IsNullOrEmpty(info.Verdict) && item.Verdict != info.Verdict)
                item.SetVerdict(info.Verdict);

            string outcome = BuildOutcome(info);
            if (outcome != null && item.OutcomeDisplay != outcome)
                item.SetOutcome(outcome);

            if (_selected != null && _selected.Pid == item.Pid) RenderTaskPane(item);
        }

        private void EnrichUnattributed()
        {
            foreach (var item in _rows.Take(300))
                TryEnrichRow(item);
        }

        /// <summary>"rc 0 · 0.4 s"-style outcome; null until the scheduler reported a result.</summary>
        private static string BuildOutcome(TaskLaunchInfo info)
        {
            if (info?.ReturnCode == null) return null;
            string prefix = info.CompletedSuccessfully == false ? "failed rc " : "rc ";
            return info.DurationSeconds is double secs
                ? $"{prefix}{info.ReturnCode} · {secs:0.##} s"
                : $"{prefix}{info.ReturnCode}";
        }

        private static string ShortTaskName(string taskPath)
        {
            // "\Microsoft\Windows\Maintenance\WinSAT" → "WinSAT"
            string trimmed = taskPath.TrimStart('\\');
            int slash = trimmed.LastIndexOf('\\');
            return slash >= 0 ? trimmed[(slash + 1)..] : trimmed;
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
            _rowByPid.Clear();
            _pauseBuffer.Clear();
            _selected = null;
            DetailRecordPanel.Children.Clear();
            ResetTaskPane();
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
                FileName = $"taskhostw-spawns-{DateTime.Now:yyyyMMdd-HHmmss}.jsonl"
            };
            if (dialog.ShowDialog() != true) return;

            try
            {
                var options = new JsonSerializerOptions { WriteIndented = false };
                using var writer = new StreamWriter(dialog.FileName, append: false);
                foreach (var row in _rows)
                {
                    // Each record merges the row with its attribution — the
                    // investigation travels with the export, not just the grid.
                    var info = _taskAttribution.GetTaskFor(row);
                    var record = new
                    {
                        row.TimeUtc,
                        row.Pid,
                        row.Image,
                        row.CommandLine,
                        row.ParentPid,
                        row.ParentImage,
                        row.ParentCommandLine,
                        row.User,
                        row.IntegrityLevel,
                        row.Hashes,
                        row.Source,
                        Task = info?.TaskPath,
                        TaskVerdict = info?.Verdict,
                        TriggerReason = info?.TriggerReason,
                        ActionName = info?.ActionName,
                        ReturnCode = info?.ReturnCode,
                        StartedAt = info?.StartedAt,
                        CompletedAt = info?.CompletedAt,
                        HandlerClassId = info?.HandlerClassId,
                        HandlerDll = info?.HandlerDll,
                        HandlerDllCompany = info?.HandlerDllCompany,
                        KnownTask = KnownTaskCatalog.Lookup(info?.TaskPath)?.Title
                    };
                    writer.WriteLine(JsonSerializer.Serialize(record, options));
                }
                MessageBox.Show($"Exported {_rows.Count} spawn record(s) to:\n{dialog.FileName}",
                    "Export", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Export failed: {ex.Message}", "Export", MessageBoxButton.OK, MessageBoxImage.Error);
            }
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

        /// <summary>
        /// The whole investigation for one spawn as markdown on the clipboard:
        /// the Sysmon record, the scheduler's attribution (task, trigger,
        /// user), the handler-DLL resolution, the outcome, and the known-task
        /// explanation — the same evidence chain the pane shows, in a form
        /// suitable for an issue, a note, or the AI tab.
        /// </summary>
        private void InvestigateMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (SpawnGrid.SelectedItem is not SpawnItem item) return;

            var info = _taskAttribution.GetTaskFor(item);
            var known = KnownTaskCatalog.Lookup(info?.TaskPath);
            var sb = new StringBuilder();
            sb.AppendLine($"# taskhostw investigation — PID {item.Pid}");
            sb.AppendLine($"When (local): {(item.TimeUtc == default ? "—" : item.TimeUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.fff"))}");
            sb.AppendLine($"Command line: {item.CommandLine}");
            if (PlaceholderArgRegex.IsMatch(item.CommandLine ?? string.Empty))
                sb.AppendLine("Argument note: $(ArgN) is a Task Scheduler placeholder; unexpanded means the task was trigger-fired with no argument (normal).");
            sb.AppendLine($"Parent: {item.ParentDisplay}");
            sb.AppendLine($"Parent command line: {item.ParentCommandLine}");
            sb.AppendLine($"User: {item.User} · Integrity: {item.IntegrityLevel}");
            sb.AppendLine($"Hashes: {item.Hashes}");
            sb.AppendLine($"Lifecycle: {item.LifeDisplay}");
            sb.AppendLine();
            sb.AppendLine($"Task: {info?.TaskPath ?? "(unresolved)"}");
            sb.AppendLine($"Verdict: {info?.Verdict ?? "Unresolved"}");
            sb.AppendLine($"Triggered by: {info?.TriggerReason ?? "—"}");
            sb.AppendLine($"Runs as: {info?.UserContext ?? "—"}");
            if (!string.IsNullOrEmpty(info?.ActionName)) sb.AppendLine($"Action: {info.ActionName}");
            if (!string.IsNullOrEmpty(info?.HandlerClassId)) sb.AppendLine($"COM handler: {info.HandlerClassId}");
            if (!string.IsNullOrEmpty(info?.HandlerDll))
            {
                string dllDetail = info.HandlerDllExists == true ? "exists" : "MISSING";
                if (!string.IsNullOrEmpty(info.HandlerDllVersion)) dllDetail += $"; {info.HandlerDllVersion}";
                if (!string.IsNullOrEmpty(info.HandlerDllCompany)) dllDetail += $"; {info.HandlerDllCompany}";
                sb.AppendLine($"Handler DLL: {info.HandlerDll} ({dllDetail})");
            }
            sb.AppendLine($"Outcome: {BuildOutcome(info) ?? (item.Exited ? "exited (no completion event)" : "running")}");
            if (known != null)
            {
                sb.AppendLine();
                sb.AppendLine($"What it does: {known.Title}");
                sb.AppendLine(known.Explanation);
                if (!string.IsNullOrEmpty(known.Note)) sb.AppendLine($"Note: {known.Note}");
            }
            sb.AppendLine();
            sb.AppendLine($"Collected {DateTime.Now:yyyy-MM-dd HH:mm:ss} by LookSee · Taskhostw Spawns");

            Clipboard.SetText(sb.ToString());
            StatusText.Text = $"📋 Investigation for PID {item.Pid} copied to the clipboard";
        }

        private void TracePidMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (SpawnGrid.SelectedItem is not SpawnItem item || item.Pid <= 0) return;
            var win = new ProcessTraceWindow(item.Pid, "taskhostw", item.Image,
                _taskAttribution.GetTaskFor(item),
                item.TimeUtc, item.TimeUtc)
            {
                Owner = Window.GetWindow(this)
            };
            win.Show();
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
            if (_filter == null) return true;
            return _filter.IsMatch($"{item.Badge} {item.CommandLine} {item.ParentCommandLine} {item.Image}");
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
                ResetTaskPane();
                return;
            }

            AddDetail("Time (local)", item.TimeUtc == default ? "—" : item.TimeUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.fff"));
            AddDetail("PID", item.Pid.ToString());
            AddDetail("Image", item.Image);
            AddDetail("Command line", item.CommandLine);
            if (PlaceholderArgRegex.IsMatch(item.CommandLine ?? string.Empty))
                AddDetail("Argument note",
                    "$(ArgN) is a Task Scheduler argument placeholder. Unexpanded — as here — it means the task was " +
                    "started by its trigger with no argument; normal, not an error or injection.");
            AddDetail("Parent", item.ParentDisplay);
            AddDetail("Parent command line", item.ParentCommandLine);
            AddDetail("User", item.User);
            AddDetail("Integrity", item.IntegrityLevel);
            AddDetail("Hashes", item.Hashes);
            AddDetail("Lifecycle", item.LifeDisplay);

            RenderTaskPane(item);
            _ = LoadTaskSummaryAsync(item);
        }

        private void AddDetail(string label, string value)
        {
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
            var panel = new StackPanel { Margin = new Thickness(0, 0, 0, 8) };
            panel.Children.Add(labelBlock);
            panel.Children.Add(valueBlock);
            DetailRecordPanel.Children.Add(panel);
        }

        private void RenderTaskPane(SpawnItem item)
        {
            var info = _taskAttribution.GetTaskFor(item);
            TaskPathText.Text = info?.TaskPath is string path && path.Length > 0 ? path : "—";
            TaskUserText.Text = !string.IsNullOrEmpty(info?.UserContext) ? info.UserContext : "—";
            TaskTriggerText.Text = !string.IsNullOrEmpty(info?.TriggerReason) ? info.TriggerReason : "—";

            string outcome = BuildOutcome(info);
            TaskOutcomeText.Text = outcome ?? (item != null && item.Exited ? "exited (no completion event)" : "—");

            if (!string.IsNullOrEmpty(info?.Verdict))
            {
                TaskVerdictText.Text = info.Verdict;
                TaskVerdictText.Foreground = info.Verdict switch
                {
                    "Inbox" => System.Windows.Media.Brushes.MediumSeaGreen,
                    "Orphaned" => System.Windows.Media.Brushes.IndianRed,
                    "Third-party" => System.Windows.Media.Brushes.Khaki,
                    _ => FindResource("TextPrimaryBrush") as System.Windows.Media.Brush
                };
            }
            else
            {
                TaskVerdictText.Text = "—";
                TaskVerdictText.Foreground = FindResource("TextSecondaryBrush") as System.Windows.Media.Brush;
            }

            if (info?.HandlerClassId != null)
            {
                string dllDetail = info.HandlerDllExists == true && !string.IsNullOrEmpty(info.HandlerDllVersion)
                    ? $" ({info.HandlerDllVersion})"
                    : string.Empty;
                TaskHandlerText.Text = info.HandlerDllExists == true
                    ? $"{info.HandlerDll}{dllDetail}  (CLSID {info.HandlerClassId})"
                    : $"CLSID {info.HandlerClassId} — handler DLL not registered (leftover of uninstalled software)";
            }
            else
            {
                TaskHandlerText.Text = "—";
            }

            var known = KnownTaskCatalog.Lookup(info?.TaskPath);
            if (known != null)
            {
                string text = $"{known.Title}\n{known.Explanation}";
                if (!string.IsNullOrEmpty(known.Note)) text += $"\n\nNote: {known.Note}";
                KnownTaskText.Text = text;
                KnownTaskText.Visibility = Visibility.Visible;
            }
            else
            {
                KnownTaskText.Text = string.Empty;
                KnownTaskText.Visibility = Visibility.Collapsed;
            }

            if (string.IsNullOrEmpty(info?.TaskPath))
                TaskSummaryText.Text = "No task attribution yet — the event logs are still catching up.";
        }

        private async System.Threading.Tasks.Task LoadTaskSummaryAsync(SpawnItem item)
        {
            var info = _taskAttribution.GetTaskFor(item);
            if (info == null || string.IsNullOrEmpty(info.TaskPath)) return;

            var (summary, error) = await TaskSchedulerService.Instance.GetTaskSummaryAsync(info.TaskPath);
            if (_selected != item) return; // selection moved on

            TaskSummaryText.Text = string.IsNullOrEmpty(error)
                ? summary ?? "(no task details)"
                : $"Could not read task '{info.TaskPath}': {error}";
        }

        private void ResetTaskPane()
        {
            TaskPathText.Text = "—";
            TaskUserText.Text = "—";
            TaskTriggerText.Text = "—";
            TaskOutcomeText.Text = "—";
            TaskVerdictText.Text = "—";
            TaskVerdictText.Foreground = FindResource("TextSecondaryBrush") as System.Windows.Media.Brush;
            TaskHandlerText.Text = "—";
            KnownTaskText.Text = string.Empty;
            KnownTaskText.Visibility = Visibility.Collapsed;
            TaskSummaryText.Text = "Select a spawn row — task details appear here as the event logs catch up.";
        }

        // -----------------------------------------------------------------------
        // Status + audit
        // -----------------------------------------------------------------------

        private void UpdateStatus()
        {
            string paused = _paused ? $" · paused ({_pauseBuffer.Count} buffered)" : "";
            int attributed = 0;
            foreach (var row in _rows)
                if (!string.IsNullOrEmpty(row.Badge)) attributed++;
            StatusText.Text = _watching
                ? $"Watching: {_rows.Count} taskhostw spawn(s) · {attributed} attributed to a task{paused}"
                : "Watcher is stopped.";
        }

    }
}
