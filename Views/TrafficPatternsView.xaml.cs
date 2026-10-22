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
using System.Windows.Threading;
using LookSee.Models;
using LookSee.Services;

namespace LookSee.Views
{
    /// <summary>
    /// Traffic Patterns tab: viewer for the TrafficAggregationService's
    /// (process → destination IP → bytes) rows. The capture is the app-level
    /// TcpStreamCaptureService shared with the Python Spawns tab; this tab
    /// additionally runs an all-process Sysmon EID 3 watcher so every flow —
    /// not just python's — gets pid attribution. Bytes only accumulate while
    /// a capturing tab is open; the aggregation itself persists across
    /// sessions and the 24h pattern ring survives restarts.
    /// </summary>
    public partial class TrafficPatternsView : UserControl
    {
        private readonly ObservableCollection<TrafficStat> _rows = new();
        private readonly Dictionary<string, TrafficStat> _rowByKey = new(StringComparer.Ordinal);

        private DnsResolutionService _dnsService;
        private SysmonConnectWatcherService _connectWatcher;
        private DispatcherTimer _liveTimer;
        private Regex _filter;
        private bool _initialized;
        private bool _captureRunning;

        public TrafficPatternsView()
        {
            InitializeComponent();
            PatternsGrid.ItemsSource = _rows;

            var view = (ListCollectionView)CollectionViewSource.GetDefaultView(_rows);
            view.SortDescriptions.Add(new System.ComponentModel.SortDescription(
                nameof(TrafficStat.WindowTotal), System.ComponentModel.ListSortDirection.Descending));
            view.GroupDescriptions.Add(new PropertyGroupDescription(nameof(TrafficStat.ProcessName)));
            view.Filter = FilterRow;

            // Live shaping instead of a periodic Refresh(): Refresh() regenerates
            // every group each tick and reset the group Expanders, collapsing
            // whatever the user had open within seconds. PropertyChanged on these
            // members now drives the resort/refilter incrementally.
            view.IsLiveSorting = true;
            view.LiveSortingProperties.Add(nameof(TrafficStat.WindowTotal));
            view.IsLiveFiltering = true;
            view.LiveFilteringProperties.Add(nameof(TrafficStat.WindowTotal));
            view.LiveFilteringProperties.Add(nameof(TrafficStat.Hostname));
        }

        // -----------------------------------------------------------------------
        // Lifecycle: lazy start on tab selection, stop on tab leave
        // -----------------------------------------------------------------------

        private void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            if (!_initialized)
            {
                _initialized = true;

                _dnsService = new DnsResolutionService();
                _dnsService.Start();

                _connectWatcher = new SysmonConnectWatcherService();
                _connectWatcher.OnError += msg => Dispatcher.Invoke(() => StatusText.Text = $"⚠ {msg}");
                _connectWatcher.OnConnect += OnConnect;

                _liveTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
                _liveTimer.Tick += (s, _) => RefreshGrid();
            }

            _connectWatcher.Start();
            TcpStreamCaptureService.Shared.AddRef();
            _captureRunning = true;

            // DnsResolutionService.Start is one-shot (single reader channel);
            // it was started in the init block above.
            if (LiveCheck.IsChecked == true) _liveTimer.Start();
            RefreshGrid();
        }

        private void UserControl_Unloaded(object sender, RoutedEventArgs e)
        {
            _liveTimer?.Stop();
            _connectWatcher?.Stop();
            if (_captureRunning)
            {
                TcpStreamCaptureService.Shared.Release();
                _captureRunning = false;
            }
        }

        /// <summary>Sysmon EID 3 → live-flow attribution (first writer wins).</summary>
        private void OnConnect(SysmonConnectEvent evt)
        {
            if (!evt.IsTcp) return; // the capture is TCP-only
            TcpStreamCaptureService.Shared.TagFlow(
                evt.SourceIp, evt.SourcePort, evt.DestIp, evt.DestPort, evt.Pid, evt.Image);
        }

        // -----------------------------------------------------------------------
        // Refresh
        // -----------------------------------------------------------------------

        private void RefreshBtn_Click(object sender, RoutedEventArgs e) => RefreshGrid();

        private void LiveChanged(object sender, RoutedEventArgs e)
        {
            if (_liveTimer == null) return;
            if (LiveCheck.IsChecked == true) _liveTimer.Start();
            else _liveTimer.Stop();
        }

        private DateTime? WindowStart => WindowCombo?.SelectedIndex switch
        {
            0 => DateTime.UtcNow.AddMinutes(-5),
            1 => DateTime.UtcNow.AddHours(-1),
            2 => DateTime.UtcNow.AddHours(-24),
            _ => null   // all time
        };

        private void RefreshGrid()
        {
            var snapshot = TrafficAggregationService.Shared.Snapshot();

            // Sync the row set (stats are stable objects, so rows keep identity)
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var stat in snapshot)
            {
                seen.Add(stat.Key);
                if (!_rowByKey.ContainsKey(stat.Key))
                {
                    _rowByKey[stat.Key] = stat;
                    _rows.Add(stat);

                    stat.Hostname = _dnsService.GetCachedHostname(stat.DestIp) ?? stat.DestIp;
                    _dnsService.EnqueueForResolution(stat);
                }
            }
            foreach (var gone in _rowByKey.Keys.Where(k => !seen.Contains(k)).ToList())
            {
                _rows.Remove(_rowByKey[gone]);
                _rowByKey.Remove(gone);
            }

            // Recompute displays for the selected window; row cells, ordering
            // and filter membership update via INPC + live shaping — never via
            // view.Refresh(), which would reset the group Expanders.
            DateTime? windowStart = WindowStart;
            foreach (var stat in _rows)
                stat.SetWindow(windowStart);

            bool allTime = windowStart == null;
            int shown = _rows.Count(r => FilterRow(r));
            string windowLabel = allTime
                ? "all time"
                : "since " + windowStart.Value.ToLocalTime().ToString("HH:mm");
            StatusText.Text =
                $"{_rowByKey.Count} process/destination pair(s) · {shown} shown · " +
                $"{TrafficAggregationService.Shared.FlowsAggregated:N0} flows aggregated · " +
                $"{TcpStreamCaptureService.Shared.LiveFlowCount} live flow(s) · " +
                $"window: {windowLabel} · " +
                $"capturing while this tab is open (shared with Python Spawns)";
        }

        // -----------------------------------------------------------------------
        // Group expanders
        // -----------------------------------------------------------------------

        /// <summary>
        /// Records the user's per-group expansion so the grid can restore it
        /// whenever the group's Expander container is (re)created or its row
        /// count changes — without this, ItemCount-driven binding re-evaluation
        /// would snap groups back to their default state.
        /// </summary>
        private void GroupExpander_StateChanged(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.Expander expander &&
                expander.DataContext is System.Windows.Data.CollectionViewGroup group &&
                group.Name is string name)
            {
                if (expander.IsExpanded)
                    Converters.GroupExpandedStateConverter.CollapsedGroups.Remove(name);
                else
                    Converters.GroupExpandedStateConverter.CollapsedGroups.Add(name);
            }
        }

        // -----------------------------------------------------------------------
        // Filter + window
        // -----------------------------------------------------------------------

        private void WindowChanged(object sender, SelectionChangedEventArgs e)
        {
            if (PatternsGrid == null) return; // event during InitializeComponent
            RefreshGrid();
        }

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
            if (_rows.Count > 0)
                CollectionViewSource.GetDefaultView(_rows).Refresh();
        }

        private bool FilterRow(object obj)
        {
            if (obj is not TrafficStat stat) return false;
            // Windowed views only make sense for rows with activity in-window
            if (!stat.WindowIsAllTime && stat.WindowTotal <= 0) return false;
            if (_filter == null) return true;
            return _filter.IsMatch($"{stat.ProcessName} {stat.DestIp} {stat.Hostname}");
        }

        // -----------------------------------------------------------------------
        // Actions
        // -----------------------------------------------------------------------

        private void CopyRowMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (PatternsGrid.SelectedItem is TrafficStat stat)
                Clipboard.SetText(JsonSerializer.Serialize(new
                {
                    process = stat.ProcessName,
                    destination = stat.DestIp,
                    hostname = stat.Hostname,
                    ports = stat.Ports.ToArray(),
                    window_tx = stat.WindowTx,
                    window_rx = stat.WindowRx,
                    lifetime_tx_bytes = stat.TxBytes,
                    lifetime_rx_bytes = stat.RxBytes,
                    lifetime_flows = stat.Flows,
                    first_seen_utc = stat.FirstSeenUtc,
                    last_seen_utc = stat.LastSeenUtc,
                    pattern_24h = stat.PatternDisplay,
                    hint = stat.PatternHint
                }, new JsonSerializerOptions { WriteIndented = true }));
        }

        private void ClearBtn_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show(
                    "Clear ALL aggregated traffic history?\n\nThis removes every process/destination row and the\n" +
                    "persisted patterns file. It does not touch firewall rules.",
                    "Clear History", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

            TrafficAggregationService.Shared.Reset();
            _rows.Clear();
            _rowByKey.Clear();
            RefreshGrid();
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
                Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
                FileName = $"traffic-patterns-{DateTime.Now:yyyyMMdd-HHmmss}.csv"
            };
            if (dialog.ShowDialog() != true) return;

            try
            {
                var sb = new StringBuilder();
                sb.AppendLine("process,destination_ip,hostname,ports,tx_bytes,rx_bytes,flows,first_seen_utc,last_seen_utc,pids,avg_tx_rate_window,pattern_24h,hint");
                foreach (var stat in _rows.OrderByDescending(r => r.TxBytes + r.RxBytes))
                {
                    sb.AppendLine(string.Join(",",
                        Csv(stat.ProcessName), Csv(stat.DestIp), Csv(stat.Hostname),
                        Csv(string.Join(";", stat.Ports)),
                        stat.TxBytes, stat.RxBytes, stat.Flows,
                        stat.FirstSeenUtc == default ? "" : stat.FirstSeenUtc.ToString("yyyy-MM-dd HH:mm:ss"),
                        stat.LastSeenUtc == default ? "" : stat.LastSeenUtc.ToString("yyyy-MM-dd HH:mm:ss"),
                        Csv(string.Join(";", stat.Pids)),
                        Csv(stat.RateDisplay), Csv(stat.PatternDisplay), Csv(stat.PatternHint)));
                }
                File.WriteAllText(dialog.FileName, sb.ToString(), new UTF8Encoding(true));
                MessageBox.Show($"Exported {_rows.Count} row(s) to:\n{dialog.FileName}",
                    "Export", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Export failed: {ex.Message}", "Export", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static string Csv(string value) =>
            $"\"{(value ?? "").Replace("\"", "\"\"")}\"";

        // -----------------------------------------------------------------------
        // Audit
        // -----------------------------------------------------------------------

    }
}
