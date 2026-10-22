using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace LookSee.Views
{
    /// <summary>
    /// Spawns tab — one home for the three Sysmon spawn feeds (taskhostw,
    /// Python, svchost timeline). The feeds are separate UserControls kept
    /// permanently in the visual tree and switched by visibility, so:
    ///   · switching feeds never fires Unloaded — a running watcher is not
    ///     interrupted by browsing between them;
    ///   · leaving the Spawns tab pauses only this strip's indicator timer;
    ///     the feeds' own lifetime policy (keep recording until the user
    ///     stops them) is enforced inside each view.
    /// The dot on each segment reflects that feed's live state.
    /// </summary>
    public partial class SpawnsView : UserControl
    {
        private static readonly SolidColorBrush RunningBrush = new(Color.FromRgb(0x4E, 0xC9, 0x6F));
        private static readonly SolidColorBrush StoppedBrush = new(Color.FromRgb(0x6B, 0x72, 0x80));

        private readonly DispatcherTimer _stateTimer = new() { Interval = TimeSpan.FromSeconds(2) };

        public SpawnsView()
        {
            InitializeComponent();
            _stateTimer.Tick += (_, _) => UpdateDots();
        }

        private void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            UpdateDots();
            _stateTimer.Start();
        }

        private void UserControl_Unloaded(object sender, RoutedEventArgs e) => _stateTimer.Stop();

        private void Feed_Checked(object sender, RoutedEventArgs e)
        {
            // The first Checked fires during InitializeComponent, before the
            // feed views exist — the initial visibility set in XAML covers it.
            if (TaskhostFeed == null || PythonFeed == null || TraceFeed == null) return;

            TaskhostFeed.Visibility = ReferenceEquals(sender, TaskhostFeedRadio) ? Visibility.Visible : Visibility.Collapsed;
            PythonFeed.Visibility   = ReferenceEquals(sender, PythonFeedRadio)   ? Visibility.Visible : Visibility.Collapsed;
            TraceFeed.Visibility    = ReferenceEquals(sender, TraceFeedRadio)    ? Visibility.Visible : Visibility.Collapsed;
        }

        private void UpdateDots()
        {
            TaskhostDot.Fill = TaskhostFeed.IsWatching ? RunningBrush : StoppedBrush;
            PythonDot.Fill   = PythonFeed.IsWatching   ? RunningBrush : StoppedBrush;
            TraceDot.Fill    = TraceFeed.IsTracing     ? RunningBrush : StoppedBrush;
        }
    }
}
