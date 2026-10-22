using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Input;
using LookSee.Services;

namespace LookSee.Views
{
    /// <summary>
    /// Editor for the two ignore lists:
    ///   · process names (ignored_processes.txt next to the exe) — enforced
    ///     by every raw feed and the Phone Bill aggregation;
    ///   · image paths (ignored-apps.json) — Who's Talking toasts and
    ///     suggestions only; rows stay visible.
    /// LookSee.exe itself is always on the process list and not shown.
    /// </summary>
    public partial class IgnoredProcessesWindow : Window
    {
        public IgnoredProcessesWindow()
        {
            InitializeComponent();
            Refresh();
        }

        private void Refresh()
        {
            ProcessList.ItemsSource = SysmonWatcherService.IgnoreFileSnapshot()
                .Where(n => !n.Equals("LookSee.exe", StringComparison.OrdinalIgnoreCase))
                .ToList();
            AppList.ItemsSource = TransmissionsIgnoreList.All().OrderBy(a => a, StringComparer.OrdinalIgnoreCase).ToList();
            RemoveProcBtn.IsEnabled = ProcessList.SelectedItem != null;
            UnignoreAppBtn.IsEnabled = AppList.SelectedItem != null;
        }

        private void ProcessList_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            RemoveProcBtn.IsEnabled = ProcessList.SelectedItem != null;
        }

        private void RemoveProcBtn_Click(object sender, RoutedEventArgs e)
        {
            if (ProcessList.SelectedItem is string name)
            {
                SysmonWatcherService.RemoveFromIgnoreFile(name);
                Refresh();
            }
        }

        private void AddProcBtn_Click(object sender, RoutedEventArgs e) => AddFromBox();

        private void NewProcBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) AddFromBox();
        }

        private void AddFromBox()
        {
            string name = (NewProcBox.Text ?? "").Trim().Trim('"');
            if (name.Length == 0) return;
            // Accept a dropped full path as a courtesy — store the name.
            if (name.Contains('\\') || name.Contains('/')) name = Path.GetFileName(name);
            SysmonWatcherService.AddToIgnoreFile(name);
            NewProcBox.Clear();
            Refresh();
        }

        private void UnignoreAppBtn_Click(object sender, RoutedEventArgs e)
        {
            if (AppList.SelectedItem is string image)
            {
                TransmissionsIgnoreList.Unignore(image);
                Refresh();
            }
        }

        private void ResetConfirmsBtn_Click(object sender, RoutedEventArgs e)
        {
            ConfirmPrefs.ResetAll();
            MessageBox.Show(
                "Every block confirmation prompt is active again.\n\n" +
                "The routine IP/process confirms, the Microsoft-infrastructure warning and the\n" +
                "Windows service-host warning each ask again before their block applies.",
                "Warnings re-armed", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}
