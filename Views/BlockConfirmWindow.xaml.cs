using System.Windows;

namespace LookSee.Views
{
    /// <summary>
    /// Confirmation for firewall blocks from Who's Talking — the exact
    /// AutoCommand Process Monitor dialog. MessageBox cannot host a
    /// checkbox, so this window carries the class-specific warning plus the
    /// "don't ask again" check-off (a ConfirmPrefs key). Frequent blockers
    /// use the checkbox to stop the prompt interrupting every block; the
    /// choice is per warning class — silencing the routine IP confirm never
    /// silences the svchost warning — and reversible from the Ignore
    /// lists… window's reset button.
    /// </summary>
    public partial class BlockConfirmWindow : Window
    {
        public bool Confirmed { get; private set; }
        public bool Suppress => SuppressCheck.IsChecked == true;

        /// <summary>ConfirmPrefs key the checkbox silences (null → no checkbox shown).</summary>
        public string SuppressKey { get; }

        public BlockConfirmWindow(string headline, string warning, string detail,
                                  string suppressKey, string suppressLabel)
        {
            InitializeComponent();
            HeadText.Text = headline;
            WarningText.Text = warning;
            WarningBorder.Visibility = string.IsNullOrEmpty(warning) ? Visibility.Collapsed : Visibility.Visible;
            DetailText.Text = detail;
            SuppressKey = suppressKey;
            if (string.IsNullOrEmpty(suppressLabel))
            {
                SuppressCheck.Visibility = Visibility.Collapsed;
            }
            else
            {
                SuppressCheck.Content = suppressLabel;
            }
        }

        private void BlockBtn_Click(object sender, RoutedEventArgs e)
        {
            Confirmed = true;
            DialogResult = true;
        }
    }
}
