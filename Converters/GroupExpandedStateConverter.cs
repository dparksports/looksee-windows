using System;
using System.Collections.Generic;
using System.Globalization;
using System.Windows.Data;

namespace LookSee.Converters
{
    /// <summary>
    /// Group expander state for the Phone Bill grid: every group starts
    /// expanded and the user's collapse choice is remembered per group name,
    /// so the OneWay binding re-evaluating on container recreation or group
    /// ItemCount changes never overrides what the user chose. Pair with
    /// Expanded/Collapsed handlers that update CollapsedGroups.
    /// </summary>
    public class GroupExpandedStateConverter : IValueConverter
    {
        /// <summary>Group names the user collapsed (groups start expanded).</summary>
        public static readonly HashSet<string> CollapsedGroups = new(StringComparer.Ordinal);

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return !(value is System.Windows.Data.CollectionViewGroup group &&
                     group.Name is string name &&
                     CollapsedGroups.Contains(name));
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }
}
