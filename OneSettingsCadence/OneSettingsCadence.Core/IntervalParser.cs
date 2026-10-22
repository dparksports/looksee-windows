using System.Globalization;
using System.Xml;

namespace LookSee.OneSettingsCadence
{
    /// <summary>
    /// Parses the interval argument for "set"/"preview". Three accepted forms:
    /// plain hours ("24", "0.5", optional trailing "h"), clock form
    /// ("06:00:00", "6:00" = HH:MM:SS or HH:MM), and ISO 8601 duration
    /// ("PT24H", "P1DT12H", "PT30M"). Formatting back to Task Scheduler form
    /// always goes through XmlConvert so the XML gets the canonical PTxxH
    /// serialization the scheduler itself writes.
    /// </summary>
    public static class IntervalParser
    {
        public static bool TryParse(string text, out TimeSpan value, out string error)
        {
            value = TimeSpan.Zero;
            error = null;
            if (string.IsNullOrWhiteSpace(text))
            {
                error = "interval is empty";
                return false;
            }

            string s = text.Trim();

            // ISO 8601 duration (XmlConvert also accepts the bare "P1D" day form)
            if (s.StartsWith("P", StringComparison.OrdinalIgnoreCase))
            {
                try { value = XmlConvert.ToTimeSpan(s); }
                catch (FormatException) { error = $"'{text}' is not a valid ISO 8601 duration (e.g. PT24H, P1DT12H, PT30M)"; return false; }
            }
            // Clock form: HH:MM:SS or HH:MM (1-2 digit hours, days not accepted)
            else if (s.Contains(':'))
            {
                var parts = s.Split(':');
                if (parts.Length is < 2 or > 3 || parts.Any(p => p.Length is < 1 or > 2 || !int.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out _)))
                {
                    error = $"'{text}' is not a valid HH:MM:SS time (e.g. 06:00:00 or 6:00)";
                    return false;
                }
                int hours = int.Parse(parts[0], CultureInfo.InvariantCulture);
                int minutes = int.Parse(parts[1], CultureInfo.InvariantCulture);
                int seconds = parts.Length == 3 ? int.Parse(parts[2], CultureInfo.InvariantCulture) : 0;
                if (minutes > 59 || seconds > 59)
                {
                    error = $"'{text}': minutes and seconds must be 00-59";
                    return false;
                }
                value = new TimeSpan(hours, minutes, seconds);
            }
            // Plain hours, decimals allowed ("24", "1.5", "24h")
            else
            {
                string num = s.EndsWith("h", StringComparison.OrdinalIgnoreCase) ? s[..^1] : s;
                if (!double.TryParse(num, NumberStyles.Float, CultureInfo.InvariantCulture, out double hours) || hours <= 0 || double.IsNaN(hours))
                {
                    error = $"'{text}' is not a valid interval — plain hours (24), HH:MM:SS (06:00:00) or ISO 8601 (PT24H)";
                    return false;
                }
                value = TimeSpan.FromHours(hours);
            }

            if (value <= TimeSpan.Zero)
            {
                error = $"'{text}': interval must be greater than zero";
                return false;
            }
            return true;
        }

        /// <summary>Canonical Task Scheduler form (PT24H, PT1H30M, ...).</summary>
        public static string ToTaskForm(TimeSpan t) => XmlConvert.ToString(t);

        /// <summary>Human form for reports (24h, 3h 36m, 1d 12h).</summary>
        public static string ToHuman(TimeSpan t)
        {
            var sb = new System.Text.StringBuilder();
            if (t.Days > 0) sb.Append($"{t.Days}d");
            if (t.Hours > 0) sb.Append($"{(sb.Length > 0 ? " " : "")}{t.Hours}h");
            if (t.Minutes > 0) sb.Append($"{(sb.Length > 0 ? " " : "")}{t.Minutes}m");
            if (t.Seconds > 0) sb.Append($"{(sb.Length > 0 ? " " : "")}{t.Seconds}s");
            return sb.Length == 0 ? "0s" : sb.ToString();
        }

        /// <summary>
        /// Soft range check — the cached OneSettings payloads declare ~72 h
        /// freshness windows, so below 6 h buys nothing and above 72 h risks
        /// serving stale remote config. Advisory only: the caller warns and
        /// proceeds.
        /// </summary>
        public static string RangeWarning(TimeSpan t)
        {
            if (t < TimeSpan.FromHours(6))
                return $"WARNING: {ToHuman(t)} is below the 6h floor this tool recommends — the stock task already fetches ~7x/day; cached OneSettings payloads stay fresh for ~72h, so runs closer than 6h apart fetch nothing new";
            if (t > TimeSpan.FromHours(72))
                return $"WARNING: {ToHuman(t)} exceeds the ~72h freshness windows the cached OneSettings configs declare — remote config (feature flags, experiment cohorts) may go stale for up to {ToHuman(t)}";
            return null;
        }
    }
}
