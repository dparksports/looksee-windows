using System;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

namespace LookSee.Services
{
    /// <summary>
    /// Dark / Light theme switching. Replaces application-level brush resources
    /// at runtime — every theme-brush reference in XAML is a DynamicResource, so
    /// the swap applies live without a restart. Choice persists in HKCU.
    ///
    /// One identity: the Fluent reference palette and its slate dark variant.
    /// Light = airy gray-blue canvas, white floating cards, muted blue accent.
    /// Dark  = the same blues on a deep slate canvas. (Some brush KEY names
    /// retain historical "Violet/Pink/Cyan" wording — values are all blues
    /// now; keys are internal identifiers referenced across the XAML.)
    /// </summary>
    public static class ThemeService
    {
        private const string RegKey = @"Software\LookSee";
        private const string RegName = "Theme";

        // (resource key, dark value, light value)
        private static readonly (string Key, string Dark, string Light)[] BrushMap =
        {
            ("BackgroundBrush",    "#171B22", "#F0F2F6"),
            ("SurfaceBrush",       "#1F242E", "#FFFFFF"),
            ("SurfaceAltBrush",    "#282F3B", "#F7F9FC"),
            ("BorderBrush",        "#39414F", "#D9DEE7"),
            ("TextPrimaryBrush",   "#F1F4F9", "#1A1D23"),
            ("TextSecondaryBrush", "#98A2B3", "#5B6472"),
            ("AccentBlueBrush",    "#3B82F6", "#2F74B5"),
            ("AccentGreenBrush",   "#34D399", "#059669"),
            ("AccentAmberBrush",   "#F59E0B", "#B45309"),
            ("AccentRedBrush",     "#F87171", "#DC2626"),
            ("AccentVioletBrush",  "#4A9EEF", "#2F74B5"),   // hover accent — blue now
            ("AccentPinkBrush",    "#5FA8F5", "#3E86D6"),   // secondary accent — blue now
            ("AccentCyanBrush",    "#53B4E8", "#2A6FA8"),
            ("NavSelectedBrush",   "#16202E", "#E2EAF4"),
            ("NavHoverBrush",      "#101823", "#EAEFF6"),
            ("RowAltBrush",        "#20262F", "#F4F7FA"),
            ("RowHoverBrush",      "#262E3A", "#EBF0F6"),
            ("RowSelectedBrush",   "#31405A", "#D9E4F2"),
            ("GridLineBrush",      "#2A323E", "#E6EAF0"),
        };

        public static string Saved =>
            Registry.GetValue($@"HKEY_CURRENT_USER\{RegKey}", RegName, "Dark") as string ?? "Dark";

        /// <summary>Apply a theme now and remember it. theme: "Dark" | "Light".</summary>
        public static void ApplyTheme(string theme)
        {
            bool light = theme == "Light";
            var res = Application.Current.Resources;
            foreach (var (key, dark, lightVal) in BrushMap)
                res[key] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(light ? lightVal : dark));

            if (light)
            {
                res["PrimaryGradientBrush"] = MakeGradient("#2F74B5", "#3E86D6");
                res["DangerGradientBrush"] = MakeGradient("#DC2626", "#EF4444");
                res["TabIndicatorGradientBrush"] = MakeGradient("#2F74B5", "#5FA8F5");
            }
            else
            {
                res["PrimaryGradientBrush"] = MakeGradient("#3B82F6", "#60A5FA");
                res["DangerGradientBrush"] = MakeGradient("#EF4444", "#F87171");
                res["TabIndicatorGradientBrush"] = MakeGradient("#60A5FA", "#3B82F6");
            }

            using var k = Registry.CurrentUser.CreateSubKey(RegKey);
            k.SetValue(RegName, light ? "Light" : "Dark");
        }

        private static LinearGradientBrush MakeGradient(params string[] stops)
        {
            var brush = new LinearGradientBrush { StartPoint = new Point(0, 0), EndPoint = new Point(1, 1) };
            double step = stops.Length > 1 ? 1.0 / (stops.Length - 1) : 0;
            for (int i = 0; i < stops.Length; i++)
                brush.GradientStops.Add(new GradientStop((Color)ColorConverter.ConvertFromString(stops[i]), i * step));
            return brush;
        }
    }
}
