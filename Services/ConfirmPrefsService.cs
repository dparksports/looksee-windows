using System;
using System.Collections.Generic;
using System.IO;

namespace LookSee.Services
{
    /// <summary>
    /// "Don't ask again" choices for the block confirmations, persisted in
    /// confirm_prefs.txt next to the exe (one key per line — the same
    /// best-effort flat-file pattern as ignored_processes.txt). One key per
    /// warning class, so silencing the routine IP/process confirm never
    /// silences the Microsoft-infrastructure or Windows-service-host
    /// warnings. Reset from the Ignore lists… window.
    /// </summary>
    public static class ConfirmPrefs
    {
        public const string ConfirmIp = "confirm.ip";
        public const string ConfirmProcess = "confirm.process";
        public const string WarnMsInfra = "warn.ms-infra";
        public const string WarnWindowsCore = "warn.windows-core";

        public static readonly string[] AllKeys = { ConfirmIp, ConfirmProcess, WarnMsInfra, WarnWindowsCore };

        // Next to the exe — a relative name would follow the working
        // directory the app was launched from (same fix as the ignore list).
        private static string PrefsPath =>
            Path.Combine(AppContext.BaseDirectory, "confirm_prefs.txt");

        private static readonly HashSet<string> _suppressed = Load();

        private static HashSet<string> Load()
        {
            var set = new HashSet<string>(StringComparer.Ordinal);
            try
            {
                if (File.Exists(PrefsPath))
                {
                    foreach (string line in File.ReadAllLines(PrefsPath))
                    {
                        string key = line.Trim();
                        if (Array.IndexOf(AllKeys, key) >= 0)
                            set.Add(key);
                    }
                }
            }
            catch { /* unreadable file — start with every prompt active */ }
            return set;
        }

        public static bool IsSuppressed(string key) => _suppressed.Contains(key);

        /// <summary>How many of the four prompt classes are currently silenced.</summary>
        public static int SuppressedCount => _suppressed.Count;

        public static void Suppress(string key)
        {
            if (Array.IndexOf(AllKeys, key) < 0 || !_suppressed.Add(key)) return;
            Save();
        }

        /// <summary>Re-arms every block confirmation prompt ("I want the warnings back").</summary>
        public static void ResetAll()
        {
            if (_suppressed.Count == 0) return;
            _suppressed.Clear();
            Save();
        }

        private static void Save()
        {
            try { File.WriteAllLines(PrefsPath, _suppressed); }
            catch { /* persistence is best-effort — the live choice still applies */ }
        }
    }
}
