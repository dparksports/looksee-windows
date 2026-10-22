using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace LookSee.Services
{
    /// <summary>
    /// One-way, read-only import of the ignore lists a user already curated
    /// in a sibling AutoCommand install:
    ///   · ignored_processes.txt  (process names)  → LookSee's ignore file
    ///   · ignored-apps.json      (image paths)    → Who's Talking ignore list
    ///
    /// AutoCommand is never written to, and nothing here is required —
    /// LookSee is fully standalone. Block knowledge is NOT imported: badges
    /// and the block/unblock menu read the live firewall rules through
    /// FirewallBlockService (LookSee and AutoCommand share one rule scheme,
    /// so each sees the other's blocks as they happen).
    /// </summary>
    public static class AutoCommandImportService
    {
        private const string RegKey = @"Software\LookSee";
        private const string ExeCacheName = "AutoCommandExe";
        private const string ImportedFlagName = "AutoCommandImportedUtc";

        public class ImportResult
        {
            public bool FoundAutoCommand;
            public int NamesImported;
            public int ImagesImported;
            public string AutoCommandPath;
        }

        // ── AutoCommand.exe discovery ───────────────────────────────────

        /// <summary>Where AutoCommand.exe lives, or null. Checked live from
        /// the running process first, then the remembered registry path.</summary>
        public static string FindAutoCommandExe()
        {
            try
            {
                foreach (var p in Process.GetProcessesByName("AutoCommand"))
                {
                    try
                    {
                        string path = p.MainModule?.FileName;
                        if (!string.IsNullOrEmpty(path) && File.Exists(path))
                        {
                            RememberExe(path);
                            return path;
                        }
                    }
                    catch { /* exited or access denied — next */ }
                }
            }
            catch { /* process enumeration unavailable */ }

            try
            {
                string cached = Registry.GetValue($@"HKEY_CURRENT_USER\{RegKey}", ExeCacheName, null) as string;
                if (!string.IsNullOrEmpty(cached) && File.Exists(cached)) return cached;
            }
            catch { }

            return null;
        }

        private static void RememberExe(string path)
        {
            try
            {
                using var k = Registry.CurrentUser.CreateSubKey(RegKey);
                k.SetValue(ExeCacheName, path);
            }
            catch { }
        }

        // ── Import ───────────────────────────────────────────────────────

        /// <summary>True once an import has already run on this machine
        /// (first-run auto-import only runs once; the button re-runs).</summary>
        public static bool AlreadyImported =>
            Registry.GetValue($@"HKEY_CURRENT_USER\{RegKey}", ImportedFlagName, null) is string s &&
            s.Length > 0;

        /// <summary>Runs the whole import on a background thread.</summary>
        public static Task<ImportResult> ImportAsync() => Task.Run(Import);

        public static ImportResult Import()
        {
            var result = new ImportResult();
            string exe = FindAutoCommandExe();
            result.FoundAutoCommand = exe != null;
            result.AutoCommandPath = exe;

            // 1) process-name ignore list — next to AutoCommand.exe
            if (exe != null)
            {
                try
                {
                    string src = Path.Combine(Path.GetDirectoryName(exe) ?? ".", "ignored_processes.txt");
                    foreach (string line in File.ReadAllLines(src))
                    {
                        string name = line.Trim();
                        if (name.Length == 0) continue;
                        if (!SysmonWatcherService.IsIgnoredByFile(name) &&
                            !name.Equals("LookSee.exe", StringComparison.OrdinalIgnoreCase))
                        {
                            SysmonWatcherService.AddToIgnoreFile(name);
                            result.NamesImported++;
                        }
                    }
                }
                catch { /* no file — fine */ }
            }

            // 2) image-path ignore list (Who's Talking's own store)
            try
            {
                string src = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "AutoCommand", "transmissions", "ignored-apps.json");
                if (File.Exists(src))
                {
                    var images = JsonSerializer.Deserialize<List<string>>(File.ReadAllText(src)) ?? new();
                    foreach (string image in images)
                    {
                        if (string.IsNullOrEmpty(image)) continue;
                        if (!TransmissionsIgnoreList.IsIgnored(image))
                        {
                            TransmissionsIgnoreList.Ignore(image);
                            result.ImagesImported++;
                        }
                    }
                }
            }
            catch { /* unreadable — skip */ }

            try
            {
                using var k = Registry.CurrentUser.CreateSubKey(RegKey);
                k.SetValue(ImportedFlagName, DateTime.UtcNow.ToString("o"));
            }
            catch { }

            return result;
        }
    }
}
