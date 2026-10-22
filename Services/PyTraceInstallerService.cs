using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using Microsoft.Win32;

namespace LookSee.Services
{
    /// <summary>
    /// Installs/uninstalls the embedded python audit-hook payload into python
    /// environments, opt-in per environment. The payload is written as a
    /// uniquely-named module + .pth importer into the environment's real
    /// site-packages — never as sitecustomize.py (which may belong to the
    /// user) and never by touching the interpreter binary. Everything written
    /// is tracked in a local manifest so Uninstall removes only our files.
    /// </summary>
    public class PyTraceInstallerService
    {
        public const string ModuleName = "PyTraceHook_ac";
        public static string ManifestPath => Path.Combine(PyTraceReaderService.TraceDir, "instrumented.json");

        private const string PayloadResourceName = "LookSee.Assets.PyTraceHook.py";

        public sealed class PythonEnv
        {
            /// <summary>Path whose Lib\site-packages receives the payload.</summary>
            public string SitePackages { get; set; }

            /// <summary>Base of the environment (venv root or interpreter install dir).</summary>
            public string Root { get; set; }

            /// <summary>Where discovery found it: pep514-hklm/hkcu, store, conda, uv,
            /// pyenv-win, scoop, choco, path, venv-scan, seen-running, manifest.</summary>
            public string Source { get; set; }

            /// <summary>False for environments the .pth mechanism cannot reach (embedded).</summary>
            public bool CanInstrument { get; set; } = true;

            /// <summary>Why not, shown in the list instead of silently omitting the row.</summary>
            public string DisableReason { get; set; }

            public string Display
            {
                get
                {
                    string kind = Source is "venv" or "venv-scan" ? "venv" : Source ?? "?";
                    return $"[{kind}] {Root}";
                }
            }
        }

        public sealed class ManifestEntry
        {
            [JsonPropertyName("sitePackages")]
            public string SitePackages { get; set; }

            [JsonPropertyName("root")]
            public string Root { get; set; }

            [JsonPropertyName("source")]
            public string Source { get; set; }

            [JsonPropertyName("files")]
            public List<string> Files { get; set; } = new();

            [JsonPropertyName("installedAt")]
            public DateTime InstalledAt { get; set; }
        }

        // -----------------------------------------------------------------------
        // Discovery
        //
        // Tier 1 (fast, synchronous): PEP 514 registry, every PATH dir,
        // Microsoft Store packages, conda, uv, pyenv-win, scoop, chocolatey.
        // Tier 2 (background): bounded pyvenv.cfg hunt from curated roots —
        // see ScanForVenvs. Tier 3 (passive): python images the spawn watcher
        // has seen run — EnvFromImage in the dialog. Everything auto-populates
        // the LIST; installing stays behind the explicit confirmation.
        // -----------------------------------------------------------------------

        /// <summary>PEP 514 registered environments plus a probe for python on PATH.</summary>
        public List<PythonEnv> DiscoverEnvironments()
        {
            var envs = new List<PythonEnv>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            void Add(PythonEnv env)
            {
                if (env?.SitePackages == null) return;
                if (seen.Add(Path.GetFullPath(env.SitePackages)))
                    envs.Add(env);
            }

            foreach (var (hive, source) in new[]
            {
                (RegistryHive.LocalMachine, "pep514-hklm"),
                (RegistryHive.CurrentUser, "pep514-hkcu")
            })
            {
                foreach (string vendor in new[] { "PythonCore", "ContinuumAnalytics", "Python" })
                {
                    using var key = RegistryKey.OpenBaseKey(hive, Environment.Is64BitProcess && hive == RegistryHive.LocalMachine
                            ? RegistryView.Registry64 : RegistryView.Default)
                        .OpenSubKey($"SOFTWARE\\Python\\{vendor}");
                    if (key == null) continue;

                    foreach (string tag in key.GetSubKeyNames())
                    {
                        using var installPath = key.OpenSubKey($"{tag}\\InstallPath");
                        // PEP 514: the (default) value of InstallPath is where python lives
                        Add(EnvFromExeDir(installPath?.GetValue(null) as string, source));
                    }
                }
            }

            // Every python.exe on PATH — WindowsApps execution aliases are
            // zero-byte stubs with no site-packages and drop out naturally.
            try
            {
                string pathVar = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
                foreach (string dir in pathVar.Split(';', StringSplitOptions.RemoveEmptyEntries))
                    Add(EnvFromExeDir(dir.Trim(), "path"));
            }
            catch { }

            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            // Microsoft Store python: the package's LocalCache site-packages is
            // the real, user-writable target (the registered alias dir has none)
            try
            {
                string packages = Path.Combine(localAppData, "Packages");
                foreach (string pkg in Directory.GetDirectories(packages, "PythonSoftwareFoundation*"))
                {
                    string localPackages = Path.Combine(pkg, "LocalCache", "local-packages");
                    if (!Directory.Exists(localPackages)) continue;
                    foreach (string pyDir in Directory.GetDirectories(localPackages, "Python*"))
                    {
                        string sitePackages = Path.Combine(pyDir, "site-packages");
                        if (Directory.Exists(sitePackages))
                            Add(new PythonEnv { Root = pkg, SitePackages = sitePackages, Source = "store" });
                    }
                }
            }
            catch { }

            foreach (string conda in new[] { "anaconda3", "miniconda3", "miniforge3", "mambaforge" })
            {
                string baseDir = Path.Combine(userProfile, conda);
                Add(EnvFromExeDir(baseDir, "conda"));
                TryAddGlob(baseDir, "envs/*", env => Add(EnvFromExeDir(env, "conda")));
                TryAddGlob(Path.Combine(userProfile, ".conda"), "envs/*", env => Add(EnvFromExeDir(env, "conda")));
            }

            // uv-managed standalone CPythons (cpython-3.12.x+...-windows-...)
            TryAddGlob(Path.Combine(localAppData, "uv", "python"), "*",
                dir => Add(EnvFromExeDir(dir, "uv")));

            // pyenv-win
            TryAddGlob(Path.Combine(userProfile, ".pyenv", "pyenv-win", "versions"), "*",
                dir => Add(EnvFromExeDir(dir, "pyenv-win")));

            // Scoop (current is a junction to the versioned dir — resolve it)
            TryAddGlob(Path.Combine(userProfile, "scoop", "apps"), "python*",
                dir => Add(EnvFromExeDir(Path.Combine(dir, "current"), "scoop")));

            // Chocolatey
            Add(EnvFromExeDir(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "chocolatey", "lib", "python3", "tools"), "choco"));

            return envs;
        }

        /// <summary>
        /// Builds an env from a directory that either is a python install root
        /// (python.exe + Lib\site-packages) or a venv root (pyvenv.cfg).
        /// Returns null when the dir holds neither (covers Store alias stubs).
        /// Embedded distributions (python._pth beside the exe) come back with
        /// CanInstrument=false so they surface in the list with a reason.
        /// </summary>
        public static PythonEnv EnvFromExeDir(string dir, string source)
        {
            if (string.IsNullOrEmpty(dir)) return null;
            try
            {
                string root = Path.GetFullPath(dir);
                if (!Directory.Exists(root)) return null;

                string exe = Path.Combine(root, "python.exe");
                string sitePackages = Path.Combine(root, "Lib", "site-packages");
                if (File.Exists(exe) && Directory.Exists(sitePackages))
                    return Build(root, sitePackages, source);

                // venv layout: root\Scripts\python.exe + root\pyvenv.cfg
                string scripts = Path.Combine(root, "Scripts");
                string venvCfg = Path.Combine(root, "pyvenv.cfg");
                if (Directory.Exists(scripts) && File.Exists(venvCfg))
                {
                    string venvSite = Path.Combine(root, "Lib", "site-packages");
                    if (Directory.Exists(venvSite))
                        return Build(root, venvSite, source == "venv" ? "venv" : source);
                }
                return null;
            }
            catch
            {
                return null;
            }

            static PythonEnv Build(string root, string sitePackages, string source)
            {
                var env = new PythonEnv { Root = root, SitePackages = sitePackages, Source = source };
                if (File.Exists(Path.Combine(root, "python._pth")))
                {
                    env.CanInstrument = false;
                    env.DisableReason = "Embedded distribution (python._pth) — site is never loaded, cannot be instrumented";
                }
                return env;
            }
        }

        /// <summary>Tier 3 helper: an env for a python.exe image the watcher saw run.</summary>
        public static PythonEnv EnvFromImage(string exePath)
        {
            if (string.IsNullOrEmpty(exePath)) return null;
            try
            {
                string dir = Path.GetDirectoryName(Path.GetFullPath(exePath));
                // venv launchers live in <root>\Scripts; base installs run from the root
                if (string.Equals(Path.GetFileName(dir), "Scripts", StringComparison.OrdinalIgnoreCase) &&
                    File.Exists(Path.Combine(Path.GetDirectoryName(dir), "pyvenv.cfg")))
                    return EnvFromExeDir(Path.GetDirectoryName(dir), "seen-running");
                return EnvFromExeDir(dir, "seen-running");
            }
            catch { return null; }
        }

        private static void TryAddGlob(string parent, string pattern, Action<string> add)
        {
            try
            {
                foreach (string dir in Directory.GetDirectories(parent, pattern))
                    add(dir);
            }
            catch { /* parent absent or denied — that source just isn't installed */ }
        }

        // -----------------------------------------------------------------------
        // Tier 2: bounded pyvenv.cfg hunt
        // -----------------------------------------------------------------------

        /// <summary>Curated roots for the deep scan, plus any the user added.</summary>
        public List<string> GetScanRoots()
        {
            var roots = new List<string>(LoadScanState().Roots);
            if (roots.Count > 0) return roots;

            string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            foreach (string candidate in new[]
            {
                profile,
                Path.Combine(profile, "Desktop"),
                Path.Combine(profile, "Documents"),
                Path.Combine(profile, "Downloads"),
                Path.Combine(profile, "source"),
                Path.Combine(profile, "source", "repos"),
                Path.Combine(profile, "Projects"),
                Path.Combine(profile, "code"),
                Path.Combine(profile, "dev"),
                @"C:\src", @"C:\dev", @"C:\Projects", @"C:\code", @"C:\work"
            })
            {
                if (Directory.Exists(candidate)) roots.Add(candidate);
            }
            return roots;
        }

        // Directories that never contain a venv root but can contain millions
        // of entries — pruning these keeps the scan seconds, not minutes.
        private static readonly HashSet<string> SkipDirNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "node_modules", ".git", ".hg", ".svn", "bin", "obj", ".vs", ".idea",
            "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", "site-packages",
            "dist-info", "$RECYCLE.BIN", "System Volume Information", "WindowsApps"
        };

        /// <summary>
        /// Breadth-first hunt for venv roots (pyvenv.cfg) and bare python
        /// installs, bounded by depth, a directory cap and a skip list; never
        /// follows reparse points. Found environments stream out via onFound.
        /// </summary>
        public static void ScanForVenvs(IEnumerable<string> roots, int maxDepth, long maxDirectories,
            Action<PythonEnv> onFound, CancellationToken cancellationToken)
        {
            var queue = new Queue<(string Dir, int Depth)>();
            foreach (string root in roots)
                if (Directory.Exists(root)) queue.Enqueue((root, 0));

            long visited = 0;
            while (queue.Count > 0 && visited < maxDirectories)
            {
                if (cancellationToken.IsCancellationRequested) return;
                var (dir, depth) = queue.Dequeue();
                visited++;

                IEnumerable<string> subDirs;
                try { subDirs = Directory.EnumerateDirectories(dir); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (string sub in subDirs)
                {
                    if (cancellationToken.IsCancellationRequested) return;

                    string name = Path.GetFileName(sub);
                    bool skipped;
                    try
                    {
                        // Reparse points cause loops (junctions back up the tree)
                        skipped = (File.GetAttributes(sub) & FileAttributes.ReparsePoint) != 0 ||
                                  SkipDirNames.Contains(name);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    if (skipped) continue;

                    // A venv root or python install stops the descent — its
                    // Lib\site-packages tree is never interesting to re-scan.
                    PythonEnv env = EnvFromExeDir(sub, "venv-scan");
                    if (env != null)
                    {
                        onFound(env);
                        continue;
                    }

                    if (depth + 1 <= maxDepth)
                        queue.Enqueue((sub, depth + 1));
                }
            }
        }

        // -----------------------------------------------------------------------
        // Scan state persistence (env_scan.json): user roots, excluded envs
        // -----------------------------------------------------------------------

        public sealed class ScanState
        {
            public List<string> Roots { get; set; } = new();
            public List<string> Excluded { get; set; } = new();
            public DateTime? LastScanUtc { get; set; }
        }

        private static string ScanStatePath => Path.Combine(PyTraceReaderService.TraceDir, "env_scan.json");

        public ScanState LoadScanState()
        {
            try
            {
                if (File.Exists(ScanStatePath))
                    return JsonSerializer.Deserialize<ScanState>(File.ReadAllText(ScanStatePath)) ?? new ScanState();
            }
            catch { /* unreadable state falls back to defaults */ }
            return new ScanState();
        }

        private void SaveScanState(ScanState state)
        {
            try
            {
                Directory.CreateDirectory(PyTraceReaderService.TraceDir);
                File.WriteAllText(ScanStatePath,
                    JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { /* persistence is best-effort */ }
        }

        public void AddScanRoot(string root)
        {
            var state = LoadScanState();
            if (!state.Roots.Contains(root, StringComparer.OrdinalIgnoreCase))
            {
                state.Roots.Add(root);
                SaveScanState(state);
            }
        }

        /// <summary>Records an environment the user deliberately removed — rescans skip it.</summary>
        public void ExcludeSitePackages(string sitePackages)
        {
            var state = LoadScanState();
            string full = Path.GetFullPath(sitePackages);
            if (!state.Excluded.Contains(full, StringComparer.OrdinalIgnoreCase))
            {
                state.Excluded.Add(full);
                SaveScanState(state);
            }
        }

        public void MarkScanned()
        {
            var state = LoadScanState();
            state.LastScanUtc = DateTime.UtcNow;
            SaveScanState(state);
        }

        public bool IsExcluded(string sitePackages)
        {
            string full = Path.GetFullPath(sitePackages);
            return LoadScanState().Excluded.Contains(full, StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>Builds an env record for a user-picked venv root folder.</summary>
        public PythonEnv EnvFromVenvRoot(string root)
        {
            if (string.IsNullOrEmpty(root)) return null;
            string sitePackages = Path.Combine(root, "Lib", "site-packages");
            return Directory.Exists(sitePackages)
                ? new PythonEnv { Root = Path.GetFullPath(root), SitePackages = Path.GetFullPath(sitePackages), Source = "venv" }
                : null;
        }

        // -----------------------------------------------------------------------
        // Install / uninstall
        // -----------------------------------------------------------------------

        public bool IsInstalled(string sitePackages)
        {
            return File.Exists(Path.Combine(sitePackages, ModuleName + ".pth")) &&
                   File.Exists(Path.Combine(sitePackages, ModuleName + ".py"));
        }

        /// <summary>Writes payload + .pth into the environment; returns an error string or null.</summary>
        public string Install(PythonEnv env)
        {
            try
            {
                string payload = ReadPayloadText();
                Directory.CreateDirectory(env.SitePackages);
                Directory.CreateDirectory(PyTraceReaderService.TraceDir);
                TlsKeylogService.EnsureHygiene();

                string modulePath = Path.Combine(env.SitePackages, ModuleName + ".py");
                string pthPath = Path.Combine(env.SitePackages, ModuleName + ".pth");
                File.WriteAllText(modulePath, payload);
                // A .pth line starting with "import " executes at site init —
                // this runs the hook before any user code without touching
                // sitecustomize.py.
                File.WriteAllText(pthPath, $"import {ModuleName}" + Environment.NewLine);

                var manifest = LoadManifest();
                var entry = manifest.FirstOrDefault(m =>
                    m.SitePackages.Equals(env.SitePackages, StringComparison.OrdinalIgnoreCase));
                if (entry == null)
                {
                    entry = new ManifestEntry { SitePackages = env.SitePackages };
                    manifest.Add(entry);
                }
                entry.Root = env.Root;
                entry.Source = env.Source;
                entry.Files = new List<string> { modulePath, pthPath };
                entry.InstalledAt = DateTime.UtcNow;
                SaveManifest(manifest);
                return null;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        /// <summary>Removes only the manifest-listed files; returns an error string or null.</summary>
        public string Uninstall(string sitePackages)
        {
            try
            {
                var manifest = LoadManifest();
                var entry = manifest.FirstOrDefault(m =>
                    m.SitePackages.Equals(sitePackages, StringComparison.OrdinalIgnoreCase));
                if (entry == null) return "Not in the instrumentation manifest.";

                foreach (string file in entry.Files)
                {
                    // Defensive: only ever delete inside the recorded site-packages dir
                    if (!Path.GetFullPath(file).StartsWith(
                            Path.GetFullPath(entry.SitePackages) + Path.DirectorySeparatorChar,
                            StringComparison.OrdinalIgnoreCase)) continue;
                    if (File.Exists(file)) File.Delete(file);
                }
                manifest.Remove(entry);
                SaveManifest(manifest);
                return null;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        public List<ManifestEntry> LoadManifest()
        {
            try
            {
                if (!File.Exists(ManifestPath)) return new List<ManifestEntry>();
                return JsonSerializer.Deserialize<List<ManifestEntry>>(File.ReadAllText(ManifestPath))
                       ?? new List<ManifestEntry>();
            }
            catch
            {
                return new List<ManifestEntry>();
            }
        }

        private static void SaveManifest(List<ManifestEntry> manifest)
        {
            Directory.CreateDirectory(PyTraceReaderService.TraceDir);
            File.WriteAllText(ManifestPath,
                JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }));
        }

        /// <summary>The embedded payload text (read from assembly resources, never from disk).</summary>
        public static string ReadPayloadText()
        {
            var assembly = Assembly.GetExecutingAssembly();
            using var stream = assembly.GetManifestResourceStream(PayloadResourceName);
            if (stream == null)
                throw new InvalidOperationException($"Embedded resource {PayloadResourceName} not found.");
            using var reader = new StreamReader(stream);
            return reader.ReadToEnd();
        }
    }
}
