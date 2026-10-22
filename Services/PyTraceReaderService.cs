using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using LookSee.Models;

namespace LookSee.Services
{
    /// <summary>
    /// Tails the per-pid JSONL files the instrumented python hook writes into
    /// %LOCALAPPDATA%\LookSee\pytrace. A FileSystemWatcher alone can miss
    /// or coalesce notifications under rapid writes, so a periodic tail
    /// (remembering a per-file read offset) does the actual catching up —
    /// the watcher only nudges the same tail to run sooner.
    /// </summary>
    public class PyTraceReaderService : IDisposable
    {
        public static string TraceDir =>
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "LookSee", "pytrace");

        private readonly string _dir;
        private readonly int _perPidCap;
        private readonly bool _loadExisting;

        private readonly ConcurrentDictionary<string, long> _offsets = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<int, ConcurrentQueue<PyTraceRecord>> _byPid = new();
        private readonly ConcurrentDictionary<int, byte> _pidsWithTrace = new();

        private FileSystemWatcher _watcher;
        private Timer _tailTimer;
        private Timer _cleanupTimer;
        private int _malformed;
        private int _disposed;

        public event Action<string> OnError;
        public event Action<PyTraceRecord> OnRecord;

        /// <summary>Malformed JSONL lines seen so far — surfaced by the view, never swallowed.</summary>
        public int MalformedCount => _malformed;

        public PyTraceReaderService(int perPidCap = 200, bool loadExisting = true)
        {
            _dir = TraceDir;
            _perPidCap = perPidCap;
            _loadExisting = loadExisting;
        }

        public void Start()
        {
            try
            {
                Directory.CreateDirectory(_dir);
            }
            catch (Exception ex)
            {
                OnError?.Invoke($"Cannot create pytrace directory: {ex.Message}");
                return;
            }

            if (_loadExisting)
                TailAllFiles(); // stacks of processes started before the tab

            try
            {
                _watcher = new FileSystemWatcher(_dir, "trace-*.jsonl")
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                    InternalBufferSize = 64 * 1024
                };
                _watcher.Created += (s, e) => TailFile(e.FullPath);
                _watcher.Changed += (s, e) => TailFile(e.FullPath);
                _watcher.EnableRaisingEvents = true;
            }
            catch (Exception ex)
            {
                OnError?.Invoke($"pytrace directory watcher failed: {ex.Message} (periodic tail continues)");
            }

            _tailTimer = new Timer(_ => TailAllFiles(), null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));
            _cleanupTimer = new Timer(_ => CleanupDeadPids(), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
        }

        public void Stop()
        {
            _watcher?.Dispose();
            _watcher = null;
            _tailTimer?.Dispose();
            _tailTimer = null;
            _cleanupTimer?.Dispose();
            _cleanupTimer = null;
        }

        /// <summary>True once any trace record has been seen for this pid.</summary>
        public bool HasTraceForPid(int pid) => _pidsWithTrace.ContainsKey(pid);

        /// <summary>Records recorded for the pid, oldest first.</summary>
        public IReadOnlyList<PyTraceRecord> GetForPid(int pid)
        {
            if (!_byPid.TryGetValue(pid, out var queue)) return Array.Empty<PyTraceRecord>();
            return queue.ToArray();
        }

        private void TailAllFiles()
        {
            try
            {
                foreach (string file in Directory.EnumerateFiles(_dir, "trace-*.jsonl"))
                    TailFile(file);
            }
            catch (DirectoryNotFoundException) { /* dir removed mid-scan */ }
            catch (Exception ex)
            {
                OnError?.Invoke($"pytrace tail failed: {ex.Message}");
            }
        }

        private void TailFile(string path)
        {
            try
            {
                // Rotation/recreation races show up as a shrunken file — the
                // offset resets and the new content is read in full.
                var fi = new FileInfo(path);
                if (!fi.Exists) { _offsets.TryRemove(path, out _); return; }

                long offset = _offsets.GetOrAdd(path, 0);
                if (fi.Length < offset) offset = 0;
                if (fi.Length == offset) return;

                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                fs.Seek(offset, SeekOrigin.Begin);
                using var reader = new StreamReader(fs);

                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (line.Length == 0) continue;
                    var record = ParseLine(line);
                    if (record == null) { _malformed++; continue; }
                    Store(record);
                }

                _offsets[path] = fs.Position;
            }
            catch (IOException)
            {
                // writer holds the file mid-append; the next tick retries
            }
            catch (Exception ex)
            {
                OnError?.Invoke($"pytrace tail failed for {Path.GetFileName(path)}: {ex.Message}");
            }
        }

        private static PyTraceRecord ParseLine(string line)
        {
            try
            {
                var record = JsonSerializer.Deserialize<PyTraceRecord>(line);
                if (record == null || record.Pid <= 0 || string.IsNullOrEmpty(record.Event)) return null;
                return record;
            }
            catch (JsonException)
            {
                return null;
            }
        }

        private void Store(PyTraceRecord record)
        {
            var queue = _byPid.GetOrAdd(record.Pid, _ => new ConcurrentQueue<PyTraceRecord>());
            queue.Enqueue(record);
            while (queue.Count > _perPidCap && queue.TryDequeue(out _)) { }
            _pidsWithTrace.TryAdd(record.Pid, 0);
            OnRecord?.Invoke(record);
        }

        /// <summary>
        /// Deletes trace files whose pid is gone, once the file has also been
        /// quiet for five minutes (a live pid mid-write never gets deleted).
        /// </summary>
        private void CleanupDeadPids()
        {
            try
            {
                foreach (string file in Directory.EnumerateFiles(_dir, "trace-*.jsonl"))
                {
                    string name = Path.GetFileNameWithoutExtension(file); // trace-<pid>
                    if (!int.TryParse(name.AsSpan("trace-".Length), out int pid)) continue;

                    var fi = new FileInfo(file);
                    if (fi.LastWriteTimeUtc > DateTime.UtcNow - TimeSpan.FromMinutes(5)) continue;

                    bool alive;
                    try { Process.GetProcessById(pid); alive = true; }
                    catch (ArgumentException) { alive = false; }

                    if (!alive)
                    {
                        try { File.Delete(file); } catch (IOException) { }
                        _offsets.TryRemove(file, out _);
                    }
                }
            }
            catch { /* cleanup is opportunistic */ }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
            Stop();
        }
    }
}
