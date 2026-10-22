using System.Globalization;
using SvchostAnalyzer.Core;

// SvchostAnalyzer — CLI face of the SvchostAnalyzer.Core engine
// (the same engine LookSee links in-process for its Svchost Trace tab).
//
//   capture : collect spawn/connect/byte events to a JSONL trace
//   analyze : pattern-detect on one or more traces
//
// Usage:
//   SvchostAnalyzer capture [--seconds N] [--poll-ms N] [--out file.jsonl]
//   SvchostAnalyzer analyze <trace.jsonl> [more.jsonl ...]
//   SvchostAnalyzer <trace.jsonl>          (shorthand for analyze)
//
// Exit codes (analyze): 0 = no flags, 2 = flags raised, 1 = usage/IO error,
// 3 = capture already running.

if (args.Length == 0) { Usage(); return 1; }

if (args[0].Equals("capture", StringComparison.OrdinalIgnoreCase))
    return RunCapture(args.Skip(1).ToArray());
if (args[0].Equals("analyze", StringComparison.OrdinalIgnoreCase))
    args = args.Skip(1).ToArray();

// every remaining argument is a trace file (shorthand: "SvchostAnalyzer
// x.jsonl" with no verb). The .jsonl/glob filter rejects stray options.
var files = new List<string>();
foreach (var a in args.Where(a => a.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase) || a.Contains('*')))
{
    if (a.Contains('*'))
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(a));
        files.AddRange(Directory.GetFiles(dir!, Path.GetFileName(a)));
    }
    else files.Add(a);
}
if (files.Count == 0) { Usage(); return 1; }

var result = TraceAnalyzer.Analyze(files);
Console.Out.Write(result.Report);
return result.Flags;

static int RunCapture(string[] a)
{
    double seconds = 90, pollMs = 1000, maxMb = 0;
    string outFile = $"svchost-trace-{DateTime.Now:yyyyMMdd-HHmmss}.jsonl";
    string stopFile = null;
    for (int i = 0; i < a.Length; i++)
    {
        switch (a[i].ToLowerInvariant())
        {
            case "--seconds": case "-s": seconds = double.Parse(a[++i], CultureInfo.InvariantCulture); break;
            case "--poll-ms":            pollMs = double.Parse(a[++i], CultureInfo.InvariantCulture); break;
            case "--max-size-mb":        maxMb = double.Parse(a[++i], CultureInfo.InvariantCulture); break;
            case "--stop-file":          stopFile = a[++i]; break;
            case "--out": case "-o":     outFile = a[++i]; break;
            default: Console.Error.WriteLine($"unknown option {a[i]}"); return 1;
        }
    }

    using var engine = new CaptureEngine(new CaptureOptions
    {
        OutFile = outFile,
        PollMs = (int)pollMs,
        Duration = seconds <= 0 ? null : TimeSpan.FromSeconds(seconds),
        MaxSizeMb = maxMb,
        StopFile = stopFile,
    });
    // subscribe BEFORE Start(): a very short capture can complete immediately
    var done = new ManualResetEventSlim(false);
    engine.Completed += file =>
    {
        Console.WriteLine($"capture complete: {file}");
        done.Set();
    };
    try
    {
        engine.Start();
    }
    catch (InvalidOperationException ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 3;
    }
    // Ctrl+C / process kill: the JSONL stays valid (every event is its own line)
    Console.CancelKeyPress += (_, e) => { e.Cancel = false; engine.Stop(); };
    // the capture thread is background; block the main thread until completion
    done.Wait();
    return 0;
}

static void Usage()
{
    Console.Error.WriteLine(
        """
        usage:
          SvchostAnalyzer capture [--seconds N] [--poll-ms N] [--out file.jsonl]
                                  [--max-size-mb N] [--stop-file path]
            --seconds 0        run until killed or stop-file appears (service mode)
            --max-size-mb N    rotate trace file when it exceeds N megabytes
          SvchostAnalyzer analyze <trace.jsonl> [more.jsonl / *.jsonl ...]

        exit codes (analyze): 0 clean, 2 flags, 1 usage/IO, 3 already-running (capture)
        """);
}
