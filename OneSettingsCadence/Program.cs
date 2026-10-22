using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using LookSee.OneSettingsCadence;

// OneSettingsCadence — CLI face of the LookSee OneSettings cadence control
// (engine: CadenceEngine.cs; Task Scheduler reached over COM, never schtasks).
//
// Slows the Windows inbox task \Microsoft\Windows\Flighting\OneSettings\RefreshCache
// (OneSettings remote-config fetch; stock = ~3h20m repetition + 1h random delay
// + WNF state-change triggers, ~20-40 runs/day as SYSTEM) to a user-chosen
// interval, and restores stock behavior afterwards.
//
//   status   : read-only report — live interval, random delay, WNF trigger
//              count, last/next run, drift vs saved cadence, watchdog, backups
//   preview  : dry run — prints the exact task XML "set" would register
//   set      : applies the interval (default 24h) — backs up the XML first,
//              verifies, rolls back on failure; self-elevates via UAC
//   restore  : re-registers the newest (or named) backup, clears saved state,
//              removes the watchdog; self-elevates via UAC
//   enforce  : the watchdog's verb — re-applies the saved cadence when the
//              live task drifted (Windows servicing rewrites inbox tasks)
//
// Interval forms: 24 | 24h (plain hours) · 06:00:00 | 6:00 (clock) · PT24H (ISO 8601)
//
// Exit codes: 0 ok · 1 usage/task-not-found/IO · 2 drift found (status) or
// verify failed but rolled back (set/restore/enforce) · 3 elevation declined ·
// 4 rollback failed too — the task needs manual attention.

if (args.Length == 0) { Usage(); return 1; }

// The elevated child tees its output to a temp file so the un-elevated parent
// (and its console) sees everything; strip it before any re-relaunch.
string[] mainArgs = args;
string teeFile = null;
var teeStripped = new List<string>();
for (int i = 0; i < mainArgs.Length; i++)
{
    if (mainArgs[i].Equals("--elevated-out", StringComparison.OrdinalIgnoreCase))
    {
        teeFile = mainArgs[i + 1];
        i++; // consume the path
    }
    else teeStripped.Add(mainArgs[i]);
}
mainArgs = teeStripped.ToArray();
if (teeFile != null) AttachOutputTee(teeFile);

string verb = mainArgs[0].ToLowerInvariant();
string[] rest = mainArgs.Skip(1).ToArray();

switch (verb)
{
    case "status":   return CmdStatus();
    case "preview":  return CmdPreview(rest);
    case "runs":     return CmdRuns(mainArgs);
    case "set":      return CmdSet(mainArgs);
    case "restore":  return CmdRestore(mainArgs);
    case "enforce":  return CmdEnforce(mainArgs);
    case "help": case "--help": case "-h": Usage(); return 0;
    default:
        Console.Error.WriteLine($"unknown command '{mainArgs[0]}'");
        Usage();
        return 1;
}

// ---------------------------------------------------------------------------
// status — read-only, no elevation
// ---------------------------------------------------------------------------

int CmdStatus()
{
    var engine = new CadenceEngine();
    CadenceEngine.LiveState live;
    try { live = engine.ReadLive(); }
    catch (Exception ex) { Console.Error.WriteLine(ex.Message); return 1; }

    string dir = CadenceEngine.StateDir;
    var state = CadenceEngine.LoadState();
    var backups = CadenceEngine.ListBackups();

    Console.WriteLine($"Task            {CadenceEngine.TaskPath}");
    Console.WriteLine($"State           {live.TaskState}");
    Console.WriteLine($"Runs as         {live.PrincipalUserId}{(SidToFriendly(live.PrincipalUserId) is { } friendly ? $" ({friendly})" : "")}");
    Console.WriteLine($"TimeTrigger     interval {Fmt(live.Interval)} · random delay {Fmt(live.RandomDelay ?? TimeSpan.Zero)} · repetition duration {(live.Duration is { } d ? Fmt(d) : "none (indefinite)")}");
    Console.WriteLine(live.WnfStateNames.Count > 0
        ? $"WNF triggers    {live.WnfStateNames.Count} ({string.Join(", ", live.WnfStateNames)})"
        :  "WNF triggers    0");
    if (live.Interval is { } iv)
        Console.WriteLine($"Rate            ~{24.0 / iv.TotalHours:0.#} runs/day from repetition alone" +
                          (live.WnfStateNames.Count > 0 ? ", plus WNF state-change runs on top" : "") +
                          (live.RandomDelay is { } rd && rd > TimeSpan.Zero ? $", jittered up to +{IntervalParser.ToHuman(rd)}" : ""));
    Console.WriteLine($"Last run        {(live.LastRun?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "never")}{(live.LastResult is { } r ? $" · result {DescribeResult(r)}" : "")}");
    Console.WriteLine($"Next run        {(live.NextRun?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "—")}");

    Console.WriteLine();
    List<string> drift = null;
    if (state != null)
    {
        // a hand-edited or corrupt state.json must degrade the report, not crash it
        try
        {
            var desired = ParsePt(state.DesiredInterval);
            Console.WriteLine($"Desired cadence {IntervalParser.ToHuman(desired)} ({state.DesiredInterval}), set {state.SetAtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} by {state.SetBy} · WNF kept: {(state.KeepWnf ? "yes" : "no")}" +
                              (state.LastEnforcedUtc is { } le ? $" · last enforced {le.ToLocalTime():yyyy-MM-dd HH:mm}" : ""));
            drift = CadenceEngine.FindMismatches(live, desired, state.KeepWnf, state.OriginalWnfCount);
            if (drift.Count == 0)
            {
                Console.WriteLine("Drift           none — live task matches the saved cadence");
            }
            else
            {
                Console.WriteLine("Drift           live task no longer matches the saved cadence:");
                foreach (string p in drift) Console.WriteLine($"                  - {p}");
                Console.WriteLine("                (Windows servicing rewrites inbox tasks; re-apply with: OneSettingsCadence set)");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Desired cadence saved but unreadable ({ex.Message}) — see {CadenceEngine.StateFile}");
            drift = new List<string>(); // unreadable ≠ drifted; do not exit 2 on a corrupt file
        }
    }
    else
    {
        Console.WriteLine("Desired cadence none saved — the task is at stock, or was changed outside this tool");
    }

    bool watchdog = engine.WatchdogInstalled();
    Console.WriteLine(watchdog
        ? $"Watchdog        installed ({CadenceEngine.WatchdogPath}) — daily 03:30 + at logon, runs 'enforce --quiet' as SYSTEM"
        :  "Watchdog        not installed");

    Console.WriteLine();
    Console.WriteLine($"Backups         {(backups.Count == 0 ? "none yet" : $"{backups.Count} file(s) under {CadenceEngine.BackupDir}")}");
    foreach (var b in backups)
        Console.WriteLine($"                  {Path.GetFileName(b.File),-40} {b.Written:yyyy-MM-dd HH:mm:ss}   {b.Size:N0} bytes");
    Console.WriteLine($"Audit trail     {(File.Exists(CadenceEngine.AuditFile) ? CadenceEngine.AuditFile : "no changes recorded yet")}");

    return drift is { Count: > 0 }
        ? 2 // schedulable drift signal, same spirit as SvchostAnalyzer's flags-raised
        : 0;
}

// ---------------------------------------------------------------------------
// preview — dry run, no elevation
// ---------------------------------------------------------------------------

int CmdPreview(string[] a)
{
    TimeSpan interval = TimeSpan.FromHours(24);
    bool keepWnf = false;
    foreach (string arg in a)
    {
        if (arg.Equals("--keep-wnf", StringComparison.OrdinalIgnoreCase)) keepWnf = true;
        else if (arg.StartsWith("--", StringComparison.Ordinal)) { Console.Error.WriteLine($"unknown option {arg}"); return 1; }
        else if (!IntervalParser.TryParse(arg, out interval, out string err)) { Console.Error.WriteLine(err); return 1; }
    }
    WarnRange(interval);

    var engine = new CadenceEngine();
    CadenceEngine.LiveState live;
    try { live = engine.ReadLive(); }
    catch (Exception ex) { Console.Error.WriteLine(ex.Message); return 1; }

    CadenceEngine.TransformResult t;
    try { t = CadenceEngine.Transform(live.Xml, interval, keepWnf); }
    catch (Exception ex) { Console.Error.WriteLine(ex.Message); return 1; }

    Console.WriteLine($"# dry run — nothing is written; 'set' would register this XML for {CadenceEngine.TaskPath}");
    Console.WriteLine($"# repetition interval {Fmt(t.OldInterval)} -> {Fmt(t.NewInterval)} · random delay {Fmt(t.OldRandomDelay ?? TimeSpan.Zero)} -> 0 (PT0S)");
    Console.WriteLine(t.RemovedWnfNames.Count > 0
        ? $"# removing {t.RemovedWnfNames.Count} WNF state-change trigger(s): {string.Join(", ", t.RemovedWnfNames)}"
        :  "# WNF triggers kept (--keep-wnf or none present)");
    foreach (string note in t.Notes) Console.WriteLine($"# {note}");
    Console.WriteLine();
    Console.WriteLine(t.ModifiedXml);
    return 0;
}

// ---------------------------------------------------------------------------
// set — self-elevates, backs up, transforms, re-registers, verifies, rolls back
// ---------------------------------------------------------------------------

int CmdSet(string[] mainArgs)
{
    TimeSpan interval = TimeSpan.FromHours(24);
    bool keepWnf = false;
    bool? watchdog = null; // null = leave whatever is installed as-is
    string[] a = mainArgs.Skip(1).ToArray();
    foreach (string arg in a)
    {
        if (arg.Equals("--keep-wnf", StringComparison.OrdinalIgnoreCase)) keepWnf = true;
        else if (arg.Equals("--watchdog", StringComparison.OrdinalIgnoreCase)) watchdog = true;
        else if (arg.Equals("--no-watchdog", StringComparison.OrdinalIgnoreCase)) watchdog = false;
        else if (arg.StartsWith("--", StringComparison.Ordinal)) { Console.Error.WriteLine($"unknown option {arg}"); Usage(); return 1; }
        else if (!IntervalParser.TryParse(arg, out interval, out string err)) { Console.Error.WriteLine(err); return 1; }
    }
    // fail fast on a bad interval (and show the range warning) BEFORE the UAC
    // prompt; the elevated child skips its own warning since this run showed it
    // (teeFile is set only in the elevated child — see the top-level prologue)
    if (teeFile == null) WarnRange(interval);

    if (!IsElevated()) return RelaunchElevated(mainArgs);

    // orchestration lives in the engine, shared with the app's OneSettings tab
    string exePath = Environment.ProcessPath ?? System.Reflection.Assembly.GetEntryAssembly()!.Location;
    CadenceEngine.ApplyResult r = new CadenceEngine().Apply(interval, keepWnf, watchdog, exePath, "enforce --quiet");

    if (r.BackupFile != null) Console.WriteLine($"backup   {r.BackupFile}");
    if (!r.Ok)
    {
        if (r.FatalError != null) Console.Error.WriteLine($"set failed: {r.FatalError}");
        foreach (string p in r.Problems) Console.Error.WriteLine($"  - {p}");
        if (r.RollbackFailed)
        {
            Console.Error.WriteLine($"CRITICAL: rollback did not restore the original definition — restore manually with: OneSettingsCadence restore --backup {Path.GetFileName(r.BackupFile)}");
            return 4;
        }
        Console.Error.WriteLine(r.RolledBack
            ? $"rolled back to {Fmt(r.Before.Interval)} from {Path.GetFileName(r.BackupFile)} — the task is unchanged"
            : "nothing was changed — the task was never modified");
        return 2;
    }

    foreach (string note in r.Notes) Console.WriteLine($"note     {note}");
    if (watchdog == true) Console.WriteLine($"watchdog installed ({CadenceEngine.WatchdogPath}) — re-applies this cadence daily 03:30 and at logon");
    else if (watchdog == false) Console.WriteLine("watchdog removed");
    Console.WriteLine($"applied  repetition {Fmt(r.Before.Interval)} -> {Fmt(r.Interval)} · random delay {Fmt(r.Before.RandomDelay ?? TimeSpan.Zero)} -> 0 · WNF triggers {r.Before.WnfStateNames.Count} -> {r.After.WnfStateNames.Count}");
    Console.WriteLine($"verified live interval {Fmt(r.After.Interval)}, next run {r.After.NextRun?.ToLocalTime():yyyy-MM-dd HH:mm:ss}");
    Console.WriteLine($"audit    {CadenceEngine.AuditFile}");
    return 0;
}

// ---------------------------------------------------------------------------
// restore — newest (or named) backup, then clear state + remove watchdog
// ---------------------------------------------------------------------------

int CmdRestore(string[] mainArgs)
{
    string backupArg = null;
    var parts = mainArgs.Skip(1).ToList();
    for (int i = 0; i < parts.Count; i++)
    {
        if (parts[i].Equals("--backup", StringComparison.OrdinalIgnoreCase))
        {
            if (backupArg != null) { Console.Error.WriteLine("--backup given twice"); return 1; }
            if (i + 1 >= parts.Count) { Console.Error.WriteLine("--backup needs a file name (see: OneSettingsCadence status)"); return 1; }
            backupArg = parts[i + 1];
            i++;
        }
        else if (parts[i].StartsWith("--", StringComparison.Ordinal))
        {
            Console.Error.WriteLine($"unknown option {parts[i]}"); Usage(); return 1;
        }
    }

    if (!IsElevated()) return RelaunchElevated(mainArgs);

    CadenceEngine.RestoreResult r;
    try { r = new CadenceEngine().RestoreFrom(backupArg); }
    catch (Exception ex) { Console.Error.WriteLine($"restore failed: {ex.Message}"); return 1; } // e.g. no backups

    if (!r.Ok)
    {
        if (r.FatalError != null) Console.Error.WriteLine($"restore failed: {r.FatalError}");
        foreach (string p in r.Problems) Console.Error.WriteLine($"  - {p}");
        if (r.RollbackFailed)
        {
            Console.Error.WriteLine($"CRITICAL: rollback did not restore the pre-restore definition — restore manually with: OneSettingsCadence restore --backup {Path.GetFileName(r.SafetyBackupFile)}");
            return 4;
        }
        Console.Error.WriteLine(r.RolledBack
            ? $"put the pre-restore definition back ({Fmt(r.Before.Interval)}); the failed backup is still available: {r.BackupFile}"
            : "nothing was changed — the task was never modified");
        return 2;
    }

    Console.WriteLine($"restored {r.BackupFile}");
    Console.WriteLine($"verified live interval {Fmt(r.After.Interval)} · random delay {Fmt(r.After.RandomDelay ?? TimeSpan.Zero)} · WNF triggers {r.After.WnfStateNames.Count}");
    Console.WriteLine(r.HadWatchdog ? "watchdog removed (it would re-apply the old cadence)" : "watchdog: was not installed");
    Console.WriteLine($"saved cadence cleared; next run {r.After.NextRun?.ToLocalTime():yyyy-MM-dd HH:mm:ss}");
    Console.WriteLine($"audit    {CadenceEngine.AuditFile}");
    return 0;
}

// ---------------------------------------------------------------------------
// enforce — the watchdog's verb; re-applies the saved cadence on drift
// ---------------------------------------------------------------------------

int CmdEnforce(string[] mainArgs)
{
    bool quiet = mainArgs.Skip(1).Any(a => a.Equals("--quiet", StringComparison.OrdinalIgnoreCase));
    if (!IsElevated()) return RelaunchElevated(mainArgs);

    // orchestration lives in the engine, shared with the app's OneSettings tab
    CadenceEngine.EnforceResult r = new CadenceEngine().Enforce();
    if (!r.HadState)
    {
        if (!quiet) Console.WriteLine("no saved cadence — nothing to enforce (this is normal after 'restore')");
        return 0;
    }
    if (r.FatalError != null) { Console.Error.WriteLine($"enforce failed: {r.FatalError}"); return 2; }
    if (!r.DriftFound)
    {
        if (!quiet) Console.WriteLine($"no drift — cadence {CadenceEngine.LoadState()?.DesiredInterval} already in force");
        return 0;
    }
    if (r.Applied)
    {
        Console.WriteLine($"re-applied {CadenceEngine.LoadState()?.DesiredInterval} · next run {r.After.NextRun?.ToLocalTime():yyyy-MM-dd HH:mm:ss}");
        return 0;
    }
    // drift found, re-apply did not verify — engine audited the failure; the
    // stock backup from 'set' remains the escape hatch, so no blind rollback
    Console.Error.WriteLine("enforce could not verify the re-applied cadence: " + string.Join("; ", r.Problems));
    return 2;
}

// ---------------------------------------------------------------------------
// runs — read-only observed-vs-expected compliance report (scheduler history)
// ---------------------------------------------------------------------------

int CmdRuns(string[] mainArgs)
{
    int days = 7;
    foreach (string arg in mainArgs.Skip(1))
    {
        if (!int.TryParse(arg, out days) || days < 1 || days > 90)
        {
            Console.Error.WriteLine($"'{arg}' is not a day count (1-90)");
            return 1;
        }
    }

    var engine = new CadenceEngine();
    CadenceEngine.LiveState live;
    try { live = engine.ReadLive(); }
    catch (Exception ex) { Console.Error.WriteLine(ex.Message); return 1; }

    var state = CadenceEngine.LoadState();
    var history = RunHistory.Read(days);
    // judge against the saved cadence when one exists, else the live (stock) one
    TimeSpan cadence = state != null ? ParsePt(state.DesiredInterval)
                                     : live.Interval ?? TimeSpan.FromHours(3.33);
    var c = RunHistory.Compute(history.Runs, cadence, state != null, days, wnfTriggersPresent: live.WnfStateNames.Count > 0);

    Console.WriteLine($"Task            {CadenceEngine.TaskPath}");
    Console.WriteLine($"Window          last {days} day(s), judged against {(state != null ? $"saved cadence {state.DesiredInterval}" : $"live (stock) interval {IntervalParser.ToTaskForm(cadence)}")}");
    if (history.ChannelWasDisabled)
        Console.WriteLine("Note            Task Scheduler history was disabled — just enabled; the window starts now");
    Console.WriteLine($"Observed        {c.TotalRuns} run(s): {c.TimerRuns} timer · {c.EventRuns} event/WNF · {c.LogonRuns} logon · {c.ManualRuns} manual/API");
    Console.WriteLine($"Expected        ~{c.ExpectedTimerRuns} timer run(s) at the {(state != null ? "saved" : "stock")} cadence");
    Console.WriteLine($"Verdict         {c.Verdict}");
    Console.WriteLine();
    foreach (RunHistory.TaskRun run in history.Runs.Take(40))
        Console.WriteLine($"  {run.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}  {run.Trigger,-16} result {(run.ResultCode is { } rc ? DescribeResult(rc) : "—")}");
    if (history.Runs.Count > 40) Console.WriteLine($"  … {history.Runs.Count - 40} more");
    return 0;
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

void Usage()
{
    Console.Error.WriteLine(
        """
        usage:
          OneSettingsCadence status
              live interval / random delay / WNF trigger count / last & next run,
              drift vs the saved desired cadence, watchdog state, backups. read-only.
          OneSettingsCadence runs [days]
              observed vs expected launches from Task Scheduler history, bucketed
              by why each fired (timer / event-WNF / logon / manual). read-only.
          OneSettingsCadence preview [interval] [--keep-wnf]
              dry run: prints the exact task XML 'set' would register. no elevation.
          OneSettingsCadence set [interval] [--keep-wnf] [--watchdog | --no-watchdog]
              applies the cadence (default 24h), backing up the task XML first;
              verifies the live task and rolls back on any failure. self-elevates.
              --watchdog    also install a SYSTEM task re-applying the cadence
                            daily + at logon (Windows servicing reverts inbox tasks)
          OneSettingsCadence restore [--backup <file>]
              re-registers the newest backup (or the named one), clears the saved
              cadence and removes the watchdog. self-elevates.
          OneSettingsCadence enforce [--quiet]
              the watchdog's verb: re-apply the saved cadence if the task drifted.
              humans normally use 'set'.

        interval forms: 24 | 24h (plain hours) - 06:00:00 | 6:00 (clock) - PT24H (ISO 8601)
        default 24h; below 6h or above 72h warns (cached configs stay fresh ~72h) but proceeds.

        exit codes: 0 ok - 1 usage/task-not-found/IO - 2 drift (status) or verified-failure
                    rolled back (set/restore/enforce) - 3 elevation declined - 4 rollback
                    failed too, manual attention needed
        """);
}

void WarnRange(TimeSpan interval)
{
    string warning = IntervalParser.RangeWarning(interval);
    if (warning != null) Console.Error.WriteLine(warning);
}

bool IsElevated()
{
    using var identity = WindowsIdentity.GetCurrent();
    return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
}

/// <summary>
/// Relaunches the current command elevated, tees the child's output back to
/// this console via a temp file, and returns the child's exit code.
/// </summary>
int RelaunchElevated(string[] mainArgs)
{
    Console.WriteLine("elevation required — approving the UAC prompt re-runs this command as administrator");
    string capture = Path.Combine(Path.GetTempPath(), $"onesettings-cadence-{Guid.NewGuid():N}.log");
    var psi = new ProcessStartInfo
    {
        FileName = Environment.ProcessPath,
        Arguments = QuoteArguments(mainArgs.Append("--elevated-out").Append(capture)),
        Verb = "runas",
        UseShellExecute = true,
    };
    try
    {
        using Process p = Process.Start(psi);
        p.WaitForExit();
        if (File.Exists(capture)) Console.Out.Write(File.ReadAllText(capture));
        return p.ExitCode;
    }
    catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) // ERROR_CANCELLED
    {
        Console.Error.WriteLine("elevation declined (UAC cancelled) — nothing was changed");
        return 3;
    }
    catch (Win32Exception ex)
    {
        Console.Error.WriteLine($"elevation failed: {ex.Message} (0x{ex.NativeErrorCode:X}) — nothing was changed");
        return 3;
    }
    finally
    {
        try { File.Delete(capture); } catch { /* best effort */ }
    }
}

string QuoteArguments(IEnumerable<string> args) =>
    string.Join(" ", args.Select(a =>
        a.Length == 0 || a.Contains(' ') ? "\"" + a.Replace("\"", "\"\"") + "\"" : a));

void AttachOutputTee(string path)
{
    var file = new StreamWriter(path, append: false) { AutoFlush = true };
    Console.SetOut(new TeeWriter(Console.Out, file));
    Console.SetError(new TeeWriter(Console.Error, file));
}

TimeSpan ParsePt(string pt) => System.Xml.XmlConvert.ToTimeSpan(pt ?? "PT0S");

string Fmt(TimeSpan? t) => t is { } v ? $"{IntervalParser.ToHuman(v)} ({IntervalParser.ToTaskForm(v)})" : "none";

string SidToFriendly(string sid) => sid?.Trim().ToUpperInvariant() switch
{
    "S-1-5-18" => "SYSTEM", "S-1-5-19" => "LOCAL SERVICE", "S-1-5-20" => "NETWORK SERVICE",
    _ => null,
};

string DescribeResult(int r) => r switch
{
    0 => "0x0 (success)",
    267009 => "0x41301 (task currently running)",
    267011 => "0x41303 (task has not yet run)",
    267014 => "0x41306 (task terminated on request)",
    _ => $"0x{r:X} ({r})",
};

/// <summary>Writes to both the console and the capture file the elevated parent reads back.</summary>
internal sealed class TeeWriter : TextWriter
{
    private readonly TextWriter _console;
    private readonly TextWriter _file;
    public TeeWriter(TextWriter console, TextWriter file) { _console = console; _file = file; }
    public override Encoding Encoding => _console.Encoding;
    public override void Write(string value) { _console.Write(value); _file.Write(value); }
    public override void WriteLine(string value) { _console.WriteLine(value); _file.WriteLine(value); }
    public override void WriteLine() { _console.WriteLine(); _file.WriteLine(); }
    public override void Flush() { _console.Flush(); _file.Flush(); }
}
