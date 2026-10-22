// BITS Transfers engine self-test — offline, synthetic, byte-identical to
// the shipped code (sources are linked from the app project). Message
// strings below are the REAL events captured from this machine's
// Bits-Client log on 2026-10-15 (Chrome Component Updater + Font
// Download), so the parser is pinned against genuine shapes, not mocks
// of my own invention.
using System;
using System.IO;
using System.Text.Json;
using LookSee.Models;
using LookSee.Services;

int failures = 0;
void Check(string name, bool pass, string evidence)
{
    Console.WriteLine($"{(pass ? "PASS" : "FAIL")}  {name}{(pass || evidence.Length == 0 ? "" : "  — " + evidence)}");
    if (!pass) failures++;
}

// ─────────────────────────────────────────────────────────────────────
// 1. Message parsing (real 2026-10-15 event shapes)
// ─────────────────────────────────────────────────────────────────────
var t0 = new DateTime(2026, 10, 15, 18, 53, 45, DateTimeKind.Utc);

var created = BitsWatcherService.ParseMessage(3, t0,
    "The BITS service created a new job.\n" +
    "Transfer job: Chrome Component Updater\n" +
    "Job ID: {1197a48c-f1f2-46e7-9840-0986435c79c1}\n" +
    "Owner: Z690\\honey\n" +
    "Process Path: C:\\Users\\honey\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe\n" +
    "Process ID: 19716");
Check("parse EID3 jobId", created?.JobId == "1197a48c-f1f2-46e7-9840-0986435c79c1", created?.JobId ?? "null");
Check("parse EID3 name", created?.JobName == "Chrome Component Updater", created?.JobName ?? "null");
Check("parse EID3 owner", created?.Owner == "Z690\\honey", created?.Owner ?? "null");
Check("parse EID3 creator image", created?.CreatorImage?.EndsWith("chrome.exe") == true, created?.CreatorImage ?? "null");
Check("parse EID3 creator pid", created?.CreatorPid == 19716, created?.CreatorPid.ToString() ?? "null");

var started = BitsWatcherService.ParseMessage(59, t0.AddSeconds(13),
    "BITS started the Chrome Component Updater transfer job that is associated with the \n" +
    "http://edgedl.me.gvt1.com/edgedl/diffgen-puffin/bjbcblmd/609fdc90 URL.");
Check("parse EID59 url", started?.Url == "http://edgedl.me.gvt1.com/edgedl/diffgen-puffin/bjbcblmd/609fdc90", started?.Url ?? "null");
Check("parse EID59 name-from-prose", started?.JobName == "Chrome Component Updater", started?.JobName ?? "null");

var stopped = BitsWatcherService.ParseMessage(60, t0.AddSeconds(19),
    "BITS stopped transferring the Chrome Component Updater transfer job that is associated with the \n" +
    "http://edgedl.me.gvt1.com/edgedl/diffgen-puffin/bjbcblmd/609fdc90 URL. The status code is 0x0.");
Check("parse EID60 status", stopped?.StatusCode == "0x0", stopped?.StatusCode ?? "null");

var done = BitsWatcherService.ParseMessage(4, t0.AddSeconds(21),
    "The transfer job is complete.\nUser: Z690\\honey\nTransfer job: Chrome Component Updater\n" +
    "Job ID: {1197a48c-f1f2-46e7-9840-0986435c79c1}\nOwner: Z690\\honey\nFile count: 1");
Check("parse EID4 file count", done?.FileCount == 1, done?.FileCount.ToString() ?? "null");
Check("parse EID4 jobId", done?.JobId == "1197a48c-f1f2-46e7-9840-0986435c79c1", done?.JobId ?? "null");

var fontJob = BitsWatcherService.ParseMessage(59, t0.AddHours(2),
    "BITS started the Font Download transfer job that is associated with the https://fs.microsoft.com/fs/windows/config.json URL.");
Check("parse https url", fontJob?.Url == "https://fs.microsoft.com/fs/windows/config.json", fontJob?.Url ?? "null");

var noise = BitsWatcherService.ParseMessage(313, t0,
    "The Network List Manager Cost Interface is reporting no network connectivity. BITS will try to retrieve the network state again at a later time.");
Check("313 idle poll ignored", noise == null, "should not produce a keyable event");

// ─────────────────────────────────────────────────────────────────────
// 2. URL split + status decode
// ─────────────────────────────────────────────────────────────────────
var (host, port) = BitsWatcherService.SplitUrl("http://edgedl.me.gvt1.com/edgedl/x");
Check("splitUrl http port 80", host == "edgedl.me.gvt1.com" && port == 80, $"{host}:{port}");
var (h2, p2) = BitsWatcherService.SplitUrl("https://fs.microsoft.com/fs/windows/config.json");
Check("splitUrl https port 443", h2 == "fs.microsoft.com" && p2 == 443, $"{h2}:{p2}");
Check("decodeStatus 0x0", BitsWatcherService.DecodeStatus("0x0") == "completed ok", BitsWatcherService.DecodeStatus("0x0"));
Check("decodeStatus 404", BitsWatcherService.DecodeStatus("0x80190194").Contains("404"), BitsWatcherService.DecodeStatus("0x80190194"));

// ─────────────────────────────────────────────────────────────────────
// 3. Stitching + stats + persistence (isolated dir, enrichment off)
// ─────────────────────────────────────────────────────────────────────
string tempDir = Path.Combine(Path.GetTempPath(), "bits-selftest-" + Guid.NewGuid().ToString("N")[..8]);
BitsWatcherService.UseBitsDirForTest(tempDir);
using var svc = new BitsWatcherService { EnrichmentEnabled = false };

svc.Apply(created);
svc.Apply(started);
svc.Apply(stopped);
svc.Apply(done);
svc.Apply(fontJob);   // different job (name-only key), no EID3 — must still stand alone

var jobs = svc.JobsSnapshot();
Check("two jobs stitched", jobs.Count == 2, $"{jobs.Count} rows");
var chrome = jobs.FirstOrDefault(j => j.Name == "Chrome Component Updater");
Check("chrome job host", chrome?.Host == "edgedl.me.gvt1.com", chrome?.Host ?? "null");
Check("chrome job port", chrome?.Port == 80, chrome?.Port.ToString() ?? "null");
Check("chrome job status", chrome?.StatusText == "completed ok", chrome?.StatusText ?? "null");
Check("chrome job creator", chrome?.CreatorPid == 19716, chrome?.CreatorPid.ToString() ?? "null");
Check("chrome timeline 4 real + 1 synthetic event", chrome?.Timeline.Count == 5
      && chrome.Timeline.Count(t => t.EventId == 4) == 2   // real EID4 + synthetic "delivered, paths unknown" note
      && chrome.Timeline.Any(t => t.Text.Contains("delivered")), chrome?.Timeline.Count.ToString() ?? "null");

var stats = svc.StatsSnapshot();
var chromeStat = stats.FirstOrDefault(s => s.Host == "edgedl.me.gvt1.com");
Check("stat row per (creator,host)", chromeStat != null && chromeStat.JobCount == 1, chromeStat == null ? "missing" : chromeStat.JobCount.ToString());
Check("stat creator image", chromeStat?.CreatorImage?.EndsWith("chrome.exe") == true, chromeStat?.CreatorImage ?? "null");

string jobsLog = Path.Combine(tempDir, "jobs.jsonl");
Check("jobs.jsonl persisted once", File.Exists(jobsLog) && File.ReadAllLines(jobsLog).Length == 1,
    File.Exists(jobsLog) ? File.ReadAllLines(jobsLog).Length + " lines" : "missing");
string persisted = File.Exists(jobsLog) ? File.ReadAllText(jobsLog) : "";
Check("persist has metadata", persisted.Contains("Chrome Component Updater") && persisted.Contains("gvt1"), "");
Check("persist has NO content/preview fields", !persisted.Contains("\"Preview") && !persisted.Contains("\"Content"), "content leaked into export");

// ─────────────────────────────────────────────────────────────────────
// 4. Reason catalog verdicts
// ─────────────────────────────────────────────────────────────────────
var explained = BitsReasonCatalog.Explain(chrome);
Check("chrome reason Normal", explained?.Verdict == "Normal", explained?.Verdict ?? "null");
Check("chrome reason names Chrome", explained?.Text.Contains("gvt1") == true, explained?.Text ?? "null");

var odd = new BitsJobItem
{
    JobId = "test-guid",
    Name = "totally unknown job",
    CreatorImage = @"C:\Users\honey\AppData\Local\Temp\upd.exe",
    CreatorPid = 4242,
    Host = "weird.example.com"
};
var oddExplained = BitsReasonCatalog.Explain(odd);
Check("unknown creator/host → Review", oddExplained?.Verdict == "Review", oddExplained?.Verdict ?? "null");
Check("unattributed text has pointers", oddExplained?.Text.Contains("Temp") == true, oddExplained?.Text ?? "null");

var uploadToKnown = new BitsJobItem { Name = "Chrome Component Updater", CreatorImage = @"C:\x\chrome.exe", Host = "edgedl.me.gvt1.com", Direction = "Upload" };
var upExplained = BitsReasonCatalog.Explain(uploadToKnown);
Check("upload overrides to Review even on known host", upExplained?.Verdict == "Review", upExplained?.Verdict ?? "null");
Check("upload note mentions UPLOAD", upExplained?.Text.Contains("UPLOAD") == true, upExplained?.Text ?? "null");

// ─────────────────────────────────────────────────────────────────────
// 5. Frequency math
// ─────────────────────────────────────────────────────────────────────
Check("ComputeCv constant → 0", Math.Abs((BitsJobStat.ComputeCv(new[] { 10.0, 10, 10 }) ?? 1)) < 1e-9, "");
double? cv = BitsJobStat.ComputeCv(new[] { 10.0, 20, 40 });
Check("ComputeCv spread → >0", cv is > 0.5, cv?.ToString() ?? "null");
Check("ComputeCv needs 3 values", BitsJobStat.ComputeCv(new[] { 10.0, 20 }) == null, "should be null");

var stat = new BitsJobStat { CreatorImage = @"C:\x\chrome.exe", Host = "h" };
var baseTime = new DateTime(2026, 10, 15, 0, 0, 0, DateTimeKind.Utc);
for (int i = 0; i < 5; i++) stat.Add(baseTime.AddMinutes(10 * i), isUpload: false);
Check("stat count", stat.JobCount == 5, stat.JobCount.ToString());
Check("stat regular CV small", stat.IntervalCv is < 0.01, stat.IntervalCv?.ToString("0.000") ?? "null");
Check("stat daily buckets", stat.Daily.Count == 1 && stat.Daily["2026-10-15"] == 5, stat.Daily.Count.ToString());

// ─────────────────────────────────────────────────────────────────────
// 6. Firewall verdict branches (pure)
// ─────────────────────────────────────────────────────────────────────
var fw = new BitsFirewallContextService();

var v1 = BitsFirewallContextService.BuildSummary(new BitsFirewallContextService.Facts { OutboundDefaultAllow = true, ProfilesChecked = "public" });
Check("fw allow-default → bypassed", v1.Bypassed && v1.Headline.Contains("Allow"), v1.Headline);

var v2 = BitsFirewallContextService.BuildSummary(new BitsFirewallContextService.Facts
{
    OutboundDefaultAllow = false,
    ProfilesChecked = "private",
    AllowRuleCount = 2,
    AllowRuleNames = new System.Collections.Generic.List<string> { "Rule A (service: BITS)", "Rule B (svchost)" }
});
Check("fw default-deny + allow rules → bypassed", v2.Bypassed && v2.Detail.Contains("Rule A"), v2.Headline);

var v3 = BitsFirewallContextService.BuildSummary(new BitsFirewallContextService.Facts { OutboundDefaultAllow = false, ProfilesChecked = "domain" });
Check("fw default-deny no rules → not bypassed", !v3.Bypassed, v3.Headline);

var v4 = BitsFirewallContextService.BuildSummary(new BitsFirewallContextService.Facts { Error = "COM unavailable" });
Check("fw error surfaced", !v4.Bypassed && v4.Headline.Contains("unavailable"), v4.Headline);

var v5 = BitsFirewallContextService.BuildSummary(null);
Check("fw null facts → graceful", v5.Headline.Contains("not checked"), v5.Headline);

// ─────────────────────────────────────────────────────────────────────
// 7. Export purity: serialized model carries metadata only
// ─────────────────────────────────────────────────────────────────────
var sample = new BitsJobItem { JobId = "g", Name = "n", Host = "h", Url = "http://h/x" };
sample.Files.Add(new BitsFileRef { RemoteName = "http://h/x", LocalName = @"C:\t\x", LocalSize = 5, Sha256 = "abc", HashStatus = "hashed" });
string json = JsonSerializer.Serialize(sample);
Check("model json has hash", json.Contains("\"Sha256\"") && json.Contains("abc"), "");
Check("model json has no content bytes", !json.Contains("\"Preview") && !json.Contains("\"ContentText\"", StringComparison.OrdinalIgnoreCase), "");

// ─────────────────────────────────────────────────────────────────────
// 8. Real channel replay (read-only; this machine only — skips elsewhere).
//    The full pipeline (reader → ParseRecord → Apply → stitch) over the
//    genuine Bits-Client log, including the 2026-10-15 jobs that motivated
//    the tab: 3× Chrome Component Updater → edgedl.me.gvt1.com and
//    Font Download → fs.microsoft.com.
// ─────────────────────────────────────────────────────────────────────
try
{
    var query = new System.Diagnostics.Eventing.Reader.EventLogQuery(
        "Microsoft-Windows-Bits-Client/Operational",
        System.Diagnostics.Eventing.Reader.PathType.LogName,
        "*[System[(EventID=3 or EventID=4 or EventID=59 or EventID=60)]]");
    int applied = 0;
    using var svcReal = new BitsWatcherService { EnrichmentEnabled = false };
    using (var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(query))
    {
        for (int i = 0; i < 8000; i++)
        {
            var r = reader.ReadEvent();
            if (r == null) break;
            var ev = BitsWatcherService.ParseRecord(r);
            if (ev != null) { svcReal.Apply(ev); applied++; }
            r.Dispose();
        }
    }
    Check("real log replay applied events", applied > 0, applied + " events");

    var realJobs = svcReal.JobsSnapshot();
    Check("real log stitched jobs", realJobs.Count > 0, realJobs.Count + " jobs");

    var gvt = realJobs.FirstOrDefault(j => j.Host?.Contains("gvt1") == true);
    Check("real log: Chrome Component Updater → gvt1.com host", gvt?.Name == "Chrome Component Updater", $"{gvt?.Name} → {gvt?.Host}");
    Check("real log: gvt1 job parsed creator/pid", gvt != null && gvt.CreatorPid > 0 && gvt.CreatorImage?.EndsWith("chrome.exe") == true,
        gvt == null ? "missing" : $"{gvt.CreatorImage} pid {gvt.CreatorPid}");
    Check("real log: gvt1 port 80", gvt?.Port == 80, gvt?.Port.ToString() ?? "null");

    var font = realJobs.FirstOrDefault(j => j.Name == "Font Download");
    Check("real log: Font Download → fs.microsoft.com:443", font?.Host == "fs.microsoft.com" && font.Port == 443,
        font == null ? "missing" : $"{font.Host}:{font.Port}");

    var realStats = svcReal.StatsSnapshot();
    Check("real log: pattern stat exists for gvt1", realStats.Any(s => s.Host?.Contains("gvt1") == true && s.JobCount >= 3),
        string.Join(", ", realStats.Where(s => s.Host?.Contains("gvt1") == true).Select(s => $"{s.CreatorDisplay}:{s.JobCount}")));
}
catch (Exception ex)
{
    Console.WriteLine($"SKIP  real-log replay (channel not readable here): {ex.Message}");
}

Console.WriteLine();
Console.WriteLine(failures == 0 ? "ALL BITS TRACE SELF-TESTS PASSED" : $"{failures} FAILURE(S)");
try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true); } catch { }
return failures == 0 ? 0 : 1;
