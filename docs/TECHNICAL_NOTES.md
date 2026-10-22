# LookSee — Technical Notes

How LookSee delivers what the [README](../README.md) promises: the technologies behind each tab, the design rules they follow, and every place on disk the app writes. No marketing — just what runs, what it touches, and why.

LookSee is the watch-only lens distilled from [AutoCommand](https://github.com/dparksports/autocommand-windows) (same author). It contains no firewall management, no blocking, no AI-assistant bridge, and no settings beyond the theme toggle — by design.

---

## Design rules

1. **Zero-PowerShell core.** Monitoring talks to Windows directly — COM, WMI, and P/Invoke — never by spawning `powershell.exe`. Native command-line tools (`wevtutil`, `ipconfig`) are used only where Microsoft ships no COM or .NET surface, and always through one audited runner (`Helpers/ProcessRunner.cs`).
2. **Watch-first.** The app observes. Its only write actions — telemetry pins, Sysmon setup, python instrumentation, the Windows Check-Ins cadence — each happen after a button that says what it does, and each is reversible from the same screen.
3. **Verified downloads.** Auto-downloaded tools (Sysmon from `live.sysinternals.com`) must pass both a logged SHA256 check and a native `WinVerifyTrust` Authenticode verification; anything else is deleted, never executed.
4. **Plain, inspectable state.** Everything the app remembers is a readable JSON, JSONL, XML or text file (listed at the end), so you can back up, diff, or delete everything it knows.
5. **Looking never interrupts.** Feeds stay in the visual tree (visibility-toggled, never unloaded), so switching tabs never stops a recording; a feed runs until you stop it.

---

## Subsystem by subsystem

### Who's Talking (💬 — the Transmissions pipeline)

| Concern | Technology |
|---|---|
| Connection truth | `GetExtendedTcpTable` (IP Helper API) per address family — one syscall each, the whole table at a single kernel instant (replaced spawning `netstat.exe`, which also never showed IPv6 rows on some builds) |
| Capture | Raw-socket sniffer — `IOControlCode.ReceiveAll` (SIO_RCVALL, IP-level first with fallback) on raw IP sockets, one IPv4 plus a best-effort IPv6 socket; no WinPcap/Npcap dependency; per-session inbound/outbound tallies make a one-way capture visible in the UI banner instead of silently reading as "no replies" |
| PID attribution | Sysmon EID 3 via the service's own connect watcher feeding `TagFlow` — first-writer-wins |
| TLS decrypt | Keys from the keylog that instrumented pythons and/or `SSLKEYLOGFILE`-honoring apps wrote (Chromium/Electron, curl, git, OpenSSL/Python); flows run through the decryptor, then an HTTP/1.x stream decoder |
| Archive | One readable, greppable JSONL index per day under `%LOCALAPPDATA%\LookSee\transmissions`, full request/response bodies in `bodies\` when they decrypted, each row carrying a SHA-256 over both plaintext directions; day files prune after a retention window and the bodies folder rotates oldest-day directories under a size budget |
| Opt-in intercept | The "decrypt" session tooling (system proxy + per-target QUIC/UDP-443 netsh rule + local CA) journals every hook (`InterceptSystemHooks`), recovers them after a crash on next start, and restores all three on stop/app exit |

### Phone Bill (🧾)

`TrafficAggregationService` folds every finalized TCP flow from the shared capture into (process name → destination IP) rows with byte totals, a 24h bucket ring, and day-over-day history. Attached once at app start, so totals accumulate whenever any feed captures — the tab is just a viewer. Names resolved by the background reverse-DNS service with a persistent JSON cache; forward-DNS cache (`dns_forward_cache.json`, 60 min TTL) answers "where do they connect" for the Deliveries tab.

### Who Started It (🧬)

| Feed | Technology |
|---|---|
| Scheduled Tasks | taskhostw instance GUID on the command line correlated with Task Scheduler history (the channel is enabled once if off); COM-handler tasks get their ClassId resolved through `HKCR\CLSID\{…}\InprocServer32` to the handler DLL, flagged when unregistered; plain-English explanations from `Assets\known-tasks.json` (user-extensible) |
| Python | Opt-in instrumentation: two small files (`PyTraceHook_ac.py` + a `.pth` importer) written into a chosen environment's site-packages, tracked in a manifest, removable from the Instrument dialog; the hook reports spawn stacks and TLS session keys; nothing inside a venv is ever read for correlation and the interpreter binary is never touched |
| svchost Timeline | `SvchostAnalyzer.Core` (vendored in-repo at `svchost-watch\`, linked in-process) — spawn genealogy, connection timeline, destination classification, beacon detection over the Sysmon feed |

### Deliveries (📦)

Reads Windows' own `Microsoft-Windows-Bits-Client/Operational` event log and enumerates the BITS COM queue read-only; never creates, cancels or modifies jobs. Completed jobs append to readable files under `%LOCALAPPDATA%\LookSee\bits\` (metadata and per-file SHA-256 — never file content; content is read only by the explicit per-file preview window, in memory). "Does it bypass the firewall?" is answered by read-only `INetFwPolicy2` COM queries (default outbound action + scoped allow rules) — three honest layers, no guessing.

### Black Hole (🚫)

Telemetry knowledge base in `Assets\telemetry_rules.json` (detection, state probe, opt-out, revert per app). Pins point known telemetry domains at a local listener (sinkhole mode) or away entirely; every denied attempt is observed and persisted as plain JSONL (`telemetry_proof.jsonl`) with aggregate counters — "I opted out; did they stop?" answered with evidence. Fully reversible; state snapshots in `telemetry_state.json` before each change.

### Defender (🦠)

Live `MsMpEng` resource sampling every 2s via WMI formatted perf data (CPU normalized to machine capacity, private working set, 5-minute ring for the sparkline), Defender's own operational event log as a live activity feed (scans pairable by ID), plus a preferences card reading every data-sharing setting the product exposes. Read-and-show; the tab's opt-outs go through the same rules engine as Black Hole.

### Privacy (🔐)

Every Windows telemetry/data-sharing switch in one list, read live. Two deliberately separate flows: corporate privacy-request letters (CCPA/CPRA and the state-statute family — requests about data vendors process *for* Microsoft go through Microsoft, and the generated letter says exactly which Defender data categories are in scope) and a local tracker for what you sent, when.

### Windows Check-Ins (🔄 — the OneSettings cadence)

Two faces over one engine (`OneSettingsCadence/OneSettingsCadence.Core`, linked in-process; the CLI keeps its own `Main()` and builds separately). It slows the Windows inbox task `\Microsoft\Windows\Flighting\OneSettings\RefreshCache` — the remote-config fetch that runs ~20-40×/day as SYSTEM — to a user-chosen interval, and restores stock behavior afterwards. Task Scheduler is reached over the `Schedule.Service` COM interface, never through `schtasks.exe`.

| Concern | Technology |
|---|---|
| Cadence proof | Reads the Task Scheduler operational channel and compares observed launches against the expected cadence — each launch bucketed by why the scheduler says it fired (timer / event / logon / manual-API); WNF-aware so excess 107s with WNF triggers installed are theirs, not a reverted cadence |
| `set` | Timestamped backup of the live task XML under `C:\ProgramData\LookSee\onesettings-cadence\backups\`, re-register, re-read, compare — any mismatch rolls back from the backup (a failed rollback exits 4 and says so loudly) |
| Watchdog | Optional SYSTEM task (daily 03:30 + logon) re-applies the saved cadence only when the live task drifted — Windows servicing rewrites inbox task definitions; `restore` removes the watchdog so it cannot fight the restored stock definition |
| Live external starts | `EventLogWatcher` over the scheduler channel flags launches that fired with no trigger event (something called `Run()` directly), confirmed on a 3 s deadline; EID 129 supplies the PID, Sysmon EID 3/5 join destinations |
| Audit | Every change is one JSONL line in `onesettings-cadence\audit.jsonl` |

Honest limits, stated in the tab itself: launches started by other actors are counted and named but not preventable, and a component that fetches in-process from a service bypasses the scheduler entirely — it would surface as svchost traffic in Who's Talking.

### Recorder (⏺)

| Concern | Technology |
|---|---|
| Status facts | Service state via `sc query`, event-channel health and 24h event counts via `wevtutil`/`Get-WinEvent`, active config hash from `HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters` |
| Recommended config | Generated `sysmon_config.xml` capturing process creations (ID 1), network connections (ID 3) and DNS queries (ID 22); applied with `Sysmon64 -c` on existing installs |
| Install/repair | Download from `live.sysinternals.com` behind the SHA256 + `WinVerifyTrust` gates, `Sysmon64 -i -accepteula`; inconsistent-state repair removes stale manifest registrations (reboot + auto-retry when Windows holds the registration) |
| Archive | The live channel is a rolling window (sized up from the 64 MB default at startup); `%LOCALAPPDATA%\LookSee\sysmon-archive` backfills everything the channel still holds, follows it live, prunes past retention — this is what makes short-lived processes traceable for weeks |
| PID Inquiry | Window for "what is this PID?": recorded create-events, live modules, the svchost identity service, and provenance hints — read-only |

### Watchdog (status bar)

The Security Enforcer, minus its former firewall-drift half: WMI event subscriptions on `Win32_NetworkAdapter` (zero polling cost), an SSTP guard re-asserting stopped+disabled, kernel-debug transport checks (`bcdedit` reads/writes, KDNIC removal via `SetupAPI` P/Invoke), privileged-scheduled-task review with a per-task whitelist, and Windows toast notifications (`Windows.UI.Notifications`) through the tray notifier. Cadence in `check_interval.txt` next to the exe.

### Platform

* **.NET 10 (WPF)**, Segoe UI, dark/light theme swapped live through DynamicResource brushes (choice remembered in `HKCU\Software\LookSee`).
* The svchost engine and the OneSettings cadence engine are vendored in-repo and ProjectReferenced in-process — no child exes (SmartScreen hard-blocks those on download extracts).
* The app icon is generated: `Assets/generate_icon.py` (Python + Pillow + numpy) renders the candidates and the size sheet into `Assets/icons/`.

---

## What the app writes on your disk

| Path | Purpose |
|---|---|
| `C:\ProgramData\LookSee\onesettings-cadence\state.json` | Saved desired cadence for the inbox RefreshCache task |
| `C:\ProgramData\LookSee\onesettings-cadence\backups\RefreshCache-*.xml` | Timestamped task-XML backups (`restore` re-registers these) |
| `C:\ProgramData\LookSee\onesettings-cadence\audit.jsonl` | Audit trail: every change with old→new values and the backup filename |
| `C:\ProgramData\LookSee\rdap-cache.json` | Destination-owner lookups (RDAP), machine-wide cache |
| `%LOCALAPPDATA%\LookSee\transmissions\` | Who's Talking archive — daily JSONL index + decrypted bodies |
| `%LOCALAPPDATA%\LookSee\pytrace\` | Python feed state — traces, TLS keylog (current-user-only ACL, rotated at 5 MB, `.old` deleted at exit), instrumentation manifest |
| `%LOCALAPPDATA%\LookSee\bits\` | Deliveries state — `jobs.jsonl` (metadata per completed job) + `bits-stats.json` rollups |
| `%LOCALAPPDATA%\LookSee\sysmon-archive\` | The Recorder's archive (backfill + live-follow + retention) |
| `%LOCALAPPDATA%\LookSee\intercept\` | Opt-in intercept session state (CA, journal) |
| `%LOCALAPPDATA%\LookSee\agents\` | *(unused in LookSee — reserved path from the shared lineage)* |
| `<app>\telemetry_proof.jsonl` | Every denied telemetry attempt the sinkhole observed |
| `<app>\telemetry_state.json` | Snapshots of the settings changed by opt-outs |
| `<app>\dns_forward_cache.json` | Forward-DNS cache for Deliveries' "where do they connect" |
| `<app>\ignored_processes.txt` | Feeds' ignore list (the raw feeds enforce it) |
| `<app>\check_interval.txt` | Watchdog cadence |
| `HKCU\Software\LookSee` | Theme choice |
| `HKCU\Software\LookSee\UsagePing` | *(inert — the optional count is not configured; the key is never created)* |

Everything is plain, readable, and deletable. Deleting the app folder plus `%LOCALAPPDATA%\LookSee` and `C:\ProgramData\LookSee` is the complete uninstall.

---

## Offline self-tests

Every engine with pure logic carries an offline self-test (no network, no writes outside temp, no elevation):

```powershell
dotnet run --project NetWatchSelfTest          # dual-family TCP table + Sysmon archive engine
dotnet run --project BitsTraceSelfTest         # BITS parse/apply/stat + firewall-context verdicts
dotnet run --project TaskAttributionSelfTest   # taskhostw GUID → task attribution
dotnet run --project PyTraceSelfTest           # audit-hook record parsing
dotnet run --project OneSettingsCadenceSelfTest # cadence parser/transform/drift (43 checks)
```

The app collects **no usage telemetry** — nothing in it sends data anywhere on its own.
