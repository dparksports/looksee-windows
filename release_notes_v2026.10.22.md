# LookSee v2026.10.22 — the Process Monitor action set, natively

Who's Talking now carries **the exact AutoCommand Process Monitor functionality**, copied natively (AutoCommand itself is untouched and not required):

## Right-click any row

- **⛔ Block remote IP / ✅ Unblock** — the same 2-rule (outbound TCP+UDP) `AC-BLOCK` scheme AutoCommand uses, so either app's Blocks/unblock manages the other's rules. Provenance (process, PID, bytes, SNI, time) is written into the rule description, visible in wf.msc. Blocked destinations wear a **⛔** in the grid.
- **⛔ Block process / ✅ Unblock** — 1 outbound rule on the exe's full path; arms even if the process already exited (blocked on its NEXT run). Carries the svchost/taskhostw and Windows-component warnings verbatim.
- **💀 Kill process** — AutoCommand's exact flow, including the stale-PID-reuse guard.
- **🔎 Trace this instance** — the PID Inquiry window: recorded parent chain, command line, provenance.
- **🚫 Ignore everywhere** — one click covers both ignore lists; managed (and reversible) from the new **🔕 Ignore lists…** editor.
- **📋 Copy row as JSON**.

Confirmations are AutoCommand's too: the checkbox dialog with **per-class "don't ask again"** (silencing the routine IP confirm never silences the Microsoft-infrastructure or service-host warnings), resettable from Ignore lists….

## Also in this release

- **🚑 Restore Internet** — the panic button in the status bar: disables every LookSee/AutoCommand block rule at once, flushes the DNS cache, nothing deleted.
- **⚪ zero-reply lens** — the TX-only checkbox, AutoCommand semantics: the live count shows on the chip before you switch it on; the grid narrows to conversations that sent and never heard one word back; per-instance PIDs stay visible; unchecking restores the exact prior list.
- **⇄ Import from AutoCommand** — one-time, one-way, read-only carry-over of your curated ignore lists (first run + button); silent when AutoCommand isn't installed.
- **Fix**: `ignored_processes.txt` (and the new `confirm_prefs.txt`) now resolve next to the exe — previously they followed the working directory, which could silently load an empty ignore list.

## Install

Download `LookSee-v2026.10.22-win-x64.zip` below, unzip anywhere, right-click `LookSee.exe` → **Run as administrator**. Checksums in `SHA256SUMS.txt`.

Made with ❤️ in California · Apache 2.0 · © 2026 Dan Park, magicpoint.ai
