# Security policy

LookSee is a visibility tool — it watches processes, connections and Windows settings, instruments TLS only for environments you explicitly opt in, and records history with Sysmon. Reports against the tool itself are taken seriously and handled privately.

## What counts as a security issue here

Broadly: anything that lets malware, an unprivileged user, or a remote party **bypass, abuse, or weaponize** LookSee's own machinery. For example:

- Weaknesses in the TLS keylog handling (`%LOCALAPPDATA%\LookSee\pytrace\sslkeys.log` — ACL bypass, leaking to other users, surviving app exit) or in the decrypted-traffic archive's ACLs
- Injecting a fake python environment or audit-hook payload that gets installed with elevated rights
- Getting the intercept stack (proxy, CA trust, QUIC rule) to run against a target you did not explicitly select, or to survive a crash without rollback
- Getting the Sysmon installer or the watchdog machinery to execute attacker-controlled content
- Crashes/hangs in the capture paths reachable from a non-admin context

"Windows itself has a flaw" or "this process I can see looks suspicious" are **not** security issues against LookSee — those belong in [Discussions](../../discussions) or a [bug report](../../issues/new?template=bug_report.yml).

## How to report

Prefer email to the address on the author's profile ([magicpoint.ai](https://magicpoint.ai)) with **"LookSee security"** in the subject. Include:

- what you found, in exact steps or a proof-of-concept if you have one
- the LookSee version (status bar, bottom right)
- your Windows build (`winver`)

You'll get an acknowledgment within a few days and a fix-first, disclose-later approach: releases carry the fix, then the report is credited (or kept private at your preference).

## Scope of the machine's own defenses

LookSee shows and (in two places you control) adjusts Windows settings. It is not antivirus, not a firewall manager, and not a substitute for patching — its job is to make what your machine does **visible**, so you can decide.
