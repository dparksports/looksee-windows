# LookSee privacy policy

**The short version: LookSee sends nothing. Not at startup, not on a timer,
not "anonymized" — nothing.**

There is no account, no login, no subscription check, no crash reporter that
phones home, and no usage counter configured. Everything the app learns about
your machine stays on your machine, in readable files you can open, back up,
or delete (the complete list is in [TECHNICAL_NOTES.md](docs/TECHNICAL_NOTES.md)).

## What about the network traffic it shows?

LookSee *observes* traffic — it reads the kernel's connection table, counts
packets on a socket of its own, and (only if you explicitly turn it on for a
specific program) decrypts that program's traffic using TLS session keys the
program itself wrote. Decrypted material is written to files under
`%LOCALAPPDATA%\LookSee\transmissions` on your disk only. Nothing is ever
uploaded.

## The optional count (currently not configured)

The code contains an opt-in, anonymous daily-count mechanism inherited from
the sibling project — one click of "Yes, count me in" would send a build
number and Windows version, with **no identifier of any kind**, at most once
a day. In LookSee it is **not configured and therefore completely inert**:
the question is never asked and nothing is ever sent. If that ever changes,
this page changes first.

## Admin permission

LookSee asks to run as administrator for one reason: the kernel only exposes
system-process connections and the Sysmon event channel to elevated readers.
The permission is used to read. The app's few write actions (telemetry pins,
Sysmon setup, python instrumentation) each happen only after you click the
button that says what they do.

## Deleting everything

Delete the folder you unzipped, plus `%LOCALAPPDATA%\LookSee` and
`C:\ProgramData\LookSee` if you used the Recorder or Windows Check-Ins.
That is the complete uninstall — there is no other state.
