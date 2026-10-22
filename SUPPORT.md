# Getting help & giving feedback

LookSee is built and maintained by one person ([Dan Park](https://magicpoint.ai)), so every channel below is designed to land your message where it can actually be acted on.

## Pick your lane

| I want to… | Go here |
|---|---|
| 💬 **Say hello, ask how something works** | [Discussions → General](../../discussions/categories/general) |
| ❤️ **Send kudos / share what you caught** | [Discussions → Show and tell](../../discussions/categories/show-and-tell) |
| 🐛 **Report a bug** | [The bug report form](../../issues/new?template=bug_report.yml) — it asks for the few facts that make a report fixable |
| 💡 **Suggest a feature** | [Discussions → Ideas](../../discussions/categories/ideas) — post the *problem* you're trying to solve; ideas that gather 👍 become issues |
| 🔒 **Report a security problem** | **Privately** — see [SECURITY.md](SECURITY.md). Please never open a public issue for these |

## Good to know

- **Bugs over guesses.** If something looks off, the fastest path is the bug form: it captures your Windows build, the app build, the tab, and points you at the readable JSON/text files on disk that speed up diagnosis.
- **Something feels stuck after a decrypt session, telemetry pins or a block?** Every change is reversible from where you made it: stop a decrypt session in Who's Talking (proxy and QUIC rule come back instantly), un-pin domains in Black Hole, right-click the row again to unblock — or hit the 🚑 **Restore Internet** button in the status bar, which disables every LookSee/AutoCommand block rule at once and flushes the DNS cache for you.
- **Security issues are different.** Anything that could let malware or another user abuse LookSee's own machinery goes to private reporting ([SECURITY.md](SECURITY.md)).

## Before you report: the two-minute checks

1. LookSee needs **Run as administrator** to see system processes — if rows look sparse, that's usually why.
2. The **Recorder** tab explains the history engine's state; if "yesterday" seems missing, check there first.
3. Everything the app remembers is a readable file — [TECHNICAL_NOTES.md](docs/TECHNICAL_NOTES.md) lists every path, so you can attach exactly the relevant one.
