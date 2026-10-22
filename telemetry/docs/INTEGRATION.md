# Client integration guide (AutoCommand + Shields Up)

Status: **integrated in AutoCommand** (this workspace; the changed files
compile clean — the tree as a whole may transiently not build while other
views are mid-edit). Shields Up integration is the same three-file pattern
below.

## What was added to AutoCommand (this workspace)

| File | Role |
|---|---|
| `Services/UsagePingService.cs` | Consent state (HKCU\Software\AutoCommand\UsagePing), daily count with client-side once-per-UTC-day throttle, ask-at-most-3-times flow, `GraphPageUrl`/`ReleasesUrl` helpers. Inert while `Endpoint` is empty. **No identifier is ever sent — not even a random id.** |
| `Views/UsagePingConsentDialog.xaml(.cs)` | The one-time opt-in prompt (theme-aware, states exactly what is sent and that no id exists) + a "see the live community graph" link (appears only once the endpoint is deployed). |
| `App.xaml.cs` | One line: `_ = Services.UsagePingService.RunStartupFlowAsync();` after the sinkhole startup block. |
| `Views/SettingsView.xaml(.cs)` | Settings → Application Information: "📈 Community graph" (opens the public page) and "🔗 Share AutoCommand" (copies the page URL — or the releases link pre-deploy). |
| `PRIVACY.md` + README "What AutoCommand will not do" | Updated to describe the anonymous daily count — **must ship in the same release** as the count code. |

## To activate (5 minutes)

1. Deploy the receiver: `../server/DEPLOY.md` (~15 min, free tier).
2. In `Services/UsagePingService.cs`, set:
   ```csharp
   private const string Endpoint = "https://<your-worker>.workers.dev/v1/ping";
   private const string AppName  = "autocommand";   // "shields-up" in Shields Up
   ```
3. Build, run once, click **Yes** in the dialog, then verify the row landed:
   `curl -H "Authorization: Bearer <ADMIN_TOKEN>" https://<your-worker>/v1/stats`
4. Release — code + PRIVACY.md + README in the same tag (ship rule #1).

## Porting to Shields Up

Copy the two `UsagePing*` files (namespace change only), set
`AppName = "shields-up"`, swap the registry root to Shields Up's own key so
consent is per-app, and add the same one-line startup call to its
`App.xaml.cs`. The server already accepts `shields-up` in its allow-list.

## Before-you-release checklist

- [ ] `Endpoint` set to the deployed worker URL (service stays inert otherwise)
- [ ] PRIVACY.md + README changes included in the release tag
- [ ] Endpoint hostname documented in `docs/TECHNICAL_NOTES.md` (Black Hole users will look)
- [ ] `wrangler d1 execute usage-ping --remote --file=schema.sql` was run (else pings 500)
- [ ] Test: run app → Yes → `crash.log` stays empty → `/v1/stats` shows the day's count → restart app same day → no second increment (client-side daily throttle)
- [ ] Test the growth loop: open the worker root URL → graph page renders with the day's count → "Copy link" copies it → in-app Settings "📈 Community graph" opens it → "🔗 Share AutoCommand" copies it
- [ ] Start saving weekly `/v1/stats` snapshots to `../../fundraising/metrics/` — that is the daily-actives time series for the raise
- [ ] **Publish**: copy this `telemetry/` folder into the public app repository — PRIVACY.md and the consent dialog both reference it there ("verify, don't trust")
