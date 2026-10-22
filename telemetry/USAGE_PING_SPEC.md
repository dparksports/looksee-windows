# Anonymous Daily Count — design spec (AutoCommand & Shields Up)

**Purpose:** count how many people run the apps each day — the usage evidence
an investor raise needs — with a design that contains **no identifiers
anywhere**: no account, no install GUID, no IP-derived value, no per-install
rows. Counting is genuinely anonymous, which keeps it outside GDPR's (and
every privacy law's) personal-data scope.

**One-line summary:** an **opt-in, off-by-default** daily count. Each
consenting install adds **1** to a daily aggregate counter, at most once per
day. The server stores daily totals only — nothing that could ever be traced
to a person, even by us, even after a full database leak.

## What the client sends

```json
POST /v1/ping
{ "a": "autocommand",          // app: autocommand | shields-up
  "v": "261015",               // build date, compact — derived from the app version's date (app versions stay 2026.10.NN)
  "o": "10.0.26300" }          // Windows OS build
```

That is the entire payload. **No identifier of any kind — not even a random
id.** No hostnames, process names, command lines, hardware ids, user
identifiers, behavioral events, and no IP retention.

## How "once per day" works

Enforced **client-side**: the app records the last UTC day it pinged
(`HKCU\Software\AutoCommand\UsagePing\LastSentDay`) and skips if today was
already counted. So each consenting install contributes at most one
increment per UTC day, and `daily count ≈ daily active installs`.

Known edges, accepted deliberately: reinstalling or wiping app settings lets
an install count twice that day; a user on two machines counts as two
installs (correctly). The alternative — a persistent install id — is exactly
what this design exists to avoid.

## Consent model (kept, even though the data is anonymous)

- **Off by default.** Nothing is sent until the user explicitly says yes.
- **Three states** in `HKCU\Software\AutoCommand\UsagePing\Consent`:
  `ask` (default) → dialog offered at most **3 times**, then never again;
  `yes`; `no`.
- The dialog states in plain English exactly what is sent, that no id of any
  kind is included, and how to withdraw (delete the registry key).
- The dialog remains for two reasons: it is good product hygiene for a
  privacy tool, and the registry writes are terminal-equipment storage under
  ePrivacy Art. 5(3) — consent keeps that clean too.

## Server design (Cloudflare Worker + D1)

- **One aggregate table** (`daily_rollup`): `(day, app, country, version) →
  count`. No per-install table exists. See `schema.sql`.
- Country comes from `request.cf.country` — Cloudflare derives it at the edge;
  **our code never reads, stores, or forwards an IP address**. The guarantee
  is architectural, not a promise.
- No secrets beyond `ADMIN_TOKEN` for the stats endpoint. No salt (nothing to
  hash), no cron (nothing personal to purge). Aggregates are kept
  indefinitely because they contain no personal data.

### Public surface (the growth loop)

Because the data is anonymous by construction, it is publishable by design:

| Route | What |
|---|---|
| `GET /` | **The community graph page** — self-contained HTML (no external assets, no tracking): stat cards, a 90-day daily-actives chart, top countries, download buttons for both apps, and share buttons (copy link / X / Reddit / Hacker News / email). This is the link users share with peers. |
| `GET /v1/graph` | Public JSON (CORS `*`, 5-min cache): daily series (365d), top-10 countries, totals. Powers the page; usable by anything else. |
| `GET /v1/badge` | Plain text: yesterday's opt-in daily actives. |
| `GET /v1/stats` | Admin JSON (bearer `ADMIN_TOKEN`): adds per-app split + version adoption. |

In-app entry points (AutoCommand): a "See the live community graph →" link on
the consent dialog and "📈 Community graph" / "🔗 Share AutoCommand" buttons in
Settings → Application Information (share copies the graph-page URL, falling
back to the GitHub releases link until the endpoint is deployed). The loop
users see: the number grows when peers install → the graph proves it → one
click shares the link that grows it.

## Metrics this yields

| Metric | How it's computed |
|---|---|
| Daily actives (opt-in) | `SUM(pings)` per day per app |
| Version adoption | rollup grouped by version (30-day window) |
| Country distribution | rollup grouped by country (edge-derived, never an IP) |
| Opt-in rate (directional) | daily actives vs. release downloads |

**Deliberate trade-off — no MAU/WAU/retention cohorts.** Without identifiers
there is no way to dedupe across days or cohort first-seen installs, so
week-over-week retention is unmeasurable by design. Decision recorded in
`../../ADVISOR-CONTEXT.md` (#6): zero-identifier anonymity was chosen over
cohort metrics; the compliance surface drops to zero and the privacy story
("no IDs, ever") becomes absolute. Report numbers honestly as
"opt-in daily actives."

## Security & abuse model

**Trust model:** the client is open source, so it can hold no secret — the
count endpoint is unauthenticated *by design*. Everything downstream assumes
the endpoint receives hostile input.

| Threat | Defense | Status |
|---|---|---|
| Browser-based count inflation (malicious page POSTing from visitors) | `Content-Type: application/json` required — forces a CORS preflight the endpoint never grants, closing the "simple request" path | in worker |
| Garbage/hostile payload values | App allowlist; every field length-capped; country regex-validated (`^[A-Z]{2}$` else `??`) | in worker |
| SQL injection | Every query is static SQL with bound parameters — no string interpolation | in worker |
| Stored XSS via the public page | All data-driven strings HTML-escaped before insertion; country values server-validated; the page loads zero external assets | in worker page |
| Single-IP flood inflation | WAF rate-limit rule on `POST /v1/ping` (recipe in server/DEPLOY.md #Hardening; needs a custom domain) | deploy-time |
| Distributed/manual inflation (`curl` loops) | **Accepted residual risk.** Mitigated by the plausibility anchor: opt-in DAU can never legitimately exceed cumulative downloads (weekly cross-check vs. `pull-github-metrics.ps1`); anomalies are annotated in the data room, never silently deleted | process |
| Small-number deanonymization (rare country × version) | Public `/v1/graph` suppresses country rows under 5 counts; admin feed keeps detail behind `ADMIN_TOKEN` | in worker |
| `ADMIN_TOKEN` leak | Random 36-byte value, gitignored file, rotation one-liner; guards reads of anonymous aggregates only | deploy-time |
| Cloudflare API token | Least-privilege scopes (Workers Scripts:Edit, D1:Edit), single account, deletable after setup | deploy-time |
| Endpoint hijack (lost/renamed worker) | Client sends nothing sensitive and ignores response bodies — blast radius is a dropped count, not data | by design |
| DoS / cost runaway | Free tier caps fail closed (counting pauses; no spend); client retries silently on next launch | by design |

**The integrity story for investors** matters as much as the confidentiality
story: because the count is spoofable in principle, the data room pairs the
raw D1 exports with the methodology (this spec) and the downloads ceiling
cross-check — "here is exactly how spoofable it is, and here is the
independent anchor." That converts a weakness into a credibility signal.

## Legal footing (summary — not legal advice)

- **GDPR/ePrivacy:** the payload contains no identifier and no IP-derived
  value; the database contains only aggregates that cannot be related to any
  natural person by anyone, including us (Recital 26 — genuinely anonymous
  data is out of scope). Consent is still collected (see above) as product
  hygiene and for the ePrivacy terminal-equipment storage of the throttle
  state. There is no personal-data inventory to maintain, no rights
  machinery, no transfer analysis — the obligations never trigger.
- **CCPA/state laws:** below every applicability threshold regardless; no
  identifiers exist to be "personal information" in any case.
- If a future feature ever reintroduces an identifier (account, sync,
  purchase), that feature — not this counter — carries its own compliance
  analysis.

## Ship rules

1. The count code **and** the README/PRIVACY.md changes ship in the **same
   release**. Never one without the other.
2. The client no-ops unless the endpoint is configured (`UsagePingService.Endpoint`).
3. Document the endpoint hostname in TECHNICAL_NOTES so Black Hole users can
   verify the app does exactly what the dialog says.
4. Never add a field to the payload without rewriting this spec first — the
   spec is the contract.
