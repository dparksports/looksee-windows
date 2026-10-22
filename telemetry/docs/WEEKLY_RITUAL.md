# The weekly ritual — automated

The traction time series an investor raise needs: opt-in daily actives from
the usage count, cumulative GitHub downloads, and the plausibility check that
keeps the two honest. One script, one scheduled task, zero discipline needed.

## The automated path (recommended)

```powershell
# one-time: register the weekly task (runs every Monday 09:00, catches up
# automatically if the machine was off at that moment - StartWhenAvailable)
powershell -ExecutionPolicy Bypass -File telemetry\server\snapshot-usage.ps1 -Install

# remove it again
powershell -ExecutionPolicy Bypass -File telemetry\server\snapshot-usage.ps1 -Uninstall
```

Every week the task runs `snapshot-usage.ps1 -Quiet`, which:

1. Pulls `/v1/stats` with the `ADMIN_TOKEN` from `telemetry/server/admin-token.txt`.
2. Sums real GitHub download counts across all releases of both apps
   (unauthenticated API, one call per repo).
3. Runs the **plausibility anchor** — yesterday's opt-in DAU must never
   exceed cumulative downloads (see below). On violation the snapshot is
   flagged `SPOOFED-SUSPECTED` and the script exits non-zero.
4. Writes `fundraising/metrics/history/usage-YYYY-MM-DD.json` (the full
   daily/country/version series for that day) and appends one line to
   `fundraising/metrics/history/usage-history.csv` — the flat file the
   data room and the deck charts are built from.
5. Runs `fundraising/pull-github-metrics.ps1` when present, so the
   GitHub side of the traction package refreshes in the same pass.

To run it ad hoc at any time: drop the flags — `powershell -File
telemetry\server\snapshot-usage.ps1`. Commit the `metrics/history/` files
with the repo (or your private data-room mirror) so the series accumulates.

## The manual path (if you'd rather see each step)

```powershell
curl -H "Authorization: Bearer (Get-Content telemetry\server\admin-token.txt)" `
     https://autocommand-usage-ping.dpark-sports.workers.dev/v1/stats | Out-File fundraising\metrics\history\usage-$(Get-Date -f yyyy-MM-dd).json
```

…then do steps 2–3 by hand. The script exists so this never has to happen
on a busy week — a gap in the series is the one thing it can't fix later.

## The plausibility anchor (why it exists)

Counts can never legitimately exceed downloads: every counted install is a
person who downloaded the app and clicked Yes. So in every snapshot,
`dau_yesterday` is compared against the cumulative download total; a DAU
that explodes past the downloads curve is spoofed (it is the one attack the
worker's own gates don't stop on plain `*.workers.dev` — see Hardening in
`server/DEPLOY.md`). The protocol when it happens: **annotate the affected
snapshots in the data room, never delete them.** Investigable raw data plus
an honest methodology note beats silently "fixed" numbers.

---

## Deferred hardening, expanded ("when convenient" items)

These are the items deliberately left out of launch day, with the full
detail so whoever picks them up doesn't have to reverse-engineer it:

### 1. Rate-limit `/v1/ping` (needs a custom domain)

The one abuse vector left after the worker's own gates (JSON-only content
type kills the browser vector; app allowlist + field truncation bound what a
row can contain): a single IP flooding `POST /v1/ping` inflates the count.
Cloudflare's dashboard **cannot** attach WAF rate-limiting rules to a bare
`*.workers.dev` zone — the worker must sit on a domain you own:

1. In Cloudflare dash, add (or use an existing) zone for a domain you own,
   e.g. `magicpoint.ai`.
2. Worker → your worker → **Settings → Domains & Routes → Add** → *Custom
   domain* → `count.magicpoint.ai` (DNS is created for you; the
   `workers.dev` URL keeps working, and the in-app endpoint doesn't change —
   both hosts serve the same worker).
3. Domain → **Security → WAF → Rate limiting rules → Create rule**:
   - Expression: `(http.request.uri.path eq "/v1/ping")`
   - With same IP: **30 requests / 10 minutes**, action **Block**, duration
     **1 hour**.
   - Free plan includes one rate-limiting rule — this is the one worth using.
4. Update the share URLs (`UsagePingService.GraphPageUrl` consumers, the
   worker page's share buttons) only if you want the branded host public;
   the count itself needs no client change.

Interim mitigation while on `workers.dev` (current state): the plausibility
anchor above. It doesn't stop inflation; it makes inflation visible and
unquotable. That trade was accepted for launch.

### 2. Token hygiene

- **Cloudflare API token** (the deploy one): delete it after setup;
  re-create only when redeploying. It grants Workers + D1 write to the
  whole account — it is the most powerful credential in this system and
  spends 100% of its life unused.
- **`ADMIN_TOKEN`** (guards `/v1/stats` reads): rotate by generating a new
  random value and running `wrangler secret put ADMIN_TOKEN` (needs a
  Cloudflare API token again), then update `admin-token.txt` (gitignored).
  It only exposes anonymous aggregates, but rotate it like any credential.
- Never commit `admin-token.txt`, never paste it in screenshots or issues.
  If it leaks: rotate as above — there is nothing else to invalidate.

### 3. Emergency off-switch

If the endpoint is ever abused: redeploy with `ALLOWED_APPS` emptied —
the worker rejects every ping, while the community page keeps rendering
history. One-line change + `wrangler deploy`; no user data is at risk in
any scenario (the database only ever held daily aggregates).

### 4. Accepted engine limitations (PLAN.md, tracked there on purpose)

Not actions — context, so nobody "fixes" them blindly: TLS 1.3 KeyUpdate
re-keying is best-effort (undecryptable records are flagged, never guessed);
0-RTT early data may fail decryption (early secret isn't in the keylog);
loopback traffic never crosses the NIC; UDP/QUIC is out of scope; pid→flow
attribution is by endpoint at connect time, so a reused 4-tuple could
mis-attribute (flagged in UI text).

---

## Operational note — remember this one

> **On a fresh deploy, the smoke tests can false-fail for about a minute.**
> The worker reports deployed before the new D1 binding has propagated to
> every edge colo, so the first requests can 500/404 even though everything
> is correct. `setup-worker.ps1` hitting a fresh worker and showing FAILs in
> the first minute is **not a bug**: wait a minute and re-run the script
> (it's idempotent) before diagnosing. Verified live on the first-ever
> deploy: 5/6 FAILs straight after deploy, all PASS on re-run, zero changes
> made in between.
