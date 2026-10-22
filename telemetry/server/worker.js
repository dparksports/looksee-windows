// Anonymous daily-count receiver — Cloudflare Worker + D1.
// Privacy architecture: the payload carries NO identifier of any kind (not
// even a random id). The worker reads only the country code Cloudflare
// derives at the edge (request.cf.country); it never reads, stores, or
// forwards an IP address, and it never writes per-install rows — only daily
// aggregate counters. Once-per-day behavior is enforced client-side (the
// app pings at most daily), so a ping ≈ one daily-active install.
//
// Public surface:
//   POST /v1/ping   — the count increment (from the app)
//   GET  /          — the community graph + share page (self-contained HTML)
//   GET  /v1/graph  — public JSON: daily series, top countries, totals (CORS *)
//   GET  /v1/badge  — yesterday's opt-in daily actives (plain text)
//   GET  /v1/stats  — admin JSON (bearer ADMIN_TOKEN)

const ALLOWED_APPS = new Set(['autocommand', 'shields-up']);
const MAX_VERSION_LEN = 32;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'POST' && url.pathname === '/v1/ping') return handlePing(request, env);
    if (request.method === 'GET' && url.pathname === '/v1/graph') return handleGraph(env);
    if (request.method === 'GET' && url.pathname === '/v1/stats') return handleStats(request, env);
    if (request.method === 'GET' && url.pathname === '/v1/badge') return handleBadge(env);
    if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html'))
      return new Response(PAGE_HTML, { headers: { 'content-type': 'text/html; charset=utf-8' } });

    return json({ error: 'not found' }, 404);
  },
};

async function handlePing(request, env) {
  // JSON-only gate: a browser "simple request" (e.g. text/plain via fetch) skips
  // CORS preflight, so a malicious page could otherwise count visitors without
  // them knowing. Requiring application/json forces a preflight we never grant.
  const ctype = (request.headers.get('content-type') || '').toLowerCase();
  if (!ctype.startsWith('application/json')) return json({ error: 'json only' }, 415);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'bad json' }, 400); }

  const app = String(body.a || '');
  const version = String(body.v || '').slice(0, MAX_VERSION_LEN) || 'unknown';
  const osBuild = String(body.o || '').slice(0, MAX_VERSION_LEN);
  if (!ALLOWED_APPS.has(app)) return json({ error: 'bad app' }, 400);

  const day = new Date().toISOString().slice(0, 10);            // UTC YYYY-MM-DD
  // Country is edge-derived and strictly validated; anything unexpected
  // collapses to '??' so the public page can never render hostile strings.
  const rawCountry = (request.cf && request.cf.country) || '';
  const country = /^[A-Z]{2}$/.test(rawCountry) ? rawCountry : '??';

  // One aggregate row per (day, app, country, version) — nothing per-install,
  // nothing per-person, nothing reversible.
  await env.DB.prepare(
    `INSERT INTO daily_rollup (day, app, country, version, pings) VALUES (?1, ?2, ?3, ?4, 1)
     ON CONFLICT(day, app, country, version) DO UPDATE SET pings = pings + 1`
  ).bind(day, app, country, `${version}/${osBuild}`.slice(0, 64)).run();

  return new Response(null, { status: 204 });
}

// Public feed for the community graph page (and anyone else — the data is
// anonymous by construction, so it is publishable by design).
async function handleGraph(env) {
  const [daily, countries, totals] = await Promise.all([
    env.DB.prepare(
      `SELECT day, SUM(pings) AS dau FROM daily_rollup GROUP BY day ORDER BY day DESC LIMIT 365`).all(),
    env.DB.prepare(
      `SELECT country, SUM(pings) AS pings FROM daily_rollup GROUP BY country
       HAVING SUM(pings) >= 5 ORDER BY pings DESC LIMIT 10`).all(),
    env.DB.prepare(
      `SELECT SUM(pings) AS total_pings, COUNT(DISTINCT country) AS countries FROM daily_rollup`).first(),
  ]);
  return new Response(JSON.stringify({
    generated_at: new Date().toISOString(),
    days: daily.results.map(r => ({ day: r.day, dau: r.dau })).reverse(),
    countries: countries.results,
    totals: totals || { total_pings: 0, countries: 0 },
  }), { headers: {
    'content-type': 'application/json',
    'access-control-allow-origin': '*',
    'cache-control': 'public, max-age=300',
  }});
}

async function handleStats(request, env) {
  if (!env.ADMIN_TOKEN) return json({ error: 'server not configured' }, 500);
  if (request.headers.get('Authorization') !== `Bearer ${env.ADMIN_TOKEN}`) return json({ error: 'unauthorized' }, 401);

  const [daily, countries, versions, totals] = await Promise.all([
    env.DB.prepare(
      `SELECT day, app, SUM(pings) AS dau FROM daily_rollup
       GROUP BY day, app ORDER BY day DESC LIMIT 240`).all(),
    env.DB.prepare(
      `SELECT country, SUM(pings) AS pings FROM daily_rollup
       GROUP BY country ORDER BY pings DESC LIMIT 60`).all(),
    env.DB.prepare(
      `SELECT version, SUM(pings) AS pings FROM daily_rollup
       WHERE day >= date('now','-29 days') GROUP BY version ORDER BY pings DESC LIMIT 40`).all(),
    env.DB.prepare(
      `SELECT SUM(pings) AS total_pings, COUNT(DISTINCT day) AS days_seen FROM daily_rollup`).first(),
  ]);

  return json({
    generated_at: new Date().toISOString(),
    note: 'daily pings approximate consenting daily-active installs; no identifiers exist anywhere in this system',
    daily: daily.results,
    countries: countries.results,
    versions: versions.results,
    totals: totals || { total_pings: 0, days_seen: 0 },
  });
}

async function handleBadge(env) {
  // Public number: yesterday's total daily actives across apps (opt-in).
  const r = await env.DB.prepare(
    `SELECT COALESCE(SUM(pings), 0) AS n FROM daily_rollup WHERE day = date('now','-1 day')`
  ).first();
  return new Response(String(r ? r.n : 0), {
    status: 200,
    headers: { 'content-type': 'text/plain', 'access-control-allow-origin': '*' },
  });
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), { status, headers: { 'content-type': 'application/json' } });
}

// ── The community graph + share page ────────────────────────────────────────
// Self-contained: no external assets, no JS libraries, no fonts, no tracking.
// (No template-literal syntax below PAGE_HTML's own backticks — the page's
// script uses string concatenation only.)
const PAGE_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AutoCommand — live community count</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background:#171B22; color:#F1F4F9; font-family:"Segoe UI",system-ui,-apple-system,sans-serif;
         max-width:880px; margin:0 auto; padding:32px 20px 60px; }
  h1 { font-size:26px; margin-bottom:4px; }
  .sub { color:#98A2B3; font-size:14px; margin-bottom:28px; }
  .stats { display:flex; gap:14px; flex-wrap:wrap; margin-bottom:22px; }
  .card { background:#1F242E; border:1px solid #39414F; border-radius:10px; padding:16px 20px; flex:1; min-width:150px; }
  .card .n { font-size:30px; font-weight:700; }
  .card .l { color:#98A2B3; font-size:12px; margin-top:2px; }
  .panel { background:#1F242E; border:1px solid #39414F; border-radius:10px; padding:18px 20px; margin-bottom:22px; }
  .panel h2 { font-size:15px; margin-bottom:12px; color:#C7D0DB; }
  svg text { fill:#98A2B3; font-size:11px; }
  .countries { list-style:none; }
  .countries li { display:flex; align-items:center; gap:10px; margin:6px 0; font-size:13px; }
  .countries .bar { height:8px; border-radius:4px; background:#3B82F6; }
  .countries .cc { width:34px; color:#98A2B3; }
  .btns { display:flex; gap:10px; flex-wrap:wrap; }
  .btn { display:inline-block; padding:10px 18px; border-radius:8px; font-size:14px; font-weight:600;
         text-decoration:none; border:1px solid #39414F; color:#F1F4F9; background:#282F3B; cursor:pointer; }
  .btn.primary { background:#2F74B5; border-color:#2F74B5; color:#fff; }
  .btn.amber { background:#B45309; border-color:#B45309; color:#fff; }
  .how { color:#98A2B3; font-size:12.5px; line-height:1.7; }
  .how b { color:#C7D0DB; }
  footer { margin-top:30px; color:#5B6472; font-size:12px; }
  a { color:#5FA8F5; }
</style>
</head>
<body>
<h1>AutoCommand <span style="color:#3B82F6">·</span> live community count</h1>
<div class="sub">How many people are using it, counted anonymously — <b>opt-in, zero identifiers, IPs never stored.</b></div>

<div class="stats" id="stats"></div>

<div class="panel">
  <h2>Daily active installs — last 90 days</h2>
  <svg id="chart" width="100%" height="220" viewBox="0 0 820 220" preserveAspectRatio="none"></svg>
  <div id="empty" style="color:#98A2B3;font-size:14px;display:none">Counting starts with the next app release — check back soon.</div>
</div>

<div class="panel">
  <h2>Where the community is</h2>
  <ul class="countries" id="countries"></ul>
</div>

<div class="panel">
  <h2>Get the apps — free, open source</h2>
  <div class="btns">
    <a class="btn primary" href="https://github.com/dparksports/autocommand-windows/releases/latest">Download AutoCommand</a>
    <a class="btn primary" href="https://github.com/dparksports/shields-up/releases/latest">Download Shields Up</a>
  </div>
</div>

<div class="panel">
  <h2>Share it — every install counts</h2>
  <div class="btns">
    <button class="btn amber" id="copyBtn">Copy link</button>
    <a class="btn" id="shareX" href="#" target="_blank" rel="noopener">Share on X</a>
    <a class="btn" id="shareReddit" href="#" target="_blank" rel="noopener">Reddit</a>
    <a class="btn" id="shareHN" href="#" target="_blank" rel="noopener">Hacker News</a>
    <a class="btn" id="shareMail" href="#">Email</a>
  </div>
</div>

<div class="panel how">
  <h2>How this number is counted (the honest version)</h2>
  <b>Opt-in only.</b> The app asks once; nothing is sent unless you say yes.<br>
  <b>No identifiers, ever.</b> Not even a random id — each install adds 1 to a daily total, at most once a day.<br>
  <b>No IPs.</b> The country is derived at the network edge and the address is never stored.<br>
  The spec, server code, and schema are public in the
  <a href="https://github.com/dparksports/autocommand-windows" rel="noopener">repository</a> — verify, don't trust.
</div>

<footer>AutoCommand — see what your Windows PC is really doing. © 2026 Dan Park, magicpoint.ai</footer>

<script>
(function () {
  var url = location.origin + '/v1/graph';
  var shareUrl = location.origin + '/';
  var text = 'AutoCommand — free, open-source Windows security that proves what it blocks. Live count:';

  var sx = document.getElementById('shareX');
  sx.href = 'https://twitter.com/intent/tweet?text=' + encodeURIComponent(text) + '&url=' + encodeURIComponent(shareUrl);
  var sr = document.getElementById('shareReddit');
  sr.href = 'https://reddit.com/submit?url=' + encodeURIComponent(shareUrl) + '&title=' + encodeURIComponent(text);
  var sh = document.getElementById('shareHN');
  sh.href = 'https://news.ycombinator.com/submitlink?u=' + encodeURIComponent(shareUrl) + '&t=' + encodeURIComponent(text);
  var sm = document.getElementById('shareMail');
  sm.href = 'mailto:?subject=' + encodeURIComponent('AutoCommand') + '&body=' + encodeURIComponent(text + ' ' + shareUrl);

  var cb = document.getElementById('copyBtn');
  cb.onclick = function () {
    var done = function () { cb.textContent = 'Copied!'; setTimeout(function () { cb.textContent = 'Copy link'; }, 1600); };
    if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(shareUrl).then(done); }
    else {
      var ta = document.createElement('textarea'); ta.value = shareUrl; document.body.appendChild(ta);
      ta.select(); try { document.execCommand('copy'); done(); } catch (e) {} document.body.removeChild(ta);
    }
  };

  fetch(url).then(function (r) { return r.json(); }).then(function (d) {
    function esc(s) {
      return String(s).replace(/[&<>"']/g, function (m) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m];
      });
    }
    var days = d.days || [];
    var el = document.getElementById('empty');
    if (!days.length) { el.style.display = 'block'; return; }

    // countries (server already suppresses rows under 5 counts on this public feed)
    var cs = d.countries || [];
    var maxC = 1;
    for (var ci = 0; ci < cs.length; ci++) { if (cs[ci].pings > maxC) maxC = cs[ci].pings; }
    document.getElementById('countries').innerHTML = cs.map(function (c) {
      var w = Math.max(10, Math.round(240 * c.pings / maxC));
      return '<li><span class="cc">' + esc(c.country) + '</span>' +
             '<span class="bar" style="width:' + w + 'px"></span>' +
             '<span>' + esc(String(c.pings)) + '</span></li>';
    }).join('');

    var last = days[days.length - 1];
    var last7 = days.slice(-7);
    var avg7 = Math.round(last7.reduce(function (a, x) { return a + x.dau; }, 0) / last7.length);
    var stats = [
      { n: last.dau, l: 'daily actives (' + last.day + ')' },
      { n: avg7, l: '7-day average' },
      { n: d.totals ? d.totals.total_pings : 0, l: 'counts all-time' },
      { n: d.totals ? d.totals.countries : 0, l: 'countries' }
    ];
    document.getElementById('stats').innerHTML = stats.map(function (s) {
      return '<div class="card"><div class="n">' + esc(String(s.n)) + '</div><div class="l">' + esc(s.l) + '</div></div>';
    }).join('');

    // ── chart: last 90 days, area + line, zero-based ──
    var w = 820, h = 220, padL = 34, padR = 8, padT = 14, padB = 22;
    var data = days.slice(-90);
    var max = Math.max.apply(null, data.map(function (x) { return x.dau; }));
    max = Math.max(max, 5);
    var iw = w - padL - padR, ih = h - padT - padB;
    var x = function (i) { return padL + (data.length === 1 ? iw / 2 : i * iw / (data.length - 1)); };
    var y = function (v) { return padT + ih - (v / max) * ih; };
    var pts = data.map(function (d2, i) { return [x(i), y(d2.dau)]; });
    var line = pts.map(function (p, i) { return (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1); }).join(' ');
    var area = line + ' L' + pts[pts.length - 1][0].toFixed(1) + ' ' + (padT + ih) +
               ' L' + pts[0][0].toFixed(1) + ' ' + (padT + ih) + ' Z';
    var svg = document.getElementById('chart');
    var grid = '';
    for (var g = 0; g <= 4; g++) {
      var gy = padT + ih - (g / 4) * ih;
      var gv = Math.round((g / 4) * max);
      grid += '<line x1="' + padL + '" y1="' + gy + '" x2="' + (w - padR) + '" y2="' + gy + '" stroke="#282F3B" stroke-width="1"/>' +
              '<text x="4" y="' + (gy + 4) + '">' + gv + '</text>';
    }
    var lx = (data.length > 1) ? [0, data.length - 1] : [0];
    var labels = lx.map(function (i) {
      return '<text x="' + Math.min(Math.max(x(i), padL), w - 60) + '" y="' + (h - 6) + '">' + data[i].day + '</text>';
    }).join('');
    var dot = pts[pts.length - 1];
    svg.innerHTML =
      '<defs><linearGradient id="fill" x1="0" y1="0" x2="0" y2="1">' +
      '<stop offset="0" stop-color="#3B82F6" stop-opacity="0.35"/><stop offset="1" stop-color="#3B82F6" stop-opacity="0.02"/>' +
      '</linearGradient></defs>' +
      grid +
      '<path d="' + area + '" fill="url(#fill)"/>' +
      '<path d="' + line + '" fill="none" stroke="#3B82F6" stroke-width="2" stroke-linejoin="round"/>' +
      '<circle cx="' + dot[0] + '" cy="' + dot[1] + '" r="4" fill="#F59E0B"/>' +
      labels;
  }).catch(function () {
    document.getElementById('empty').style.display = 'block';
    document.getElementById('empty').textContent = 'Could not load the count right now — try again in a moment.';
  });
})();
</script>
</body>
</html>`;
