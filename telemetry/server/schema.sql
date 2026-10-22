-- Anonymous daily-count schema — D1. A single aggregate table; there are no
-- per-install rows, no identifiers, and no IP-derived values anywhere.

CREATE TABLE IF NOT EXISTS daily_rollup (
  day     TEXT NOT NULL,          -- YYYY-MM-DD (UTC)
  app     TEXT NOT NULL,          -- 'autocommand' | 'shields-up'
  country TEXT NOT NULL,          -- ISO 3166-1 alpha-2 from request.cf.country, or '??'
  version TEXT NOT NULL,          -- "appversion/osbuild"
  pings   INTEGER NOT NULL DEFAULT 0,  -- daily-active count (client pings at most once/day)
  PRIMARY KEY (day, app, country, version)
);

-- Pure aggregates; retained indefinitely (they contain no personal data).
