#!/usr/bin/env node
import { runCli, UsageError } from '../src/cli-core.js';
import { check, TOOL } from '../src/index.js';

const HELP = `redirect-sentinel {VERSION} — find open redirects and mixed content

Usage: redirect-sentinel <build-dir|file|https://url> [...] [options]

Directories are scanned offline: *.html, *.js, *.css and redirect configs (_redirects, netlify.toml,
vercel.json, .htaccess, nginx *.conf). URLs are crawled (same origin only), including same-origin scripts.

      --http                 Static pages are served over plain HTTP (skip mixed-content checks)
      --max-pages <n>        Pages to crawl per URL (default 50)
      --max-scripts <n>      Same-origin scripts to fetch per URL (default 30)
      --probe                Actively test redirect parameters found while crawling with a harmless
                             ${'redirect-sentinel.invalid'} destination. Only use on sites you own or may test.
      --no-http-check        Do not check that http:// redirects to https://
      --timeout <ms>         Per-request timeout (default 10000)
{COMMON}`;

process.exitCode = await runCli(TOOL, {
  help: HELP,
  options: { http: { type: 'boolean' }, 'max-pages': { type: 'string' }, 'max-scripts': { type: 'string' }, probe: { type: 'boolean' }, 'no-http-check': { type: 'boolean' }, timeout: { type: 'string' } },
  run(o, pos, cfg) {
    const targets = pos.length ? pos : cfg.targets || ['.'];
    const num = (n, d) => { const v = o[n] ?? cfg[n.replace(/-(.)/g, (_, c) => c.toUpperCase())]; if (v === undefined) return d; const x = Number(v); if (!Number.isInteger(x) || x < 0) throw new UsageError(`--${n} must be a whole number`); return x; };
    return check(targets, { https: !(o.http ?? cfg.http), maxPages: num('max-pages'), maxScripts: num('max-scripts'), probe: o.probe ?? cfg.probe, httpCheck: !(o['no-http-check'] ?? cfg.noHttpCheck), timeout: num('timeout'), allow: cfg.allow, severity: cfg.severity });
  },
});
