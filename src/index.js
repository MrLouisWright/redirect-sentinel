import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, basename } from 'node:path';
import { buildReport, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError, validateConfig } from './core.js';
import { RULES } from './rules.js';
import { analyzeHtml, analyzeJs, analyzeCss, analyzeRedirectConfig, REDIRECT_PARAMS } from './analyze.js';
import { crawl, get, CANARY } from './crawl.js';
import { scanHtml } from './html.js';
import { analyzeServerJs, analyzeNextConfig, analyzeNginx, analyzeHostingRedirects } from './server.js';
import { isSafeRedirect, safeRedirectUrl, safeRedirectMiddleware, nextSafeRedirect } from './safe-redirect.js';
export { analyzeServerJs, analyzeNextConfig, analyzeNginx, analyzeHostingRedirects, isSafeRedirect, safeRedirectUrl, safeRedirectMiddleware, nextSafeRedirect };

export { analyzeHtml, analyzeJs, analyzeCss, analyzeRedirectConfig, crawl, scanHtml, REDIRECT_PARAMS, CANARY, RULES, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError };
export const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
export const TOOL = { name: 'redirect-sentinel', version: VERSION, rules: RULES, title: 'redirect-sentinel', emoji: '↪️', defaultFailOn: 'high' };

const SKIP = new Set(['node_modules', '.git', '.cache']);
const CONFIG = /^(_redirects|netlify\.toml|vercel\.json|next\.config\.(?:m?js|cjs|m?ts)|\.htaccess|nginx.*\.conf|.*\.nginx|default\.conf|site\.conf)$/i;
function walk(dir, out = []) { for (const e of readdirSync(dir, { withFileTypes: true })) { if (SKIP.has(e.name)) continue; const f = join(dir, e.name); if (e.isDirectory()) walk(f, out); else if (/\.(html?|[cm]?js|[cm]?tsx?|jsx|css)$/i.test(e.name) && !/\.d\.[cm]?ts$/.test(e.name) && !/\.min\.map$/.test(e.name) || CONFIG.test(e.name)) out.push(f); } return out; }

/** Scan build directories / files, or crawl http(s) URLs. Options: https (static pages are served over HTTPS, default true), maxPages, maxScripts, probe, httpCheck, timeout, allow, severity. */
export async function check(targets, opts = {}) {
  validateConfig({ allow: opts.allow, severity: opts.severity });
  const results = [];
  for (const t of targets) {
    if (/^https?:\/\//i.test(t)) {
      const c = await crawl(t, opts);
      results.push({ target: t, ...(c.fatal ? { fatal: true } : {}), summary: { pages: c.pages, ...(c.probed !== undefined ? { probedParams: c.probed } : {}) }, raw: c.raw, errors: c.errors });
      continue;
    }
    let files; try { files = statSync(t).isDirectory() ? walk(t) : [t]; } catch (e) { results.push({ target: t, fatal: true, raw: [], errors: [`Cannot read ${t}: ${e.code || e.message}`] }); continue; }
    const raw = []; const counts = { html: 0, js: 0, css: 0, config: 0 };
    for (const f of files.sort()) {
      const loc = relative(process.cwd(), f) || f; const n = basename(f);
      let text; try { if (statSync(f).size > 5_000_000) continue; text = readFileSync(f, 'utf8'); } catch { continue; }
      if (CONFIG.test(n)) { counts.config++; raw.push(...analyzeRedirectConfig(text, loc)); }
      else if (/\.html?$/i.test(n)) { counts.html++; raw.push(...analyzeHtml(text, { loc, https: opts.https !== false }).raw); }
      else if (/\.([cm]?js|jsx)$/i.test(n)) { counts.js++; raw.push(...analyzeJs(text, loc), ...analyzeServerJs(text, loc)); }
      else if (/\.[cm]?tsx?$/i.test(n)) { counts.js++; raw.push(...analyzeServerJs(text, loc)); }
      else if (/\.css$/i.test(n)) { counts.css++; raw.push(...analyzeCss(text, loc, { https: opts.https !== false })); }
    }
    for (const r of raw) r.file ??= r.location.replace(/:\d+$/, '');
    results.push({ target: t, summary: counts, raw });
  }
  return buildReport(TOOL, results, opts);
}
