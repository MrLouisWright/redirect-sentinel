// Static checks for server-side redirect code and Next.js redirects(), plus nginx variable tracking.
import { parseNetlifyRedirects, parseVercelConfig } from 'static-link-sentinel';
import { isSafeRedirect } from './safe-redirect.js';

const lineOf = (text, idx) => text.slice(0, idx).split('\n').length;
const REQ_SRC = String.raw`(?:req(?:uest)?\.(?:query|params|body|headers)(?:\.\w+|\[['"][^'"]+['"]\])|(?:req\.nextUrl\.|nextUrl\.|url\.|request\.nextUrl\.)?searchParams\.get\(\s*['"][^'"]+['"]\s*\)|ctx\.query\.\w+|req\.get\(\s*['"]referr?er['"]\s*\))`;
const SINKS = [
  [new RegExp(String.raw`\bres\.redirect\(\s*(?:\d{3}\s*,\s*)?` + REQ_SRC), 'Express res.redirect() with a value from the request'],
  [new RegExp(String.raw`\bNextResponse\.redirect\(\s*(?:new\s+URL\(\s*)?` + REQ_SRC), 'NextResponse.redirect() with a value from the request'],
  [new RegExp(String.raw`(?<![.\w])(?:redirect|permanentRedirect)\(\s*` + REQ_SRC), 'Next.js redirect() with a value from the request'],
  [new RegExp(String.raw`\b(?:ctx|reply)\.redirect\(\s*` + REQ_SRC), 'Koa/Fastify redirect() with a value from the request'],
  [new RegExp(String.raw`\b(?:res|response)\.(?:setHeader|header|set)\(\s*['"]location['"]\s*,\s*` + REQ_SRC, 'i'), 'Location header set from the request'],
];
const FIX = 'Wrap the value with safeRedirectUrl() from redirect-sentinel (relative paths or an allowlist only).';

/** Server-side JS/TS: res.redirect(req.query.next), NextResponse.redirect(new URL(searchParams.get('next'))), etc. */
export function analyzeServerJs(code, file) {
  const raw = []; const text = String(code);
  if (/safeRedirectUrl|isSafeRedirect|nextSafeRedirect/.test(text)) return raw;
  for (const [re, what] of SINKS) {
    const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
    for (const m of text.matchAll(g)) { const line = lineOf(text, m.index); raw.push({ rule: 'open-redirect-server', line, location: `${file}:${line}`, message: `${what}: ${m[0].slice(0, 120)}`, evidence: m[0].slice(0, 120), fix: FIX }); }
  }
  return raw;
}

const placeholderHost = (to) => /^(:[\w]+|\$\d|\$\{?\w+)/.test(to) || /^https?:\/\/(:[\w]+|\$\d|\$\{?\w+|\{\w+\})/.test(to) || /^\/\/(:|\$)/.test(to);

/** next.config.(m)js / ts redirects(): finds { source, destination, has } objects across lines, incl. query-driven destinations. */
export function analyzeNextConfig(text, file) {
  const raw = []; const s = String(text);
  const enclosing = (i) => { let d = 0, st = i, en = i; for (; st >= 0; st--) { if (s[st] === '}') d++; else if (s[st] === '{') { if (!d) break; d--; } } d = 0; for (; en < s.length; en++) { if (s[en] === '{') d++; else if (s[en] === '}') { if (!d) break; d--; } } return s.slice(Math.max(st, 0), en + 1); };
  for (const m of s.matchAll(/\bdestination\s*:\s*(['"`])([^'"`]+)\1/g)) {
    const dest = m[2]; const line = lineOf(s, m.index); const obj = enclosing(m.index);
    const qKeys = [...obj.matchAll(/\{[^{}]*type\s*:\s*['"]query['"][^{}]*\}/g)].map((x) => /key\s*:\s*['"](\w+)['"]/.exec(x[0])?.[1]).filter(Boolean);
    const hostVar = /^(?:https?:)?\/\/:(\w+)|^:(\w+)/.exec(dest);
    const fromQuery = hostVar && qKeys.includes(hostVar[1] || hostVar[2]);
    if (placeholderHost(dest) || fromQuery) raw.push({ rule: 'open-redirect-config', line, location: `${file}:${line}`, message: `Next.js redirect destination "${dest}"${fromQuery ? ` comes from the ?${hostVar[1] || hostVar[2]}= query parameter` : ' takes its host from the request'}`, evidence: dest, fix: 'Use fixed destination hosts; validate query-driven redirects in middleware with safeRedirectUrl().' });
  }
  return raw;
}

/** nginx: return/rewrite to $arg_*, $http_referer, $args, or to a variable set from them via map/set. */
export function analyzeNginx(text, file) {
  const raw = []; const lines = String(text).split('\n');
  const tainted = new Set(['arg_\\w+', 'http_referer', 'args', 'query_string', 'request_uri']);
  const taintRe = () => new RegExp(String.raw`\$(?:${[...tainted].join('|')})\b`);
  lines.forEach((l) => {
    const m = /^\s*map\s+(\$\S+)\s+\$(\w+)/.exec(l); if (m && taintRe().test(m[1])) tainted.add(m[2]);
    const s = /^\s*set\s+\$(\w+)\s+(\S+?);/.exec(l); if (s && taintRe().test(s[2])) tainted.add(s[1]);
  });
  const dynHost = () => new RegExp(String.raw`^(?:https?:\/\/|\/\/)?\$(?:${[...tainted].join('|')})\b`);
  lines.forEach((l, i) => {
    if (/^\s*#/.test(l)) return;
    const m = /\b(?:return\s+30[1278]|rewrite\s+\S+)\s+(\S+?)(?:\s+(?:redirect|permanent))?;/.exec(l);
    if (!m) return;
    const to = m[1].replace(/^["']|["']$/g, '');
    if (/^https?:\/\/\$(host|server_name|http_host)\b/.test(to) || /^\$scheme:\/\/\$(host|server_name)/.test(to)) return;
    if (dynHost().test(to) || /^\$scheme:\/\/\$(?:arg_|http_referer)/.test(to)) raw.push({ rule: 'open-redirect-config', line: i + 1, location: `${file}:${i + 1}`, message: `nginx redirects to "${to}", a destination taken from the request`, evidence: l.trim(), fix: 'Redirect only to fixed hosts, or validate the value with a map of allowed destinations.' });
  });
  return raw;
}

/** _redirects and vercel.json via static-link-sentinel's parsers; flags rules whose destination host comes from the request. */
export function analyzeHostingRedirects(text, file) {
  const raw = []; const name = file.split('/').pop().toLowerCase();
  let rules = [];
  if (name === '_redirects') rules = parseNetlifyRedirects(String(text), file);
  else if (name === 'vercel.json') {
    let j; try { j = JSON.parse(text); } catch { return raw; }
    rules = parseVercelConfig(j, file).rules;
    const lineFor = (d) => { const i = String(text).indexOf(d); return i < 0 ? undefined : lineOf(text, i); };
    for (const r of [...(j.redirects || [])]) if ((r.has || r.missing) && r.destination) { const q = (r.has || []).filter((h) => h.type === 'query').map((h) => h.key); const hv = /^(?:https?:)?\/\/:(\w+)/.exec(r.destination); if (placeholderHost(r.destination) || (hv && q.includes(hv[1]))) rules.push({ to: r.destination, from: r.source, file, line: lineFor(r.destination), type: 'redirect' }); }
    for (const r of rules) r.line ??= lineFor(r.to);
  }
  for (const r of rules) if (r.type === 'redirect' && placeholderHost(r.to)) raw.push({ rule: 'open-redirect-config', line: r.line, location: r.line ? `${file}:${r.line}` : file, message: `${r.from} redirects to "${r.to}", a destination taken from the request`, evidence: r.to, fix: 'Redirect only to fixed hosts; never build the destination host from the request.' });
  return raw;
}

export { isSafeRedirect };
