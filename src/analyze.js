import { scanHtml } from './html.js';

export const REDIRECT_PARAMS = /^(next|url|uri|redirect|redirect_?ur[il]|redirect_?to|return|return_?to|returnurl|return_?path|continue|dest|destination|goto|go|target|to|out|r|u|link|forward|callback|redir|rurl|checkout_?url|success_?url|back|backurl|ref)$/i;
const SOURCES = /\b(location\s*\.\s*(search|hash|href)|document\s*\.\s*(URL|documentURI|referrer|baseURI)|URLSearchParams|searchParams\s*\.\s*get|window\s*\.\s*name|getParameter(ByName)?|getQueryParam|query\s*\.\s*(next|url|redirect|returnTo|return_to)|\$route\s*\.\s*query|router\s*\.\s*query|useSearchParams)\b/;
const SINK = /((window|document|top|self|parent)\s*\.\s*)?location(\s*\.\s*href)?\s*=(?!=)|location\s*\.\s*(assign|replace)\s*\(|window\s*\.\s*open\s*\(|\b(navigate|router\s*\.\s*push|redirect)\s*\(\s*(?!['"`]\/[^/])/;

const ACTIVE = { script: ['src'], iframe: ['src'], frame: ['src'], object: ['data'], embed: ['src'], applet: ['code'], base: ['href'] };
const PASSIVE = { img: ['src', 'srcset'], audio: ['src'], video: ['src', 'poster'], source: ['src', 'srcset'], track: ['src'], input: ['src'] };
const isHttp = (v) => /^\s*http:\/\//i.test(v || '');
const notLocal = (v) => !/^\s*http:\/\/(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)([:/]|$)/i.test(v);
const host = (u) => { try { return new URL(u).host; } catch { return ''; } };

/** Analyse a JS source for client-side open redirects (URL/hash/referrer flowing into a navigation sink). */
export function analyzeJs(code, loc, baseLine = 1) {
  const raw = []; const text = String(code);
  if (text.length > 3_000_000) return raw;
  const tainted = new Set();
  const minified = text.length > 2000 && text.length / (text.split('\n').length) > 400;
  const decl = /(?:\b(?:const|let|var)\s+|[,;{(]\s*|^\s*)([A-Za-z_$][\w$]*)\s*=(?!=)([^;\n]*)/gm;
  for (let pass = 0; pass < 2; pass++) {
    for (const m of text.matchAll(decl)) {
      const rhs = m[2];
      if (SOURCES.test(rhs) || [...tainted].some((t) => new RegExp(`(^|[^\\w$.])${t.replace(/\$/g, '\\$')}([^\\w$]|$)`).test(rhs))) if (!minified && m[1].length > 1) tainted.add(m[1]);
    }
  }
  const lines = text.split('\n'); const seen = new Set();
  lines.forEach((l, i) => {
    for (const st of l.split(';')) {
      const sm = SINK.exec(st); if (!sm) continue;
      const after = st.slice(sm.index + sm[0].length);
      const viaSource = SOURCES.test(after);
      const viaVar = [...tainted].find((t) => new RegExp(`(^|[^\\w$.])${t.replace(/\$/g, '\\$')}([^\\w$]|$)`).test(after));
      if (!viaSource && !viaVar) continue;
      if (/startsWith\(\s*['"`]\/['"`]|\.origin\s*===?|isSafeRedirect|allowlist|whitelist|sameOrigin/i.test(st)) continue;
      const line = baseLine + i; const key = `${line}`; if (seen.has(key)) continue; seen.add(key);
      raw.push({ rule: 'open-redirect-js', line, location: `${loc}:${line}`, message: `${sm[0].replace(/\s+/g, '').replace(/\($/, '(…)')} is fed by ${viaSource ? (SOURCES.exec(after)[0]).replace(/\s+/g, '') : `"${viaVar}" (from the URL/referrer)`}`, evidence: st.trim().slice(0, 160), fix: 'Only redirect to relative paths ("/…" but not "//…") or to an allowlist of hosts.' });
    }
  });
  return raw;
}

export function analyzeCss(css, loc, { https = true, baseLine = 1 } = {}) {
  const raw = []; if (!https) return raw;
  String(css).split('\n').forEach((l, i) => {
    for (const m of l.matchAll(/@import\s+(?:url\()?\s*['"]?(http:\/\/[^'")\s;]+)/gi)) if (notLocal(m[1])) raw.push({ rule: 'mixed-content-active', line: baseLine + i, location: `${loc}:${baseLine + i}`, message: `@import over http: ${m[1]}`, evidence: m[1] });
    const imported = new Set([...l.matchAll(/@import\s+url\(\s*['"]?([^'")\s]+)/gi)].map((m) => m[1]));
    for (const m of l.matchAll(/url\(\s*['"]?(http:\/\/[^'")\s]+)/gi)) if (notLocal(m[1]) && !imported.has(m[1])) raw.push({ rule: 'mixed-content-passive', line: baseLine + i, location: `${loc}:${baseLine + i}`, message: `CSS url() over http: ${m[1]}`, evidence: m[1] });
  });
  return raw;
}

/** Analyse an HTML document. ctx: { loc, pageUrl?, https (default true) } */
export function analyzeHtml(html, ctx = {}) {
  const loc = ctx.loc || ctx.pageUrl || 'page.html'; const https = ctx.https ?? true;
  const { tags, scripts, styles } = scanHtml(html); const raw = []; const links = []; const scriptSrcs = [];
  const add = (rule, line, message, evidence, extra = {}) => raw.push({ rule, line, location: `${loc}:${line}`, message, evidence, ...extra });
  const insecureLinkHosts = new Set();
  for (const t of tags) {
    const a = t.attrs;
    if (t.name === 'script' && a.src) scriptSrcs.push(a.src);
    if (https) {
      for (const at of ACTIVE[t.name] || []) if (isHttp(a[at]) && notLocal(a[at])) add('mixed-content-active', t.line, `<${t.name} ${at}="${a[at]}"> on an HTTPS page`, a[at], { fix: 'Load it over https:// (or a relative URL).' });
      if (t.name === 'link' && isHttp(a.href) && notLocal(a.href)) {
        const rel = (a.rel || '').toLowerCase();
        if (/stylesheet|import|modulepreload|preload|prefetch|manifest/.test(rel) && !(rel.includes('preload') && /image|font/.test(a.as || ''))) add('mixed-content-active', t.line, `<link rel="${rel}" href="${a.href}"> on an HTTPS page`, a.href);
        else if (/icon|preload/.test(rel)) add('mixed-content-passive', t.line, `<link rel="${rel}" href="${a.href}"> on an HTTPS page`, a.href);
      }
      for (const at of PASSIVE[t.name] || []) {
        const v = a[at]; if (!v) continue;
        const urls = at === 'srcset' ? v.split(',').map((s) => s.trim().split(/\s+/)[0]) : [v];
        for (const u of urls) if (isHttp(u) && notLocal(u)) { add('mixed-content-passive', t.line, `<${t.name} ${at}="${u}"> on an HTTPS page`, u); break; }
      }
      if (t.name === 'form' && isHttp(a.action) && notLocal(a.action)) add('insecure-form', t.line, `Form submits to ${a.action}`, a.action, { fix: 'Post to https:// only.' });
      if (t.name === 'a' && isHttp(a.href) && notLocal(a.href) && !insecureLinkHosts.has(host(a.href))) { insecureLinkHosts.add(host(a.href)); add('insecure-link', t.line, `Link to ${a.href}`, a.href); }
      if (a.style) for (const f of analyzeCss(a.style, loc, { https, baseLine: t.line })) raw.push({ ...f, line: t.line, location: `${loc}:${t.line}` });
    }
    if (t.name === 'meta' && /refresh/i.test(a['http-equiv'] || '')) {
      const m = /url\s*=\s*['"]?([^'"]+)/i.exec(a.content || '');
      if (m) { const target = m[1].trim(); const page = ctx.pageUrl ? host(ctx.pageUrl) : null; if (/^(https?:)?\/\//i.test(target) && (!page || host(new URL(target, ctx.pageUrl || 'https://x/').href) !== page)) add('meta-refresh-external', t.line, `Meta refresh to ${target}`, target); if (https && /^http:\/\//i.test(target)) add('redirect-downgrade', t.line, `Meta refresh from an HTTPS page to ${target}`, target); }
    }
    const href = t.name === 'a' || t.name === 'area' ? a.href : t.name === 'form' ? a.action : null;
    if (href) {
      links.push({ href, line: t.line, form: t.name === 'form' });
      try {
        const u = new URL(href, ctx.pageUrl || 'https://site.invalid/');
        for (const [k, v] of u.searchParams) if (REDIRECT_PARAMS.test(k) && /^(https?:)?\/\//i.test(v)) { add('redirect-param', t.line, `${t.name === 'form' ? 'Form' : 'Link'} passes ${k}=${v.slice(0, 60)}; check that the endpoint only allows your own hosts`, `${u.pathname}?${k}=`); break; }
      } catch {}
    }
  }
  for (const s of scripts) if (!s.attrs.src && !/json|template|text\/(x-)?(html|template)/i.test(s.attrs.type || '')) raw.push(...analyzeJs(s.code, loc, s.line));
  for (const s of styles) raw.push(...analyzeCss(s.code, loc, { https, baseLine: s.line }));
  return { raw, links, scriptSrcs };
}

/** Redirect rules: Netlify _redirects / netlify.toml, vercel.json, nginx, Apache. */
export function analyzeRedirectConfig(text, file) {
  const raw = []; const name = file.split('/').pop().toLowerCase();
  const add = (line, message, evidence) => raw.push({ rule: 'open-redirect-config', line, location: `${file}:${line}`, message, evidence, fix: 'Redirect only to fixed hosts; never build the destination host from the request.' });
  const hostFromPlaceholder = (to) => /^(:[\w]+|\$\d|\$\{?\w+)/.test(to) || /^https?:\/\/(:[\w]+|\$\d|\$\{?\w+|\{\w+\})/.test(to) || /^\/\/(:|\$)/.test(to);
  const lines = String(text).split('\n');
  if (name === '_redirects') lines.forEach((l, i) => { const t = l.replace(/#.*/, '').trim().split(/\s+/); if (t.length < 2) return; const to = t.slice(1).find((x) => !/=/.test(x)) || ''; if (hostFromPlaceholder(to)) add(i + 1, `${t[0]} redirects to "${to}", a destination taken from the request`, l.trim()); });
  else if (name === 'netlify.toml') lines.forEach((l, i) => { const m = /^\s*to\s*=\s*["']([^"']+)/.exec(l); if (m && hostFromPlaceholder(m[1])) add(i + 1, `Redirect to "${m[1]}", a destination taken from the request`, m[1]); });
  else if (name === 'vercel.json' || name === 'next.config.js' || name === 'next.config.mjs') lines.forEach((l, i) => { const m = /["']?destination["']?\s*:\s*["']([^"']+)/.exec(l); if (m && hostFromPlaceholder(m[1])) add(i + 1, `Redirect destination "${m[1]}" is taken from the request`, m[1]); });
  else lines.forEach((l, i) => {
    if (/^\s*#/.test(l)) return;
    if (/\b(return\s+30[1278]|rewrite\s+\S+)\s+\S*\$(arg_\w+|http_referer|request_uri|query_string|args)\b/i.test(l) && !/return\s+30\d\s+https?:\/\/\$(host|server_name)/i.test(l)) {
      const m = /(return\s+30\d\s+|rewrite\s+\S+\s+)(\S+)/i.exec(l); const to = (m?.[2] || '').replace(/;$/, '');
      if (/^\$(arg_|http_referer|args|query_string)/i.test(to) || /^https?:\/\/\$(arg_|http_referer)/i.test(to)) add(i + 1, `nginx redirects to "${to}"`, l.trim());
    }
    if (/^\s*RewriteRule\s+\S+\s+(%\d|\$\d|https?:\/\/%\d|https?:\/\/%\{QUERY_STRING\}|%\{QUERY_STRING\}|%\{HTTP_REFERER\})\S*\s+\[[^\]]*R/i.test(l)) add(i + 1, 'Apache RewriteRule redirects to a destination captured from the request', l.trim());
  });
  return raw;
}
