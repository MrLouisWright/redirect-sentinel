import { analyzeHtml, analyzeJs, analyzeCss, REDIRECT_PARAMS } from './analyze.js';

export const CANARY = 'redirect-sentinel.invalid';

/** GET with manual redirects; returns the chain and final response. */
export async function get(url, { timeout = 10000, maxHops = 10, method = 'GET', follow = true } = {}) {
  const chain = []; let cur = url;
  for (let hop = 0; hop <= maxHops; hop++) {
    const ac = new AbortController(); const t = setTimeout(() => ac.abort(), timeout);
    let res;
    try { res = await fetch(cur, { method, redirect: 'manual', signal: ac.signal, headers: { 'user-agent': 'redirect-sentinel', accept: 'text/html,*/*;q=0.5' } }); }
    catch (e) { clearTimeout(t); return { error: e.name === 'AbortError' ? `timeout after ${timeout} ms` : (e.cause?.code || e.message), chain }; }
    const loc = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && loc) {
      clearTimeout(t); await res.body?.cancel().catch(() => {});
      let next; try { next = new URL(loc, cur).href; } catch { return { status: res.status, url: cur, chain, location: loc, body: '' }; }
      chain.push({ from: cur, to: next, status: res.status });
      if (!follow || new URL(next).hostname === CANARY) return { status: res.status, url: cur, chain, location: next, body: '' };
      cur = next; continue;
    }
    const type = res.headers.get('content-type') || '';
    let body = '';
    if (/html|javascript|css|text/i.test(type)) { try { body = await res.text(); } catch {} } else await res.body?.cancel().catch(() => {});
    clearTimeout(t);
    return { status: res.status, url: cur, chain, type, body };
  }
  return { error: 'too many redirects', chain };
}

const sameOrigin = (a, b) => { try { return new URL(a).origin === new URL(b).origin; } catch { return false; } };
const pageLike = (u) => !/\.(png|jpe?g|gif|webp|svg|ico|pdf|zip|gz|mp4|mp3|webm|woff2?|ttf|eot|css|js|mjs|json|xml|txt|map)(\?|$)/i.test(new URL(u).pathname);

/** Crawl one site (same origin, breadth first). */
export async function crawl(start, o = {}) {
  const raw = []; const errors = []; const max = o.maxPages ?? 50; const timeout = o.timeout ?? 10000;
  const startUrl = new URL(/^https?:\/\//i.test(start) ? start : `https://${start}`).href;
  const queue = [startUrl]; const seen = new Set([startUrl.split('#')[0]]); const jsSeen = new Set(); const probeTargets = new Map();
  let pages = 0;
  const chainCheck = (r, from) => {
    if (r.chain.length > 3) raw.push({ rule: 'redirect-chain', location: from, message: `${r.chain.length} redirects: ${[from, ...r.chain.map((c) => c.to)].join(' → ')}` });
    for (const c of r.chain) if (c.from.startsWith('https:') && c.to.startsWith('http:')) raw.push({ rule: 'redirect-downgrade', location: c.from, message: `${c.status} redirect from ${c.from} to ${c.to}`, evidence: c.to });
  };
  while (queue.length && pages < max) {
    const url = queue.shift(); pages++;
    const r = await get(url, { timeout });
    if (r.error) { (pages === 1 ? errors : raw).push(pages === 1 ? `${url}: ${r.error}` : { rule: 'fetch-error', location: url, message: `${url}: ${r.error}` }); if (pages === 1) return { raw, errors, pages, fatal: true }; continue; }
    chainCheck(r, url);
    if (!/html/i.test(r.type || '') || !r.body) continue;
    const a = analyzeHtml(r.body, { loc: r.url, pageUrl: r.url, https: r.url.startsWith('https:') });
    raw.push(...a.raw);
    for (const l of a.links) {
      let u; try { u = new URL(l.href, r.url); } catch { continue; }
      if (!/^https?:$/.test(u.protocol)) continue;
      u.hash = '';
      if (sameOrigin(u.href, startUrl)) {
        for (const [k] of u.searchParams) if (REDIRECT_PARAMS.test(k)) { probeTargets.set(`${u.origin}${u.pathname}?${k}`, { url: u.href, param: k }); break; }
        if (!seen.has(u.href) && pageLike(u.href) && !l.form) { seen.add(u.href); queue.push(u.href); }
      }
    }
    for (const s of a.scriptSrcs) {
      let u; try { u = new URL(s, r.url); } catch { continue; }
      if (!sameOrigin(u.href, startUrl) || jsSeen.has(u.href) || jsSeen.size >= (o.maxScripts ?? 30)) continue;
      jsSeen.add(u.href); const js = await get(u.href, { timeout });
      if (js.body) raw.push(...analyzeJs(js.body, u.href));
    }
  }
  if (startUrl.startsWith('https:') && o.httpCheck !== false) {
    const http = startUrl.replace(/^https:/, 'http:'); const r = await get(http, { timeout, follow: true });
    if (!r.error && !(r.url || '').startsWith('https:') && !(r.chain.at(-1)?.to || '').startsWith('https:')) raw.push({ rule: 'http-no-redirect', location: http, message: `${http} answers with ${r.status} instead of redirecting to HTTPS`, fix: 'Redirect all http:// requests to https:// (301/308) and send HSTS.' });
  }
  if (o.probe) for (const { url, param } of probeTargets.values()) {
    for (const payload of [`https://${CANARY}/`, `//${CANARY}/`, `/\\${CANARY}/`, `https:${CANARY}`]) {
      const u = new URL(url); u.searchParams.set(param, payload);
      const r = await get(u.href, { timeout, follow: false });
      const loc = r.location || r.chain?.[0]?.to;
      let h = ''; try { h = loc ? new URL(loc, u.href).hostname : ''; } catch {}
      if (h === CANARY) { raw.push({ rule: 'open-redirect', location: u.href, message: `${u.pathname}?${param}= redirects to any site (payload ${payload} → ${loc})`, evidence: `${u.pathname}?${param}=`, fix: 'Validate the parameter: allow relative paths only, or an allowlist of hosts.' }); break; }
    }
  }
  return { raw, errors, pages, probed: o.probe ? probeTargets.size : undefined };
}
