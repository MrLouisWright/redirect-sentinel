import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawnSync } from 'node:child_process';
import { check, analyzeHtml, analyzeJs, analyzeRedirectConfig, scanHtml, exitCode, CANARY } from '../src/index.js';
const F = new URL('./fixtures/', import.meta.url).pathname;
const rules = (x) => new Set((x.findings || x).map((f) => f.rule));

test('HTML scanner: attributes, comments, inline scripts, lines', () => {
  const s = scanHtml('<a href="x?a=1&amp;b=2" data-x=\'y\'>\n<!-- <script src="no"></script> -->\n<script>go()</script><img src=z.png>');
  assert.equal(s.tags[0].attrs.href, 'x?a=1&b=2');
  assert.equal(s.tags.filter((t) => t.name === 'script').length, 1);
  assert.equal(s.scripts[0].line, 3);
  assert.equal(s.tags.at(-1).attrs.src, 'z.png');
});
test('static fixture site', async () => {
  const r = await check([F + 'site']);
  const s = rules(r);
  for (const k of ['mixed-content-active', 'mixed-content-passive', 'insecure-form', 'insecure-link', 'redirect-param', 'meta-refresh-external', 'open-redirect-js', 'open-redirect-config']) assert.ok(s.has(k), k);
  const locs = r.findings.map((f) => f.location).join('\n');
  assert.ok(!locs.includes('good.html'), 'good page is clean');
  assert.ok(!r.findings.some((f) => /localhost|commented/.test(f.message)));
  assert.equal(r.findings.filter((f) => f.rule === 'insecure-link').length, 1, 'one per host');
  assert.equal(r.findings.filter((f) => f.rule === 'open-redirect-config').length, 4);
  assert.equal(exitCode(r, 'high'), 1);
});
test('--http disables mixed-content checks', async () => {
  const s = rules(await check([F + 'site/index.html'], { https: false }));
  assert.ok(!s.has('mixed-content-active')); assert.ok(s.has('open-redirect-js'));
});
test('JS heuristics: guarded and constant redirects are fine', () => {
  assert.equal(analyzeJs("location.href = '/home';\nconst n = new URLSearchParams(location.search).get('n'); if (n.startsWith('/')) location.href = n;", 'a.js').length, 0);
  assert.equal(analyzeJs('const target = location.hash.slice(1);\nconst t2 = decodeURIComponent(target);\nlocation.replace(t2);', 'a.js').length, 1);
  assert.equal(analyzeJs("router.push(new URLSearchParams(location.search).get('next'))", 'a.js').length, 1);
});
test('redirect configs', () => {
  assert.equal(analyzeRedirectConfig('/a /b 301\n/x https://example.com/:splat 302\n', '_redirects').length, 0);
  assert.equal(analyzeRedirectConfig('[[redirects]]\n  from = "/r"\n  to = ":url"\n', 'netlify.toml').length, 1);
  assert.equal(analyzeRedirectConfig('RewriteCond %{QUERY_STRING} url=(.*)\nRewriteRule ^go$ %1 [R=302,L]\n', '.htaccess').length, 1);
  assert.equal(analyzeRedirectConfig('return 301 https://$host$request_uri;\n', 'nginx.conf').length, 0);
});

let srv, base;
before(async () => {
  srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    const html = (b) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(b); };
    if (u.pathname === '/') return html('<a href="/page2">p2</a><a href="/go?next=/home">go</a><a href="/safe?next=/x">safe</a><a href="/chain">c</a><a href="https://elsewhere.example/">x</a><script src="/app.js"></script>');
    if (u.pathname === '/page2') return html('<img src="http://cdn.example.com/a.png"><form action="/login?returnTo=https://evil.example/"></form>');
    if (u.pathname === '/app.js') { res.writeHead(200, { 'content-type': 'text/javascript' }); return res.end('window.open(document.referrer);'); }
    if (u.pathname === '/go') { res.writeHead(302, { location: u.searchParams.get('next') || '/' }); return res.end(); }
    if (u.pathname === '/safe') { const n = u.searchParams.get('next') || '/'; res.writeHead(302, { location: n.startsWith('/') && !n.startsWith('//') && !n.startsWith('/\\') ? n : '/' }); return res.end(); }
    if (u.pathname === '/chain') { res.writeHead(301, { location: '/c1' }); return res.end(); }
    if (/^\/c[1-3]$/.test(u.pathname)) { res.writeHead(301, { location: `/c${+u.pathname[2] + 1}` }); return res.end(); }
    if (u.pathname === '/c4') return html('end');
    if (u.pathname === '/home' || u.pathname === '/x') return html('home');
    res.writeHead(404); res.end();
  });
  await new Promise((ok) => srv.listen(0, '127.0.0.1', ok)); base = `http://127.0.0.1:${srv.address().port}`;
});
after(() => srv.close());

test('crawl: same-origin pages, scripts, chains; no probing by default', async () => {
  const r = await check([base + '/'], { httpCheck: false });
  const s = rules(r);
  assert.ok(s.has('open-redirect-js')); assert.ok(s.has('redirect-chain')); assert.ok(s.has('redirect-param'));
  assert.ok(!s.has('open-redirect'));
  assert.ok(!s.has('mixed-content-passive'), 'http page: no mixed content');
  assert.ok(r.targets[0].summary.pages >= 3);
});
test('crawl --probe confirms the open redirect and not the safe one', async () => {
  const r = await check([base + '/'], { probe: true, httpCheck: false });
  const hits = r.findings.filter((f) => f.rule === 'open-redirect');
  assert.equal(hits.length, 1); assert.match(hits[0].location, /\/go\?next=/); assert.match(hits[0].message, new RegExp(CANARY.replace(/\./g, '\\.')));
});
test('unreachable start URL is fatal', async () => {
  const s = http.createServer(); await new Promise((ok) => s.listen(0, '127.0.0.1', ok)); const port = s.address().port; await new Promise((ok) => s.close(ok));
  assert.equal(exitCode(await check([`http://127.0.0.1:${port}/`], { timeout: 2000 }), 'high'), 2);
});
test('allowlist and severity', async () => {
  const r = await check([F + 'site'], { allow: [{ rule: 'open-redirect-config', target: '*', match: '*vercel.json*', reason: 'reviewed' }], severity: { 'insecure-link': 'off' } });
  assert.equal(r.findings.filter((f) => f.rule === 'open-redirect-config').length, 3); assert.ok(!rules(r).has('insecure-link'));
});
test('CLI', () => {
  const bin = new URL('../bin/redirect-sentinel.js', import.meta.url).pathname;
  for (const f of ['json', 'sarif', 'markdown', 'text']) { const p = spawnSync('node', [bin, F + 'site', '-f', f]); assert.equal(p.status, 1, f); assert.ok(p.stdout.length); }
  assert.equal(spawnSync('node', [bin, F + 'site/good.html']).status, 0);
  assert.equal(spawnSync('node', [bin, '/nonexistent']).status, 2);
  assert.equal(spawnSync('node', [bin, F + 'site', '--max-pages', 'x']).status, 2);
});
