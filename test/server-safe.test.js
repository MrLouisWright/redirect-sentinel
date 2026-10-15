import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isSafeRedirect, safeRedirectUrl, safeRedirectMiddleware, nextSafeRedirect, analyzeServerJs, analyzeNextConfig, analyzeNginx, analyzeHostingRedirects, check } from '../src/index.js';

test('isSafeRedirect accepts relative paths and allowlisted hosts only', () => {
  for (const ok of ['/account', '/a?b=1#c', 'https://shop.example.com/x']) assert.ok(isSafeRedirect(ok, { allowedHosts: ['.example.com'] }), ok);
  for (const bad of ['//evil.com', '/\\evil.com', '/%2F%2Fevil.com', 'https://evil.com', 'javascript:alert(1)', 'http://shop.example.com', 'https://user@shop.example.com.evil.com', ' /x', '/x\n', '', null, 'https://example.com.evil.com'])
    assert.equal(isSafeRedirect(bad, { allowedHosts: ['.example.com'] }), false, String(bad));
  assert.ok(isSafeRedirect('https://mysite.test/x', { base: 'https://mysite.test' }));
  assert.equal(safeRedirectUrl('//evil', '/home'), '/home');
});

test('Express middleware and Next helper fall back on unsafe targets', () => {
  const calls = []; const res = { redirect: (s, u) => calls.push([s, u]) };
  safeRedirectMiddleware({ fallback: '/login' })({}, res, () => {});
  res.safeRedirect('https://evil.com'); res.safeRedirect(301, '/ok');
  assert.deepEqual(calls, [[302, '/login'], [301, '/ok']]);
  assert.equal(nextSafeRedirect(new URL('https://a.test/?next=//evil')), '/');
  assert.equal(nextSafeRedirect(new URL('https://a.test/?next=/dash')), '/dash');
  assert.equal(nextSafeRedirect({ next: ['/a'] }), '/a');
});

test('analyzeServerJs flags request-driven redirects', () => {
  const f = analyzeServerJs(`app.get('/l', (req, res) => res.redirect(req.query.next));
export function middleware(req) { return NextResponse.redirect(new URL(req.nextUrl.searchParams.get('to'), req.url)); }
redirect(searchParams.get('back'));
res.setHeader('Location', req.headers['referer']);
res.redirect('/fixed');`, 'srv.js');
  assert.deepEqual(f.map((x) => x.line), [1, 2, 3, 4]);
  assert.equal(analyzeServerJs(`res.redirect(safeRedirectUrl(req.query.next))`, 'x.js').length, 0);
});

test('analyzeNextConfig finds multi-line and query-driven destinations', () => {
  const f = analyzeNextConfig(`module.exports = { async redirects() { return [
    { source: '/old', destination: '/new', permanent: true },
    { source: '/out',
      has: [{ type: 'query', key: 'host' }],
      destination: 'https://:host/landing',
      permanent: false },
    { source: '/go/:dest*', destination: ':dest*', permanent: false },
  ]; } };`, 'next.config.js');
  assert.equal(f.length, 2);
  assert.match(f[0].message, /\?host=/);
  assert.equal(f[0].line, 5);
});

test('analyzeNginx tracks map/set taint and ignores $host', () => {
  const f = analyzeNginx(`map $arg_next $dest { default $arg_next; }
server {
  set $back $http_referer;
  location /a { return 301 $arg_url; }
  location /b { return 302 https://$arg_host/x; }
  location /c { return 302 $dest; }
  location /d { rewrite ^ $back redirect; }
  location /e { return 301 https://$host$request_uri; }
}`, 'site.conf');
  assert.deepEqual(f.map((x) => x.line), [4, 5, 6, 7]);
});

test('hosting configs are parsed with static-link-sentinel parsers', () => {
  assert.equal(analyzeHostingRedirects('/x :splat 302\n/y /z 301\n/g/* https://:host/ 302', '_redirects').length, 2);
  const v = analyzeHostingRedirects(JSON.stringify({ redirects: [{ source: '/a', destination: '/b' }, { source: '/o', has: [{ type: 'query', key: 'h' }], destination: 'https://:h/' }] }, null, 1), 'vercel.json');
  assert.equal(v.length, 1);
});

test('check scans TS server code', async () => {
  const d = mkdtempSync(join(tmpdir(), 'rs-')); mkdirSync(join(d, 'app'));
  writeFileSync(join(d, 'app', 'route.ts'), `export function GET(request) { return NextResponse.redirect(new URL(request.nextUrl.searchParams.get('next')!, request.url)); }`);
  writeFileSync(join(d, 'app', 'x.d.ts'), `res.redirect(req.query.next)`);
  const r = await check([d]);
  const f = r.targets[0].findings.filter((x) => x.rule === 'open-redirect-server');
  assert.equal(f.length, 1);
});
