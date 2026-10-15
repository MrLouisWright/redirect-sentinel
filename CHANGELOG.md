# Changelog

## 1.0.0 - 2026-10-14

### Added before first publish

- Safe redirect helpers: `isSafeRedirect()`, `safeRedirectUrl()`, Express/Connect `safeRedirectMiddleware()` (adds `res.safeRedirect`) and Next.js `nextSafeRedirect()`. They reject `//host`, `/\host`, encoded slashes, control characters, credentials and non-allowlisted hosts.
- `open-redirect-server` rule: `res.redirect(req.query.x)`, `NextResponse.redirect(new URL(searchParams.get(...)))`, Next `redirect()`, Koa/Fastify, and `Location` headers taken from the request. Scans `.ts`/`.tsx`/`.cjs`/`.jsx` too, but skips `.d.ts`.
- Next.js `redirects()` analysis now spans multiple lines and catches `has: [{ type: 'query' }]`-driven destination hosts (also `next.config.ts`/`.mjs`/`.cjs`).
- nginx: `return 30x $arg_*`, `https://$arg_host`, and variables tainted through `map`/`set` from `$arg_*`/`$http_referer`; `$host`/`$server_name` stay allowed.
- `_redirects` and `vercel.json` are now parsed with static-link-sentinel's parsers (new dependency) instead of a second copy.

### Packaging

- Dual ESM + CommonJS: `import` loads `src/`, `require` loads a bundled `dist/index.cjs`, via package.json `exports`.
- TypeScript declarations are generated from the source (`dist/types`) instead of hand-written.
- CI runs build, tests and a require+import check on Node 18/20/22; releases use `npm publish --provenance`.

- First release: open redirect and mixed content finder for build directories and live crawls, with 13 rules: active/passive mixed content, insecure forms and links, client-side open redirects, open redirect rules in Netlify/Vercel/nginx/Apache configs, redirect parameters, meta refresh, HTTPS downgrades, long chains, missing HTTP→HTTPS redirect, and opt-in safe probing with a `.invalid` canary.
- Text, JSON, SARIF and Markdown output; allowlist with expiry; per-rule severity; `--fail-on`; composite GitHub Action.
