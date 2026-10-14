# redirect-sentinel

> Find open redirects and mixed content in a built site (offline) or a live crawl: http:// scripts and styles on HTTPS pages, insecure forms, client-side redirects fed by the URL, open redirect rules in `_redirects`/`vercel.json`/nginx, HTTPS downgrades, and optional safe redirect probing.

Point `redirect-sentinel` at your build output (`dist/`, `public/`, `_site/`) in CI, or at a URL to crawl the live site. CLI, library and GitHub Action. Node.js 18+, **zero runtime dependencies**. Broken links are out of scope (see [static-link-sentinel](https://github.com/MrLouisWright/static-link-sentinel)).

## What it checks

- **Mixed content** on HTTPS pages: `http://` scripts, stylesheets, `@import`, iframes, objects and `<base>` (active, high); images, `srcset`, media, icons and CSS `url()` (passive, medium); forms posting to `http://`; `http://` links (low, once per host). `localhost` URLs are ignored. Use `--http` if the static site is not served over HTTPS.
- **Client-side open redirects**: `location = …`, `location.assign/replace`, `window.open`, `router.push`, `navigate` fed by `location.search`/`hash`, `URLSearchParams`, `document.referrer` or `window.name`, directly or through a variable. Redirects guarded by `startsWith('/')` or an origin check are skipped. This is a heuristic, not a data-flow engine: minified bundles are only checked for direct flows.
- **Server redirect rules**: Netlify `_redirects` and `netlify.toml`, `vercel.json`/`next.config.js`, nginx (`return 302 $arg_url`) and Apache (`RewriteRule … %1 [R]`) rules whose destination host comes from the request.
- **Links** that pass a full URL in a redirect-style parameter (`next`, `url`, `returnTo`, `redirect_uri`, `continue`, `goto`…).
- **Crawl only**: redirect chains longer than 3 hops, `https://` → `http://` downgrades (including meta refresh), `http://` not redirecting to `https://`, and same-origin JavaScript files.
- **`--probe`** (crawl only, opt-in): for each same-origin link with a redirect-style parameter, requests it with `https://redirect-sentinel.invalid/`, `//redirect-sentinel.invalid/` and similar payloads, without following the redirect. A `Location` pointing at that host is a confirmed `open-redirect` (critical). `.invalid` can never resolve, so nobody is sent anywhere. **Only probe sites you own or are authorised to test.**

## Rules

| Rule | Default | Meaning |
|---|---|---|
| `open-redirect` | critical | Confirmed open redirect: a parameter sends visitors to any site |
| `open-redirect-js` | high | Client-side redirect or window.open fed by URL, hash or referrer |
| `open-redirect-config` | high | Redirect rule sends visitors to a host taken from the request |
| `mixed-content-active` | high | HTTPS page loads a script, stylesheet, frame or object over http:// |
| `redirect-downgrade` | high | Redirect goes from https:// to http:// |
| `insecure-form` | high | Form posts to an http:// URL |
| `mixed-content-passive` | medium | HTTPS page loads an image, audio or video over http:// |
| `http-no-redirect` | medium | http:// version of the site does not redirect to https:// |
| `redirect-param` | medium | Link passes a full URL in a redirect-style parameter (next, url, returnTo…) |
| `meta-refresh-external` | low | Meta refresh redirects to another site |
| `insecure-link` | low | Link to an http:// URL |
| `redirect-chain` | low | Redirect chain longer than 3 hops |
| `fetch-error` | low | Page could not be fetched |

## Install and run

```bash
npx redirect-sentinel dist/                            # offline, in CI after the build
npx redirect-sentinel https://staging.example.com --max-pages 200
npx redirect-sentinel https://staging.example.com --probe --fail-on high
```

## Library

```js
import { check, analyzeHtml, analyzeJs } from 'redirect-sentinel';
const report = await check(['dist'], { severity: { 'insecure-link': 'off' } });
```

## Configuration

Put a `.redirect-sentinel.json` in the working directory (or pass `--config <file>`). Every key is optional; CLI flags override the file.

```json
{
  "failOn": "high",
  "severity": { "insecure-link": "high" },
  "allow": [
    { "rule": "insecure-link", "match": "http://partner.example.org*", "reason": "Accepted risk, ticket SEC-123", "expires": "2027-03-31" }
  ]
}
```

- **`severity`** changes the severity of any rule, or turns it `off`.
- **`allow`** suppresses findings. Each entry needs a `rule` (globs such as `insecure-*` work) and a `reason`, and can be narrowed with `target` and `match` (a glob tested against the target, location and value). Suppressed findings are listed in the JSON report. When `expires` (YYYY-MM-DD) has passed, the finding comes back together with an `allow-expired` finding, so exceptions can't be forgotten. Entries that match nothing are reported as `allow-unused` (info).

## Output and exit codes

- `--format text|json|sarif|markdown` for stdout, plus `--json`, `--sarif` and `--markdown <file>` to write extra copies in one run. SARIF 2.1.0 works with GitHub code scanning.
- `--fail-on critical|high|medium|low|info|none` (default `high`).
- Exit code **0**: passed. **1**: at least one finding at or above `--fail-on`. **2**: usage or config error, or a target could not be checked.
- `--list-rules` prints every rule with its default severity.

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # only for the SARIF upload
steps:
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
    with: { persist-credentials: false }
  - uses: MrLouisWright/redirect-sentinel@v1
    with:
      targets: 'dist'
      fail-on: high
      sarif: redirect-sentinel.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with: { sarif_file: redirect-sentinel.sarif }
```

Inputs: `targets`, `fail-on`, `config`, `sarif`, `json`, `job-summary` (Markdown report in the job summary, default `true`), `args` (extra CLI flags), `max-pages`, `probe`. Outputs: `markdown-file`, `exit-code`.

## Requirements

Node.js 18 or newer. No runtime dependencies.

## Support

If this project is useful to you, you can support its development with a donation: [Buy me a coffee](https://donate.stripe.com/aFa00lek3cvX4Ds2Fk9EI0b). It helps keep these tools maintained, documented and free for everyone.

## License

MIT © Louis Wright ([Louis Wright](https://github.com/MrLouisWright))
