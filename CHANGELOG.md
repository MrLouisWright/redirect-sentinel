# Changelog

## 1.0.0 - 2026-10-14

- First release: open redirect and mixed content finder for build directories and live crawls, with 13 rules: active/passive mixed content, insecure forms and links, client-side open redirects, open redirect rules in Netlify/Vercel/nginx/Apache configs, redirect parameters, meta refresh, HTTPS downgrades, long chains, missing HTTP→HTTPS redirect, and opt-in safe probing with a `.invalid` canary.
- Text, JSON, SARIF and Markdown output; allowlist with expiry; per-rule severity; `--fail-on`; composite GitHub Action.
