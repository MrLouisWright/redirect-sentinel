// Safe redirect helpers: allow same-site relative paths (and optional allowlisted hosts), reject everything else.
const CTRL = /[\u0000-\u001f\u007f\\]/;

/**
 * True when `target` stays on this site (relative path like "/account") or goes to an allowlisted host.
 * Rejects scheme-relative ("//evil"), backslash tricks ("/\\evil"), "javascript:", encoded slashes and control chars.
 * opts: { allowedHosts: string[] (exact, or ".example.com" for subdomains), base: 'https://mysite.example', allowHttp: false }
 */
export function isSafeRedirect(target, opts = {}) {
  if (typeof target !== 'string' || !target || target.length > 2048) return false;
  let t = target.trim();
  if (t !== target || CTRL.test(t)) return false;
  let dec = t; try { dec = decodeURIComponent(t); } catch { return false; }
  if (CTRL.test(dec) || /^\/\//.test(dec) || /^\/\\/.test(dec)) return false;
  if (t.startsWith('/') && !t.startsWith('//')) {
    try { const base = new URL(opts.base || 'https://local.invalid'); return new URL(t, base).origin === base.origin; } catch { return false; }
  }
  let u; try { u = new URL(t); } catch { return false; }
  if (u.protocol !== 'https:' && !(opts.allowHttp && u.protocol === 'http:')) return false;
  if (u.username || u.password) return false;
  const hosts = [...(opts.allowedHosts || [])];
  if (opts.base) try { hosts.push(new URL(opts.base).hostname); } catch {}
  const h = u.hostname.toLowerCase();
  return hosts.some((a) => { a = String(a).toLowerCase(); return a.startsWith('.') ? h.endsWith(a) || h === a.slice(1) : h === a; });
}

/** Return `target` when safe, else `fallback` (default "/"). */
export function safeRedirectUrl(target, fallback = '/', opts = {}) { return isSafeRedirect(target, opts) ? target : fallback; }

/**
 * Express/Connect middleware: adds res.safeRedirect(target, [status]) which falls back to opts.fallback for unsafe targets.
 * app.use(safeRedirectMiddleware({ allowedHosts: ['.example.com'] }))
 */
export function safeRedirectMiddleware(opts = {}) {
  return function safeRedirect(req, res, next) {
    res.safeRedirect = (target, status = 302) => {
      if (typeof target === 'number') [status, target] = [target, status];
      const url = safeRedirectUrl(target, opts.fallback ?? '/', opts);
      if (typeof res.redirect === 'function') return res.redirect(status, url);
      res.statusCode = status; res.setHeader('location', url); res.end();
    };
    next?.();
  };
}

/**
 * Next.js: safe destination from a URL/searchParams. Use in middleware or route handlers:
 * return NextResponse.redirect(new URL(nextSafeRedirect(req.nextUrl, 'next'), req.url))
 */
export function nextSafeRedirect(urlOrParams, param = 'next', opts = {}) {
  const sp = urlOrParams?.searchParams ?? urlOrParams;
  const v = typeof sp?.get === 'function' ? sp.get(param) : sp?.[param];
  return safeRedirectUrl(Array.isArray(v) ? v[0] : v, opts.fallback ?? '/', opts);
}
