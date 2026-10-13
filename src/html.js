// Small, tolerant HTML scanner: tags with attributes, inline scripts and styles, with line numbers.
const lineAt = (text, i) => { let n = 1; for (let k = 0; k < i; k++) if (text.charCodeAt(k) === 10) n++; return n; };
export function scanHtml(text) {
  const tags = []; const scripts = []; const styles = [];
  const re = /<!--[\s\S]*?-->|<(script|style)\b([^>]*)>([\s\S]*?)<\/\1\s*>|<([a-zA-Z][\w:-]*)\b((?:[^>"']|"[^"]*"|'[^']*')*)>/g;
  let m; let lastIdx = 0; let line = 1;
  const ln = (i) => { for (let k = lastIdx; k < i; k++) if (text.charCodeAt(k) === 10) line++; lastIdx = i; return line; };
  while ((m = re.exec(text))) {
    if (m[0].startsWith('<!--')) continue;
    const l = ln(m.index);
    if (m[1]) { const attrs = parseAttrs(m[2]); const name = m[1].toLowerCase(); tags.push({ name, attrs, line: l }); if (m[3].trim()) (name === 'script' ? scripts : styles).push({ code: m[3], line: l, attrs }); continue; }
    tags.push({ name: m[4].toLowerCase(), attrs: parseAttrs(m[5]), line: l });
  }
  return { tags, scripts, styles };
}
export function parseAttrs(s) {
  const out = {}; const re = /([^\s=/>"']+)(?:\s*=\s*("([^"]*)"|'([^']*)'|([^\s>"']+)))?/g; let m;
  while ((m = re.exec(s))) out[m[1].toLowerCase()] = decode(m[3] ?? m[4] ?? m[5] ?? '');
  return out;
}
export const decode = (s) => s.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n)).replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCharCode(parseInt(n, 16)));
export { lineAt };
