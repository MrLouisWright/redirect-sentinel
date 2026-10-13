function go() { location.assign(decodeURIComponent(location.hash.slice(1))); }
function safe() { const n = new URLSearchParams(location.search).get('next'); if (n && n.startsWith('/') && !n.startsWith('//')) location.href = n; }
window.open(document.referrer);
location.href = '/home';
