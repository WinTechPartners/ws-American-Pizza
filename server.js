// Static server for the American Pizza site. No dependencies.
// Serves index.html at "/", adds security headers, gives the page's inline scripts a
// per-request CSP nonce, and generates robots.txt and sitemap.xml for whatever host it runs on.
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const PORT = process.env.PORT || 3000;
const TYPES = {
  '.html': 'text/html; charset=utf-8', '.txt': 'text/plain; charset=utf-8', '.xml': 'application/xml; charset=utf-8',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8',
};

function publicUrl(req) {
  const env = (process.env.PUBLIC_URL || '').replace(/\/+$/, '');
  if (env) return env;
  const proto = req.headers['x-forwarded-proto'] || 'http';
  return `${proto}://${req.headers.host}`;
}

function securityHeaders(res, nonce) {
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: https://res.cloudinary.com https://images.unsplash.com",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
    'upgrade-insecure-requests',
  ].join('; '));
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
}

function send(res, status, type, body, extra) {
  res.writeHead(status, Object.assign({ 'Content-Type': type, 'Content-Length': Buffer.byteLength(body) }, extra || {}));
  res.end(body);
}

const server = http.createServer((req, res) => {
  const nonce = crypto.randomBytes(16).toString('base64');
  securityHeaders(res, nonce);
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'text/plain', 'Method not allowed');
  let p;
  try { p = decodeURIComponent(new URL(req.url, 'http://x').pathname); } catch (e) { return send(res, 400, 'text/plain', 'Bad request'); }

  if (p === '/' || p === '/index.html') {
    let html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
    html = html.replace(/<script>/g, `<script nonce="${nonce}">`); // JSON-LD is data, not code; it needs no nonce
    return send(res, 200, TYPES['.html'], html, { 'Cache-Control': 'public, max-age=300' });
  }
  if (p === '/robots.txt') {
    return send(res, 200, TYPES['.txt'], `User-agent: *\nAllow: /\n\nSitemap: ${publicUrl(req)}/sitemap.xml\n`);
  }
  if (p === '/sitemap.xml') {
    const today = new Date().toISOString().slice(0, 10);
    const xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
      `  <url><loc>${publicUrl(req)}/</loc><lastmod>${today}</lastmod><changefreq>monthly</changefreq><priority>1.0</priority></url>\n</urlset>\n`;
    return send(res, 200, TYPES['.xml'], xml);
  }
  if (p === '/security.txt') p = '/.well-known/security.txt';

  // Static files: only what sits inside the repo, never the server, config, git internals, or backups.
  const file = path.normalize(path.join(ROOT, p));
  if (!file.startsWith(ROOT) || /[\\/]\.git([\\/]|$)|server\.js$|package\.json$|railway\.json$|backup/i.test(file)) {
    return send(res, 404, 'text/plain', 'Not found');
  }
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) return send(res, 404, 'text/plain', 'Not found');
    const type = TYPES[path.extname(file).toLowerCase()] || 'application/octet-stream';
    const cache = /^\/(assets|\.well-known)\//.test(p) ? 'public, max-age=86400' : 'public, max-age=3600';
    res.writeHead(200, { 'Content-Type': type, 'Content-Length': st.size, 'Cache-Control': cache });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  });
});

server.listen(PORT, '0.0.0.0', () => console.log(`American Pizza site on :${PORT}`));
