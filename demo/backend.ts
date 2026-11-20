/**
 * Demo origin server (port 4000).
 *
 * Deliberately contains several reflection points whose inputs a front cache
 * may not include in its cache key. Every page also contains volatile content
 * (timestamp + request id) to exercise the detector's noise masking.
 *
 * Planted issues:
 *  V1  X-Forwarded-Host reflected into <link rel="canonical"> (unkeyed header)
 *  V2  utm_source reflected into body (cache ignore-listed param)
 *  V3  duplicate `q` param: backend uses LAST value (cache keys FIRST)
 *  V4  raw Host header (incl. port) reflected into asset URL
 *      (cache normalizes host by stripping the port)
 * Controls:
 *  C1  `next` param on /redirect.html: reflected, but fully keyed
 *  C2  /api/data.json: Cache-Control no-store, never cached
 *  C3  /static/app.js: cacheable, no reflection
 */
import http from 'node:http';
import crypto from 'node:crypto';

export const BACKEND_PORT = 4000;

function esc(s: string): string {
  // Intentionally NOT a sanitizer for the reflected demo values — the pages
  // below reflect raw input on purpose. This helper is only for static text.
  return s;
}

export function startBackend(): Promise<http.Server> {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://origin.internal');
    const path = url.pathname;
    const host = req.headers['host'] ?? 'unknown';
    const xfh = req.headers['x-forwarded-host'];
    const ts = new Date().toISOString();
    const reqId = crypto.randomUUID();
    const volatileBlock = `<!-- req:${reqId} ts:${ts} -->\n<span id="server-time">${ts}</span>`;

    const send = (status: number, body: string, headers: Record<string, string> = {}) => {
      res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', ...headers });
      res.end(body);
    };

    if (path === '/') {
      res.writeHead(302, { Location: '/index.html' });
      res.end();
      return;
    }

    if (path === '/index.html') {
      // V1: unkeyed header reflected into canonical link
      const canonicalHost = Array.isArray(xfh) ? xfh[0] : xfh ?? host;
      // V2: cache-ignored analytics param reflected into body
      const utm = url.searchParams.get('utm_source');
      // V4: raw Host (with port) reflected into asset URL
      const assetHost = host;
      send(
        200,
        [
          '<!doctype html><html><head>',
          `<link rel="canonical" href="http://${esc(canonicalHost)}/index.html">`,
          `<script src="http://${esc(assetHost)}/static/app.js"></script>`,
          '</head><body>',
          '<h1>Demo Shop</h1>',
          utm !== null ? `<p class="referrer">You came from: ${esc(utm)}</p>` : '<p class="referrer">Welcome!</p>',
          volatileBlock,
          '</body></html>',
        ].join('\n'),
      );
      return;
    }

    if (path === '/search.html') {
      // V3: duplicate-param discrepancy — backend uses the LAST `q`
      const all = url.searchParams.getAll('q');
      const q = all.length > 0 ? all[all.length - 1] : '';
      send(
        200,
        [
          '<!doctype html><html><body>',
          '<h1>Search</h1>',
          `<div id="query">You searched for: ${esc(q)}</div>`,
          volatileBlock,
          '</body></html>',
        ].join('\n'),
      );
      return;
    }

    if (path === '/redirect.html') {
      // C1: reflected param that IS in the cache key — detector must not flag it
      const next = url.searchParams.get('next') ?? '/index.html';
      send(
        200,
        [
          '<!doctype html><html><body>',
          `<a id="continue" href="${esc(next)}">Continue</a>`,
          volatileBlock,
          '</body></html>',
        ].join('\n'),
      );
      return;
    }

    if (path === '/api/data.json') {
      // C2: explicitly non-cacheable
      send(200, JSON.stringify({ ok: true, ts, reqId }), {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
      });
      return;
    }

    if (path === '/static/app.js') {
      // C3: cacheable static asset, nothing reflected
      send(200, `console.log("app"); // built 2024-01-01\n`, {
        'Content-Type': 'application/javascript',
        'Cache-Control': 'public, max-age=300',
      });
      return;
    }

    send(404, '<h1>404</h1>');
  });

  return new Promise((resolve) => {
    server.listen(BACKEND_PORT, '127.0.0.1', () => resolve(server));
  });
}
