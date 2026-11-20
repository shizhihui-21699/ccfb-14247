/**
 * Demo caching reverse proxy (port 8080) in front of the origin.
 *
 * Cache-key policy (realistic CDN-style, with deliberate discrepancies):
 *  - host: lowercased, PORT STRIPPED                     -> enables V4
 *  - query params: sorted; names matching /^utm_/i dropped -> enables V2
 *  - duplicate param names: FIRST occurrence kept          -> enables V3
 *  - no request headers are part of the key                -> enables V1
 *
 * Cacheability policy:
 *  - GET only; path must end in /, .html, .js or .css
 *  - response must be 200, without Set-Cookie, and its Cache-Control
 *    must not contain no-store / private / no-cache
 *  - TTL 60s; serves X-Cache: HIT|MISS and Age headers
 */
import http from 'node:http';

export const CACHE_PORT = 8080;
const TTL_MS = 60_000;

interface CacheEntry {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
  storedAt: number;
}

const store = new Map<string, CacheEntry>();

function normalizeHost(host: string | undefined): string {
  if (!host) return '';
  return host.toLowerCase().replace(/:\d+$/, ''); // strip port -> V4
}

export function cacheKey(rawUrl: string, hostHeader: string | undefined): string {
  const url = new URL(rawUrl, 'http://cache.internal');
  const rawParts = url.search.slice(1).split('&').filter(Boolean);
  const kept: string[] = [];
  const seenNames = new Set<string>();
  for (const part of rawParts) {
    const eq = part.indexOf('=');
    const rawName = eq === -1 ? part : part.slice(0, eq);
    let decodedName = rawName;
    try {
      decodedName = decodeURIComponent(rawName);
    } catch {
      /* keep raw */
    }
    if (/^utm_/i.test(decodedName)) continue; // analytics ignore-list -> V2
    if (seenNames.has(rawName)) continue; // duplicates: keep FIRST -> V3
    seenNames.add(rawName);
    kept.push(part);
  }
  kept.sort();
  const query = kept.length > 0 ? '?' + kept.join('&') : '';
  return `${normalizeHost(hostHeader)}|${url.pathname}|${query}`;
}

function isCacheablePath(pathname: string): boolean {
  return pathname === '/' || /\.(html|js|css)$/.test(pathname);
}

function isCacheableResponse(status: number, headers: http.IncomingHttpHeaders): boolean {
  if (status !== 200) return false;
  if (headers['set-cookie']) return false;
  const cc = String(headers['cache-control'] ?? '').toLowerCase();
  if (/no-store|private|no-cache/.test(cc)) return false;
  return true;
}

export function startCache(backendPort: number): Promise<http.Server> {
  const server = http.createServer((clientReq, clientRes) => {
    if (clientReq.method !== 'GET' && clientReq.method !== 'HEAD') {
      clientRes.writeHead(405).end();
      return;
    }
    const rawUrl = clientReq.url ?? '/';
    const url = new URL(rawUrl, 'http://cache.internal');
    const cacheablePath = isCacheablePath(url.pathname);
    const key = cacheKey(rawUrl, clientReq.headers.host);

    if (cacheablePath) {
      const hit = store.get(key);
      if (hit && Date.now() - hit.storedAt < TTL_MS) {
        clientRes.writeHead(hit.status, {
          ...hit.headers,
          'X-Cache': 'HIT',
          Age: String(Math.floor((Date.now() - hit.storedAt) / 1000)),
        });
        clientRes.end(hit.body);
        return;
      }
    }

    const proxyReq = http.request(
      {
        hostname: '127.0.0.1',
        port: backendPort,
        method: clientReq.method,
        path: rawUrl,
        headers: { ...clientReq.headers, host: clientReq.headers.host ?? 'localhost' },
      },
      (proxyRes) => {
        const chunks: Buffer[] = [];
        proxyRes.on('data', (c) => chunks.push(c));
        proxyRes.on('end', () => {
          const body = Buffer.concat(chunks);
          const outHeaders: Record<string, string> = {};
          for (const [k, v] of Object.entries(proxyRes.headers)) {
            if (typeof v === 'string') outHeaders[k] = v;
          }
          const status = proxyRes.statusCode ?? 502;
          if (cacheablePath && isCacheableResponse(status, proxyRes.headers)) {
            store.set(key, { status, headers: outHeaders, body, storedAt: Date.now() });
          }
          clientRes.writeHead(status, { ...outHeaders, 'X-Cache': 'MISS', Age: '0' });
          clientRes.end(body);
        });
      },
    );
    proxyReq.on('error', () => clientRes.writeHead(502).end('origin error'));
    proxyReq.end();
  });

  return new Promise((resolve) => {
    server.listen(CACHE_PORT, '127.0.0.1', () => resolve(server));
  });
}
