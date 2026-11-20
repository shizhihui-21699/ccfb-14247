/**
 * Minimal raw HTTP GET helper. The path is sent verbatim so probes keep full
 * control over encoding, duplicate params and delimiters.
 */
import http from 'node:http';

export interface RawResponse {
  status: number;
  headers: Record<string, string | string[]>;
  body: string;
}

export function header(res: RawResponse, name: string): string | undefined {
  const v = res.headers[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

export function rawGet(
  target: URL,
  rawPath: string,
  headers: Record<string, string> = {},
): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: target.hostname,
        port: target.port || 80,
        method: 'GET',
        path: rawPath,
        headers: { Connection: 'close', ...headers },
        timeout: 8000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers as Record<string, string | string[]>,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
      },
    );
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('request timed out')));
    req.end();
  });
}
