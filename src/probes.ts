/**
 * Candidate unkeyed inputs. Values carry a per-scan canary so reflection is
 * unambiguous and evidence is greppable.
 */

export interface HeaderProbe {
  name: string;
  value: (canary: string) => string;
}

export const HEADER_PROBES: HeaderProbe[] = [
  { name: 'X-Forwarded-Host', value: (c) => `${c}.evil.example` },
  { name: 'X-Host', value: (c) => `${c}.evil.example` },
  { name: 'X-Forwarded-Server', value: (c) => `${c}.evil.example` },
  { name: 'X-Original-URL', value: (c) => `/${c}` },
  { name: 'X-Rewrite-URL', value: (c) => `/${c}` },
  { name: 'X-Forwarded-Scheme', value: (c) => `http${c}` },
  { name: 'Referer', value: (c) => `http://${c}.evil.example/` },
  { name: 'User-Agent', value: (c) => `Mozilla/5.0 ${c}` },
  { name: 'Accept-Language', value: (c) => c },
  { name: 'X-Forwarded-For', value: (c) => `203.0.113.${c.length}` },
  // Host itself: cache layers frequently normalize it (case/port) while the
  // origin still reflects the raw value.
  { name: 'Host', value: (c) => `${c}.evil.example` },
];

export const PARAM_PROBES: string[] = [
  'q',
  'search',
  'query',
  'next',
  'url',
  'redirect',
  'redir',
  'return',
  'callback',
  'ref',
  'utm_source',
  'utm_medium',
  'utm_campaign',
  'lang',
  'theme',
  'id',
  'page',
];

/** Case / encoding / duplicate transforms applied to params that reflect. */
export type ParamTransform = 'plain' | 'case' | 'encoded-name' | 'duplicate';

export function transformParamName(name: string, t: ParamTransform): string {
  switch (t) {
    case 'case':
      return name.length > 0 ? name[0].toUpperCase() + name.slice(1) : name;
    case 'encoded-name':
      return name
        .split('')
        .map((ch, i) => (i === 0 ? `%${ch.charCodeAt(0).toString(16)}` : ch))
        .join('');
    default:
      return name;
  }
}
