/**
 * Scan orchestration.
 *
 * Per path:
 *  1. Preflight — confirm the path is cacheable and that our cache-buster
 *     param IS part of the cache key (otherwise safe isolation is impossible
 *     and the path is skipped).
 *  2. Baseline — 3 requests, volatile content normalized away, stable line
 *     set learned.
 *  3. Influence probes — candidate headers / params carrying canaries; a
 *     probe counts only if the difference reproduces on a second request.
 *  4. Key-membership verification — for every influencing input, prove
 *     whether two requests differing only in that input collide on one cache
 *     entry (isolated by the buster), i.e. real poisoning potential.
 *  5. Transforms — for reflecting params also try case / percent-encoded
 *     names and duplicate occurrences (parser discrepancies).
 *  6. Safety audit — fetch the clean URL and assert none of our canaries
 *     leaked into the production cache entry.
 */
import crypto from 'node:crypto';
import { rawGet, header } from './http.ts';
import type { RawResponse } from './http.ts';
import { normalize, learnBaseline, diffAgainstBaseline } from './diff.ts';
import type { Baseline } from './diff.ts';
import { HEADER_PROBES, PARAM_PROBES, transformParamName } from './probes.ts';
import {
  verifyHeaderUnkeyed,
  verifyParamUnkeyed,
  verifyDuplicateParam,
  verifyHostPortUnkeyed,
} from './verify.ts';
import type { VerifyResult } from './verify.ts';

const BUSTER_PARAM = '__cpb';
const rand = (n = 4): string => crypto.randomBytes(n).toString('hex');

export interface Finding {
  path: string;
  input: string;
  kind: 'header' | 'param' | 'param-transform' | 'host';
  influencesResponse: boolean;
  keyed: boolean | 'unknown';
  poisoningVerified: boolean;
  severity: 'high' | 'medium' | 'info';
  evidence: string[];
}

export interface PathReport {
  path: string;
  cacheable: boolean;
  busterKeyed: boolean;
  note?: string;
  findings: Finding[];
  safetyAudit: { checked: boolean; cleanUrlContainsCanary: boolean };
}

export interface ScanContext {
  target: URL;
  busterValues: string[]; // normalized away when diffing
}

function severityOf(keyed: boolean | 'unknown', poisoningVerified: boolean): Finding['severity'] {
  if (poisoningVerified) return 'high';
  if (keyed === false) return 'medium';
  return 'info';
}

export async function scanPath(target: URL, path: string): Promise<PathReport> {
  const ctx: ScanContext = { target, busterValues: [] };
  const findings: Finding[] = [];

  const get = (rawPath: string, headers: Record<string, string> = {}): Promise<RawResponse> =>
    rawGet(target, rawPath, headers);

  const busted = (extraQuery = ''): string => {
    const b = rand(6);
    ctx.busterValues.push(b);
    return `${path}?${BUSTER_PARAM}=${b}${extraQuery}`;
  };

  // ---- 1. preflight -------------------------------------------------------
  const b1 = rand(6);
  const b2 = rand(6);
  ctx.busterValues.push(b1, b2);
  const p1 = await get(`${path}?${BUSTER_PARAM}=${b1}`);
  const p2 = await get(`${path}?${BUSTER_PARAM}=${b1}`);
  const p3 = await get(`${path}?${BUSTER_PARAM}=${b2}`);
  const x1 = header(p1, 'x-cache');
  const x2 = header(p2, 'x-cache');
  const x3 = header(p3, 'x-cache');

  if (x1 === undefined && x2 === undefined) {
    return {
      path, cacheable: false, busterKeyed: false, findings,
      note: 'no X-Cache/Age signal from the front layer; cannot confirm caching behavior, skipping (manual analysis needed)',
      safetyAudit: { checked: false, cleanUrlContainsCanary: false },
    };
  }
  const cacheable = x2 === 'HIT';
  if (!cacheable) {
    return {
      path, cacheable: false, busterKeyed: false, findings,
      note: `path is not cached (repeat request returned X-Cache:${x2 ?? 'none'}); poisoning not applicable`,
      safetyAudit: { checked: false, cleanUrlContainsCanary: false },
    };
  }
  const busterKeyed = x3 === 'MISS';
  if (!busterKeyed) {
    return {
      path, cacheable: true, busterKeyed: false, findings,
      note: `cache-buster param "${BUSTER_PARAM}" is NOT in the cache key — cannot isolate probes from production cache, aborting this path for safety`,
      safetyAudit: { checked: false, cleanUrlContainsCanary: false },
    };
  }

  // ---- 2. baseline --------------------------------------------------------
  const baselineBodies: string[] = [];
  for (let i = 0; i < 3; i++) {
    const res = await get(busted());
    baselineBodies.push(normalize(res.body, ctx.busterValues));
  }
  const baseline: Baseline = learnBaseline(baselineBodies);

  // ---- 3. influence probes ------------------------------------------------
  // Every probe runs twice; only reproducible differences count.
  async function probeInfluences(
    makePath: () => string,
    makeHeaders: () => Record<string, string>,
  ): Promise<{ influences: boolean; evidence: string[] }> {
    const evidences: string[][] = [];
    for (let i = 0; i < 2; i++) {
      const res = await get(makePath(), makeHeaders());
      const d = diffAgainstBaseline(normalize(res.body, ctx.busterValues), baseline);
      if (!d.differs) return { influences: false, evidence: [] };
      evidences.push([...d.added.map((l) => `+ ${l}`), ...d.removed.map((l) => `- ${l}`)]);
    }
    // reproducible: both runs produced the same changed-line signature
    const [a, b] = evidences.map((e) => e.join('\n'));
    if (a !== b) return { influences: false, evidence: [] };
    return { influences: true, evidence: evidences[0].slice(0, 4).map((l) => l.slice(0, 160)) };
  }

  const record = (f: Omit<Finding, 'severity'>): void => {
    findings.push({ ...f, severity: severityOf(f.keyed, f.poisoningVerified) });
  };

  // headers
  for (const hp of HEADER_PROBES) {
    const canary = `cpdh${rand(4)}`;
    const value = hp.value(canary);
    const { influences, evidence } = await probeInfluences(
      () => busted(),
      () => ({ [hp.name]: value }),
    );
    if (!influences) continue;

    let result: VerifyResult;
    let kind: Finding['kind'] = 'header';
    let input = `header:${hp.name}`;
    if (hp.name === 'Host') {
      // Host is keyed by hostname; the interesting discrepancy is port/case
      // normalization, verified with an isolated random subdomain.
      result = await verifyHostPortUnkeyed(target, path);
      kind = 'host';
      input = 'header:Host (port normalization)';
    } else {
      result = await verifyHeaderUnkeyed(target, path, hp.name);
    }
    record({
      path, input, kind,
      influencesResponse: true,
      keyed: result.keyed,
      poisoningVerified: result.poisoningVerified,
      evidence: [...evidence, ...result.evidence],
    });
  }

  // params
  const reflectingParams: string[] = [];
  for (const name of PARAM_PROBES) {
    const canary = `cpdp${rand(4)}`;
    const { influences, evidence } = await probeInfluences(
      () => busted(`&${name}=${canary}`),
      () => ({}),
    );
    if (!influences) continue;
    reflectingParams.push(name);
    const result = await verifyParamUnkeyed(target, path, name);
    record({
      path, input: `param:${name}`, kind: 'param',
      influencesResponse: true,
      keyed: result.keyed,
      poisoningVerified: result.poisoningVerified,
      evidence: [...evidence, ...result.evidence],
    });
  }

  // ---- 5. transforms on reflecting params ---------------------------------
  for (const name of reflectingParams) {
    for (const t of ['case', 'encoded-name'] as const) {
      const tName = transformParamName(name, t);
      const canary = `cpdt${rand(4)}`;
      const { influences, evidence } = await probeInfluences(
        () => busted(`&${tName}=${canary}`),
        () => ({}),
      );
      if (!influences) continue;
      const result = await verifyParamUnkeyed(target, path, tName);
      record({
        path, input: `param:${tName} (${t} of "${name}")`, kind: 'param-transform',
        influencesResponse: true,
        keyed: result.keyed,
        poisoningVerified: result.poisoningVerified,
        evidence: [...evidence, ...result.evidence],
      });
    }
    // duplicate occurrence: backend may use a different occurrence than the cache keys
    const canary = `cpdd${rand(4)}`;
    const first = `cpdf${rand(4)}`;
    const { influences, evidence } = await probeInfluences(
      () => busted(`&${name}=${first}&${name}=${canary}`),
      () => ({}),
    );
    if (influences) {
      const result = await verifyDuplicateParam(target, path, name);
      // Only report when the discrepancy is real: if the backend used the
      // FIRST occurrence (marker never reflected), there is nothing to exploit.
      if (!result.poisoningVerified && result.keyed !== false) continue;
      record({
        path, input: `param:${name} (duplicate, first/last discrepancy)`, kind: 'param-transform',
        influencesResponse: true,
        keyed: result.keyed,
        poisoningVerified: result.poisoningVerified,
        evidence: [...evidence, ...result.evidence],
      });
    }
  }

  // ---- 6. safety audit ----------------------------------------------------
  const clean = await get(path);
  const canaryLeaked = /cpd[hptdxfu][0-9a-f]{8}/.test(clean.body) || clean.body.includes('31337');

  return {
    path,
    cacheable: true,
    busterKeyed: true,
    findings,
    safetyAudit: { checked: true, cleanUrlContainsCanary: canaryLeaked },
  };
}
