/**
 * Safe exploitability verification.
 *
 * Every request that can write to the cache carries a random cache-buster in
 * a position confirmed to be part of the cache key (see detector preflight).
 * Poisoning is therefore proven only inside an isolated keyspace that real
 * users never collide with: we show that two requests differing ONLY in the
 * suspect input map to the SAME cache entry, and the second ("victim")
 * request is served the first ("attacker") request's content.
 */
import { rawGet, header } from './http.ts';
import crypto from 'node:crypto';

const rand = (n = 4): string => crypto.randomBytes(n).toString('hex');

export interface VerifyResult {
  keyed: boolean | 'unknown';
  poisoningVerified: boolean;
  evidence: string[];
}

interface Step {
  label: string;
  path: string;
  headers?: Record<string, string>;
}

async function runSteps(
  target: URL,
  attacker: Step,
  victim: Step,
  attackerMarker: string,
): Promise<VerifyResult> {
  const evidence: string[] = [];
  const a1 = await rawGet(target, attacker.path, attacker.headers);
  const a1Cache = header(a1, 'x-cache') ?? '?';
  evidence.push(`prime  ${attacker.label} -> ${a1.status} X-Cache:${a1Cache}`);
  if (a1Cache !== 'MISS') {
    return { keyed: 'unknown', poisoningVerified: false, evidence: [...evidence, 'prime request was not a cache MISS; cannot verify safely'] };
  }
  if (!a1.body.includes(attackerMarker)) {
    return { keyed: 'unknown', poisoningVerified: false, evidence: [...evidence, 'attacker marker not reflected; nothing to poison with'] };
  }
  const a2 = await rawGet(target, attacker.path, attacker.headers);
  evidence.push(`replay ${attacker.label} -> ${a2.status} X-Cache:${header(a2, 'x-cache') ?? '?'}`);
  if (header(a2, 'x-cache') !== 'HIT') {
    return { keyed: 'unknown', poisoningVerified: false, evidence: [...evidence, 'response was not stored by the cache'] };
  }
  const v = await rawGet(target, victim.path, victim.headers);
  const vCache = header(v, 'x-cache') ?? '?';
  const poisoned = vCache === 'HIT' && v.body.includes(attackerMarker);
  evidence.push(`victim ${victim.label} -> ${v.status} X-Cache:${vCache} ${poisoned ? 'SERVED ATTACKER CONTENT' : 'served own content'}`);
  if (vCache === 'MISS') {
    return { keyed: true, poisoningVerified: false, evidence: [...evidence, 'victim request missed the cache: input IS part of the cache key'] };
  }
  if (poisoned) {
    return { keyed: false, poisoningVerified: true, evidence };
  }
  return { keyed: 'unknown', poisoningVerified: false, evidence: [...evidence, 'cache HIT but content not poisoned; inconclusive'] };
}

/** Header (other than Host) is absent from the cache key. */
export function verifyHeaderUnkeyed(target: URL, path: string, headerName: string): Promise<VerifyResult> {
  const buster = rand(6);
  const valA = `cpda${rand(4)}.evil.example`;
  const valB = `cpdb${rand(4)}.evil.example`;
  const p = `${path}?__cpb=${buster}`;
  return runSteps(
    target,
    { label: `${headerName}: ${valA}`, path: p, headers: { [headerName]: valA } },
    { label: `${headerName}: ${valB}`, path: p, headers: { [headerName]: valB } },
    valA,
  );
}

/** Query param (name sent verbatim) is absent from the cache key. */
export function verifyParamUnkeyed(target: URL, path: string, rawParamName: string): Promise<VerifyResult> {
  const buster = rand(6);
  const valA = `cpda${rand(4)}`;
  const valB = `cpdb${rand(4)}`;
  return runSteps(
    target,
    { label: `?${rawParamName}=${valA}`, path: `${path}?${rawParamName}=${valA}&__cpb=${buster}` },
    { label: `?${rawParamName}=${valB}`, path: `${path}?${rawParamName}=${valB}&__cpb=${buster}` },
    valA,
  );
}

/**
 * Duplicate-param discrepancy: cache keys the FIRST value, origin uses the
 * LAST. The unique first value isolates the keyspace, so only our own probe
 * entry is poisoned.
 */
export function verifyDuplicateParam(target: URL, path: string, paramName: string): Promise<VerifyResult> {
  const buster = rand(6);
  const uniqueFirst = `cpdu${rand(4)}`;
  const payload = `cpdx${rand(4)}`;
  return runSteps(
    target,
    { label: `?${paramName}=${uniqueFirst}&${paramName}=${payload}`, path: `${path}?${paramName}=${uniqueFirst}&${paramName}=${payload}&__cpb=${buster}` },
    { label: `?${paramName}=${uniqueFirst} (victim)`, path: `${path}?${paramName}=${uniqueFirst}&__cpb=${buster}` },
    payload,
  );
}

/**
 * Host normalization discrepancy: cache strips the port from the key, origin
 * reflects the raw Host (with port). A random subdomain isolates the keyspace.
 */
export function verifyHostPortUnkeyed(target: URL, path: string): Promise<VerifyResult> {
  const buster = rand(6);
  const base = `cpdh${rand(4)}.example`;
  const p = `${path}?__cpb=${buster}`;
  return runSteps(
    target,
    { label: `Host: ${base}:31337`, path: p, headers: { Host: `${base}:31337` } },
    { label: `Host: ${base} (victim)`, path: p, headers: { Host: base } },
    ':31337',
  );
}
