/**
 * Response comparison that tolerates volatile content (timestamps, request
 * ids, nonces) instead of naive byte equality.
 *
 * Strategy:
 *  1. normalize(): mask well-known volatile shapes (ISO timestamps, UUIDs,
 *     epoch millis, long hex tokens) plus caller-supplied strings (the random
 *     cache-buster values we injected ourselves).
 *  2. Learn a baseline set from N requests; a probe "differs" when it
 *     introduces lines never seen in any baseline, or drops a line that was
 *     stable across all baselines.
 *  3. Every probe is sent twice; only reproducible differences count.
 */

const VOLATILE_PATTERNS: RegExp[] = [
  /\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\b/g, // ISO 8601
  /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, // UUID
  /\b1\d{12}\b/g, // epoch millis (2001–2033)
  /\b[0-9a-f]{24,}\b/gi, // long hex tokens / CSRF-ish
];

export function normalize(body: string, extraValues: string[] = []): string {
  let out = body;
  for (const re of VOLATILE_PATTERNS) out = out.replace(re, '§');
  for (const v of extraValues) {
    if (v.length >= 4) out = out.split(v).join('§');
  }
  return out;
}

function toLines(normalized: string): string[] {
  return normalized
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

export interface Baseline {
  lineSets: Set<string>[];
  union: Set<string>;
  stable: Set<string>; // lines present in EVERY baseline
}

export function learnBaseline(normalizedBodies: string[]): Baseline {
  const lineSets = normalizedBodies.map((b) => new Set(toLines(b)));
  const union = new Set<string>();
  for (const s of lineSets) for (const l of s) union.add(l);
  const stable = new Set<string>();
  if (lineSets.length > 0) {
    for (const l of lineSets[0]) {
      if (lineSets.every((s) => s.has(l))) stable.add(l);
    }
  }
  return { lineSets, union, stable };
}

export interface BodyDiff {
  differs: boolean;
  added: string[]; // lines in probe never seen in baselines
  removed: string[]; // stable baseline lines missing from probe
}

export function diffAgainstBaseline(normalizedProbe: string, baseline: Baseline): BodyDiff {
  const probeLines = toLines(normalizedProbe);
  const probeSet = new Set(probeLines);
  const added = probeLines.filter((l) => !baseline.union.has(l));
  const removed: string[] = [];
  for (const l of baseline.stable) {
    if (!probeSet.has(l)) removed.push(l);
  }
  return { differs: added.length > 0 || removed.length > 0, added, removed };
}
