/**
 * CLI: node src/cli.ts --target http://127.0.0.1:8080 --paths /index.html,/search.html [--report out.json]
 */
import { writeFileSync } from 'node:fs';
import { scanPath } from './detector.ts';
import type { PathReport, Finding } from './detector.ts';

function parseArgs(argv: string[]): { target: string; paths: string[]; report?: string } {
  const args: Record<string, string> = {};
  for (let i = 2; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      args[argv[i].slice(2)] = argv[i + 1] ?? '';
      i++;
    }
  }
  if (!args.target || !args.paths) {
    console.error('usage: node src/cli.ts --target <base-url> --paths <comma-separated> [--report file.json]');
    process.exit(2);
  }
  return { target: args.target, paths: args.paths.split(','), report: args.report };
}

const SEV_MARK: Record<Finding['severity'], string> = { high: '[HIGH]', medium: '[MED ]', info: '[info]' };

function printReport(r: PathReport): void {
  console.log(`\n=== ${r.path} ===`);
  if (r.note) {
    console.log(`  note: ${r.note}`);
    return;
  }
  if (r.findings.length === 0) {
    console.log('  no influencing unkeyed inputs found');
  }
  for (const f of r.findings) {
    const keyed = f.keyed === 'unknown' ? 'unknown' : f.keyed ? 'keyed' : 'UNKEYED';
    console.log(`  ${SEV_MARK[f.severity]} ${f.input}`);
    console.log(`         influences-response=yes cache-key=${keyed} poisoning-verified=${f.poisoningVerified ? 'YES' : 'no'}`);
    for (const line of f.evidence.slice(0, 6)) console.log(`         | ${line}`);
  }
  if (r.safetyAudit.checked) {
    console.log(
      `  safety: clean-URL entry ${r.safetyAudit.cleanUrlContainsCanary ? 'CONTAINS CANARY — production cache was touched!' : 'clean (all probes stayed in isolated cache keys)'}`,
    );
  }
}

async function main(): Promise<void> {
  const { target, paths, report } = parseArgs(process.argv);
  const targetUrl = new URL(target);
  const reports: PathReport[] = [];
  for (const p of paths) {
    process.stdout.write(`scanning ${p} ...\n`);
    reports.push(await scanPath(targetUrl, p));
  }
  for (const r of reports) printReport(r);

  const high = reports.flatMap((r) => r.findings).filter((f) => f.severity === 'high');
  console.log(`\n${high.length} verified poisoning vector(s) across ${reports.length} path(s).`);
  if (report) {
    writeFileSync(report, JSON.stringify({ target, scannedAt: new Date().toISOString(), reports }, null, 2));
    console.log(`report written to ${report}`);
  }
  process.exit(high.length > 0 ? 1 : 0);
}

await main();
