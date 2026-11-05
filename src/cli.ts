#!/usr/bin/env node
import { SUITE_VERSION } from './version.js';
import { isProfile, type Profile } from './profiles.js';
import { formatReport } from './report.js';
import { runPreflight, checkPrereqs } from './preflight.js';
import { assembleCapabilityProbes } from './probes.js';

const COMMANDS = ['preflight', 'run', 'gateway', 'collector'] as const;

function usage(): void {
  process.stderr.write(
    [
      `agent-sandbox ${SUITE_VERSION}`,
      '',
      'Usage:',
      '  agent-sandbox preflight [--profile <dev|linux-sandbox>] [--json]',
      '                                 Probe capabilities + run the attacker suite',
      '  agent-sandbox run -- <cmd>     Launch a command inside the sandbox',
      '  agent-sandbox gateway          Run the model auth gateway',
      '  agent-sandbox collector        Run the trusted evidence collector',
      '',
    ].join('\n'),
  );
}

function parseFlag(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
}

async function cmdPreflight(argv: string[]): Promise<number> {
  const json = argv.includes('--json');
  const profileArg = parseFlag(argv, '--profile') ?? 'linux-sandbox';
  if (!isProfile(profileArg)) {
    process.stderr.write(`invalid --profile: ${profileArg}\n`);
    return 2;
  }
  const profile = profileArg as Profile;

  const prereqs = await checkPrereqs();
  const sourceArg = parseFlag(argv, '--source');
  // The attacker suite is registered by the later stacked module; capability
  // probes are assembled from whatever this host supports.
  const report = await runPreflight({
    profile,
    capabilityProbes: assembleCapabilityProbes(sourceArg ? { sourceDir: sourceArg } : {}),
  });

  if (json) {
    process.stdout.write(JSON.stringify({ prereqs, report }, null, 2) + '\n');
  } else {
    process.stdout.write('prerequisites:\n');
    for (const p of prereqs) {
      process.stdout.write(`  [${p.ok ? '+' : 'x'}] ${p.name} — ${p.detail}\n`);
    }
    process.stdout.write('\n' + formatReport(report) + '\n');
  }
  return report.publishable ? 0 : 1;
}

async function main(): Promise<number> {
  const [, , cmd, ...rest] = process.argv;
  if (!cmd || cmd === '-h' || cmd === '--help') {
    usage();
    return cmd ? 0 : 2;
  }
  if (!(COMMANDS as readonly string[]).includes(cmd)) {
    process.stderr.write(`unknown command: ${cmd}\n`);
    usage();
    return 2;
  }
  switch (cmd) {
    case 'preflight':
      return cmdPreflight(rest);
    default:
      process.stderr.write(`${cmd}: not implemented in this build\n`);
      return 1;
  }
}

main().then(
  (code) => process.exit(code),
  (err: unknown) => {
    process.stderr.write(`fatal: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  },
);
