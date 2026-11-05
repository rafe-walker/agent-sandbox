#!/usr/bin/env node
import { SUITE_VERSION } from './version.js';
import { isProfile, type Profile } from './profiles.js';
import { formatReport } from './report.js';
import { runPreflight, checkPrereqs } from './preflight.js';
import { assembleCapabilityProbes } from './probes.js';

const COMMANDS = ['preflight', 'run', 'gateway', 'collector', 'submit'] as const;

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
      '  agent-sandbox collector --run-dir <d> --attempt <id>',
      '                                 Run the trusted evidence collector',
      '  agent-sandbox submit --socket <s> --kind <k> [--data <json>]',
      '                                 Submit a proposal (host-side helper)',
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

async function cmdCollector(argv: string[]): Promise<number> {
  const { createAttemptCollector } = await import('./collector.js');
  const runDir = parseFlag(argv, '--run-dir');
  const attempt = parseFlag(argv, '--attempt');
  if (!runDir || !attempt) {
    process.stderr.write('collector requires --run-dir and --attempt\n');
    return 2;
  }
  const uidStr = parseFlag(argv, '--worker-uid');
  const { socketPath, storePath } = await createAttemptCollector({
    runDir,
    attempt,
    ...(uidStr ? { workerUid: Number(uidStr) } : {}),
  });
  process.stdout.write(`collector listening\n  socket: ${socketPath}\n  store:  ${storePath}\n`);
  // Run until signalled.
  await new Promise<void>((resolve) => {
    process.on('SIGINT', resolve);
    process.on('SIGTERM', resolve);
  });
  return 0;
}

async function cmdSubmit(argv: string[]): Promise<number> {
  const { submitProposal } = await import('./collector.js');
  const socket = parseFlag(argv, '--socket') ?? process.env.ASBX_COLLECTOR_SOCK;
  const kind = parseFlag(argv, '--kind');
  if (!socket || !kind) {
    process.stderr.write('submit requires --socket (or $ASBX_COLLECTOR_SOCK) and --kind\n');
    return 2;
  }
  const dataStr = parseFlag(argv, '--data') ?? '{}';
  let data: unknown;
  try {
    data = JSON.parse(dataStr);
  } catch {
    process.stderr.write('--data is not valid JSON\n');
    return 2;
  }
  const receipt = await submitProposal(socket, kind, data);
  process.stdout.write(JSON.stringify(receipt) + '\n');
  return receipt.ok ? 0 : 1;
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
    case 'collector':
      return cmdCollector(rest);
    case 'submit':
      return cmdSubmit(rest);
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
