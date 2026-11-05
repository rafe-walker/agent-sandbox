#!/usr/bin/env node
import { SUITE_VERSION } from './version.js';
import { isProfile, type Profile } from './profiles.js';
import { formatReport } from './report.js';
import { runPreflight, checkPrereqs } from './preflight.js';
import { assembleCapabilityProbes } from './probes.js';
import { coreAttacks } from './attacks/index.js';
import { canLaunch } from './launcher-probes.js';
import type { NetHandle } from './net.js';

const COMMANDS = ['preflight', 'run', 'gateway', 'collector', 'submit', 'cleanup'] as const;

function usage(): void {
  process.stderr.write(
    [
      `agent-sandbox ${SUITE_VERSION}`,
      '',
      'Usage:',
      '  agent-sandbox preflight [--profile <dev|linux-sandbox>] [--json]',
      '                                 Probe capabilities + run the attacker suite',
      '  agent-sandbox run [--profile linux-sandbox|dev] [--source <dir>] [--wall-ms <n>]',
      '                    [--gateway-port <p>] [--env K=V ...] [--inherit-env (dev only)] -- <cmd...>',
      '                                 Launch a command inside the sandbox',
      '  agent-sandbox gateway --listen <host:port> [--max-requests n] [--max-tokens n]',
      '                    [--max-wall-ms n] [--ca <bundle>]',
      '                                 Run the model auth gateway (key from $ANTHROPIC_API_KEY)',
      '  agent-sandbox collector --run-dir <d> --attempt <id>',
      '                                 Run the trusted evidence collector',
      '  agent-sandbox submit --socket <s> --kind <k> [--data <json>]',
      '                                 Submit a proposal (host-side helper)',
      '  agent-sandbox cleanup          Remove leftover asbx_ uids/netns/nft/veth from crashed runs',
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
    // The 25-attack suite runs when this host can launch sandboxes.
    attacks: canLaunch() ? coreAttacks() : [],
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

/** Parse a non-negative safe integer flag; rejects NaN/Infinity/1e400/negatives. */
function intFlag(argv: string[], name: string): number | undefined {
  const raw = parseFlag(argv, name);
  if (raw === undefined) return undefined;
  if (!/^\d+$/.test(raw) || !Number.isSafeInteger(Number(raw))) {
    throw new Error(`${name} must be a non-negative integer, got "${raw}"`);
  }
  return Number(raw);
}

function multiFlag(argv: string[], name: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i++) if (argv[i] === name && argv[i + 1] !== undefined) out.push(argv[i + 1]!);
  return out;
}

async function cmdRun(argv: string[]): Promise<number> {
  const dd = argv.indexOf('--');
  const opts = dd >= 0 ? argv.slice(0, dd) : argv;
  const command = dd >= 0 ? argv.slice(dd + 1) : [];
  if (command.length === 0) {
    process.stderr.write('run requires a command after --\n');
    return 2;
  }
  const profile = parseFlag(opts, '--profile') ?? 'linux-sandbox';
  if (!isProfile(profile)) {
    process.stderr.write(`invalid --profile: ${profile}\n`);
    return 2;
  }
  const env: Record<string, string> = {};
  for (const kv of multiFlag(opts, '--env')) {
    const i = kv.indexOf('=');
    if (i <= 0) {
      process.stderr.write(`--env expects K=V, got "${kv}"\n`);
      return 2;
    }
    env[kv.slice(0, i)] = kv.slice(i + 1);
  }
  const wallClockMs = intFlag(opts, '--wall-ms');

  if (profile === 'dev') {
    process.stderr.write(
      'WARNING: profile "dev" runs the command with NO isolation. Never publishable.\n',
    );
    const { spawnSync } = await import('node:child_process');
    const { MINIMAL_ENV } = await import('./launcher.js');
    // Even in dev, the harness env (credentials) is NOT passed unless asked.
    const base: Record<string, string> = opts.includes('--inherit-env')
      ? Object.fromEntries(Object.entries(process.env).filter((e): e is [string, string] => e[1] !== undefined))
      : {
          ...MINIMAL_ENV,
          ...(process.env.HOME ? { HOME: process.env.HOME } : {}),
          ...(process.env.TERM ? { TERM: process.env.TERM } : {}),
        };
    const r = spawnSync(command[0]!, command.slice(1), {
      stdio: 'inherit',
      env: { ...base, ...env },
      ...(wallClockMs !== undefined ? { timeout: wallClockMs } : {}),
    });
    return r.status ?? 1;
  }
  if (profile === 'microvm') {
    process.stderr.write('profile "microvm" is reserved and not implemented\n');
    return 2;
  }

  const { allocateWorker, launch } = await import('./launcher.js');
  const gatewayPort = intFlag(opts, '--gateway-port');
  const source = parseFlag(opts, '--source');
  let handle: NetHandle | undefined;
  if (gatewayPort !== undefined) {
    const { setupNetwork } = await import('./net.js');
    handle = await setupNetwork({ gatewayPorts: [gatewayPort] });
    process.stderr.write(`network cage ${handle.netns}: gateway reachable at ${handle.hostIp}:${gatewayPort}\n`);
  }
  try {
    const worker = await allocateWorker();
    const r = await launch({
      worker,
      command,
      env,
      ...(source ? { sourceDir: source } : {}),
      ...(wallClockMs !== undefined ? { wallClockMs } : {}),
      ...(handle ? { netns: handle.netns, gatewayIp: handle.hostIp } : {}),
    });
    if (r.timedOut) process.stderr.write('wall-clock limit reached; sandbox killed\n');
    if (r.survivors !== 0) process.stderr.write(`WARNING: ${r.survivors} process(es) survived teardown\n`);
    return r.exitCode ?? 1;
  } finally {
    if (handle) {
      const { teardownNetwork } = await import('./net.js');
      await teardownNetwork(handle);
    }
  }
}

async function cmdGateway(argv: string[]): Promise<number> {
  const { gatewayFromEnv } = await import('./gateway.js');
  const listen = parseFlag(argv, '--listen') ?? '127.0.0.1:0';
  const m = /^(.+):(\d+)$/.exec(listen);
  if (!m) {
    process.stderr.write(`--listen expects host:port, got "${listen}"\n`);
    return 2;
  }
  const ca = parseFlag(argv, '--ca') ?? process.env.NODE_EXTRA_CA_CERTS;
  const proxy = process.env.HTTPS_PROXY ?? process.env.https_proxy;
  const g = gatewayFromEnv({
    listenHost: m[1]!,
    listenPort: Number(m[2]),
    ...(proxy ? { proxyUrl: proxy } : {}),
    ...(ca ? { caBundlePath: ca } : {}),
  });
  await g.start();
  const budget: Record<string, number> = {};
  const req = intFlag(argv, '--max-requests');
  const tok = intFlag(argv, '--max-tokens');
  const wall = intFlag(argv, '--max-wall-ms');
  if (req !== undefined) budget.maxRequests = req;
  if (tok !== undefined) budget.maxTokens = tok;
  if (wall !== undefined) budget.maxWallMs = wall;
  const { attemptId, sessionToken } = g.registerAttempt(budget);
  // The session token is a low-value per-attempt credential meant for the
  // sandbox; the real key is never printed.
  process.stdout.write(
    JSON.stringify({ attemptId, ANTHROPIC_BASE_URL: `http://${m[1]}:${g.port}`, ANTHROPIC_API_KEY: sessionToken }) + '\n',
  );
  await new Promise<void>((resolve) => {
    process.on('SIGINT', resolve);
    process.on('SIGTERM', resolve);
  });
  process.stderr.write(`usage ${JSON.stringify(g.usage(attemptId))}\n`);
  await g.stop();
  return 0;
}

async function cmdCleanup(): Promise<number> {
  const { cleanupStaleWorkers } = await import('./launcher.js');
  const { cleanupStale } = await import('./net.js');
  const workers = await cleanupStaleWorkers();
  const net = await cleanupStale();
  process.stdout.write(JSON.stringify({ workers, ...net }) + '\n');
  return 0;
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
    case 'run':
      return cmdRun(rest);
    case 'gateway':
      return cmdGateway(rest);
    case 'collector':
      return cmdCollector(rest);
    case 'submit':
      return cmdSubmit(rest);
    case 'cleanup':
      return cmdCleanup();
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
