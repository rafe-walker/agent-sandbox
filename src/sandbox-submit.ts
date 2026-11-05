#!/usr/bin/env node
/**
 * `sandbox-submit` — a tiny CLI run INSIDE the sandbox to submit a proposal to
 * the trusted collector. The socket path comes from $ASBX_COLLECTOR_SOCK (set
 * by the launcher) or --socket. The event body is read from --data (JSON
 * string) or stdin. It prints the receipt JSON and exits non-zero on rejection.
 *
 * Usage:
 *   sandbox-submit --kind finding --data '{"k":"v"}'
 *   echo '{"k":"v"}' | sandbox-submit --kind finding
 */
import { submitProposal } from './collector.js';

function flag(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let s = '';
    if (process.stdin.isTTY) return resolve('');
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (d) => (s += d));
    process.stdin.on('end', () => resolve(s));
  });
}

async function main(): Promise<number> {
  const socket = flag('--socket') ?? process.env.ASBX_COLLECTOR_SOCK;
  const kind = flag('--kind');
  if (!socket) {
    process.stderr.write('no collector socket (set ASBX_COLLECTOR_SOCK or --socket)\n');
    return 2;
  }
  if (!kind) {
    process.stderr.write('--kind is required\n');
    return 2;
  }
  const dataStr = flag('--data') ?? (await readStdin());
  let data: unknown = {};
  if (dataStr.trim()) {
    try {
      data = JSON.parse(dataStr);
    } catch {
      process.stderr.write('--data / stdin is not valid JSON\n');
      return 2;
    }
  }
  const receipt = await submitProposal(socket, kind, data);
  process.stdout.write(JSON.stringify(receipt) + '\n');
  return receipt.ok ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (err: unknown) => {
    process.stderr.write(`sandbox-submit error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  },
);
