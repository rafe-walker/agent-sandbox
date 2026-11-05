#!/usr/bin/env node
import { SUITE_VERSION } from './version.js';

const COMMANDS = ['preflight', 'run', 'gateway', 'collector'] as const;
type Command = (typeof COMMANDS)[number];

function usage(): void {
  process.stderr.write(
    [
      `agent-sandbox ${SUITE_VERSION}`,
      '',
      'Usage:',
      '  agent-sandbox preflight        Probe capabilities + run the attacker suite',
      '  agent-sandbox run -- <cmd>     Launch a command inside the sandbox',
      '  agent-sandbox gateway          Run the model auth gateway',
      '  agent-sandbox collector        Run the trusted evidence collector',
      '',
    ].join('\n'),
  );
}

async function main(): Promise<number> {
  const [, , cmd] = process.argv;
  if (!cmd || cmd === '-h' || cmd === '--help') {
    usage();
    return cmd ? 0 : 2;
  }
  if (!(COMMANDS as readonly string[]).includes(cmd)) {
    process.stderr.write(`unknown command: ${cmd}\n`);
    usage();
    return 2;
  }
  // Subcommands are wired in the following PRs.
  process.stderr.write(`${cmd as Command}: not implemented in this build\n`);
  return 1;
}

main().then(
  (code) => process.exit(code),
  (err: unknown) => {
    process.stderr.write(`fatal: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  },
);
