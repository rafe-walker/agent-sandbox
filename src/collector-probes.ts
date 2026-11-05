/**
 * The `evidence_writer_separated` capability probe. It stands up a real
 * collector, launches a sandbox with ONLY the socket bind-mounted (the store is
 * not), and measures that:
 *   - a valid proposal from inside gets a receipt and lands in the host store,
 *   - the canonical store is not reachable from inside the sandbox,
 *   - the collector, not the agent, owns ids/timestamps/attempt identity.
 */
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { CapabilityProbe } from './preflight.js';
import type { CapabilityResult } from './report.js';
import { createAttemptCollector, readStore } from './collector.js';
import { allocateWorker, releaseWorker, launch } from './launcher.js';
import { canLaunch } from './launcher-probes.js';

const SANDBOX_SOCK = '/run/asbx/collector.sock';

export function evidenceWriterProbe(): CapabilityProbe {
  return {
    name: 'evidence_writer_separated',
    async run(): Promise<CapabilityResult> {
      const runDir = await mkdtemp(path.join(tmpdir(), 'asbx-run-'));
      const worker = await allocateWorker();
      const { collector, socketPath, storePath } = await createAttemptCollector({
        runDir,
        attempt: 'probe0001',
        workerUid: worker.uid,
      });
      try {
        // Inside the sandbox: submit a valid proposal over the bound UNIX
        // socket using python3 (node lives in /opt, which is not bound; python3
        // is under the ro /usr bind). The payload deliberately carries bogus
        // id/attempt fields under data to prove the collector ignores them.
        const script = [
          // Write the submitter as a file (heredoc, no shell/one-line quoting
          // hazards) and run it. node lives in /opt (unbound); python3 is /usr.
          `cat > /tmp/sub.py <<'PY'`,
          'import socket,json,sys',
          's=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)',
          's.connect(sys.argv[1])',
          "s.sendall((json.dumps({'schema':'asbx.proposal.v1','kind':'finding','data':{'note':'from-sandbox','injectedId':'ev_HACK','attempt':'other'}})+'\\n').encode())",
          "print('RECEIPT:'+s.recv(4096).decode().strip())",
          'PY',
          `python3 -I /tmp/sub.py "$ASBX_COLLECTOR_SOCK" 2>&1 || echo SUBMIT_ERR`,
          // can the agent reach the canonical store?
          `test -e ${storePath} && echo STORE_VISIBLE || echo store_hidden`,
          `test -w ${storePath} && echo STORE_WRITABLE || echo store_not_writable`,
        ].join('\n');

        const r = await launch({
          worker,
          command: ['/bin/sh', '-c', script],
          capture: true,
          rwBinds: [{ src: socketPath, dest: SANDBOX_SOCK }],
          env: { ASBX_COLLECTOR_SOCK: SANDBOX_SOCK },
          wallClockMs: 15000,
        });
        const out = r.stdout ?? '';

        if (!/RECEIPT:/.test(out)) {
          return { status: 'fail', detail: `no receipt from collector: ${out.slice(0, 200)}` };
        }
        if (/STORE_VISIBLE/.test(out) || /STORE_WRITABLE/.test(out)) {
          return { status: 'fail', detail: 'canonical store reachable from sandbox' };
        }

        const events = await readStore(storePath);
        if (events.length !== 1) {
          return { status: 'fail', detail: `expected 1 stored event, got ${events.length}` };
        }
        const ev = events[0]!;
        // The collector must have assigned identity, ignoring agent-supplied
        // injectedId / attempt fields (those live under data, untrusted).
        if (ev.attempt !== 'probe0001') return { status: 'fail', detail: 'attempt identity not collector-assigned' };
        if (typeof ev.id !== 'string' || ev.id === 'ev_HACK') return { status: 'fail', detail: 'id not collector-assigned' };
        if (typeof ev.ts !== 'string') return { status: 'fail', detail: 'timestamp not collector-assigned' };
        return { status: 'pass', detail: 'proposal stored; store unreachable; ids/ts/attempt collector-assigned' };
      } finally {
        await collector.stop();
        await releaseWorker(worker);
        await rm(runDir, { recursive: true, force: true });
      }
    },
  };
}

export function canCollect(): boolean {
  return canLaunch();
}
