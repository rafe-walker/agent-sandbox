/**
 * Capability probes backed by the launcher. Each allocates a throwaway worker,
 * runs a check inside the real sandbox config, and reports a MEASURED result.
 * These feed the preflight; they never self-report from inside the agent.
 */
import type { CapabilityProbe } from './preflight.js';
import type { CapabilityResult } from './report.js';
import { allocateWorker, releaseWorker, runInSandbox, fdAssertionScript } from './launcher.js';

export function launcherProbes(sourceDir?: string): CapabilityProbe[] {
  const common = sourceDir ? { sourceDir } : {};

  return [
    {
      name: 'uid_separated',
      async run(): Promise<CapabilityResult> {
        const r = await runInSandbox('id -u; id -G', common);
        const uid = Number(r.stdout?.split('\n')[0]?.trim());
        const harness = process.geteuid?.() ?? -1;
        if (!Number.isFinite(uid)) return { status: 'fail', detail: 'could not read sandbox uid' };
        if (uid === 0) return { status: 'fail', detail: 'sandbox runs as root' };
        if (uid === harness) return { status: 'fail', detail: 'sandbox uid equals harness uid' };
        return { status: 'pass', detail: `sandbox uid ${uid} != harness ${harness}` };
      },
    },
    {
      name: 'pid_ns',
      async run(): Promise<CapabilityResult> {
        const r = await runInSandbox(
          'echo PID=$$; ls /proc | grep -cE "^[0-9]+$"; echo HARNESS=' + process.pid,
          common,
        );
        const lines = (r.stdout ?? '').split('\n');
        const pid = Number(lines[0]?.replace('PID=', '').trim());
        const procCount = Number(lines[1]?.trim());
        // In a fresh PID namespace the shell is pid 1/2 and only a handful of
        // processes are visible; the harness pid must not be among them.
        if (!Number.isFinite(pid) || pid > 10) {
          return { status: 'fail', detail: `shell pid ${pid} is not namespace-local` };
        }
        if (!Number.isFinite(procCount) || procCount > 20) {
          return { status: 'fail', detail: `${procCount} processes visible (expected a handful)` };
        }
        const canSeeHarness = await runInSandbox(
          `test -d /proc/${process.pid} && echo SEES || echo HIDDEN`,
          common,
        );
        if ((canSeeHarness.stdout ?? '').includes('SEES')) {
          return { status: 'fail', detail: 'harness pid visible in sandbox /proc' };
        }
        return { status: 'pass', detail: `shell pid ${pid}, ${procCount} procs, harness hidden` };
      },
    },
    {
      name: 'mount_ns',
      async run(): Promise<CapabilityResult> {
        const r = await runInSandbox(
          [
            '(echo x > /usr/_w 2>/dev/null && echo USR_WRITABLE) || echo usr_ro',
            'test -e /run && echo RUN_PRESENT || echo run_absent',
            'test -e /src && ((echo x > /src/_w 2>/dev/null && echo SRC_WRITABLE) || echo src_ro) || echo no_src',
          ].join('\n'),
          common,
        );
        const out = r.stdout ?? '';
        if (out.includes('USR_WRITABLE')) return { status: 'fail', detail: '/usr is writable' };
        if (out.includes('RUN_PRESENT')) return { status: 'fail', detail: '/run is present' };
        if (out.includes('SRC_WRITABLE')) return { status: 'fail', detail: 'source bind is writable' };
        return { status: 'pass', detail: '/usr ro, /run absent, source bind ro' };
      },
    },
    {
      name: 'fds_clean',
      async run(): Promise<CapabilityResult> {
        const r = await runInSandbox(fdAssertionScript([0, 1, 2]), common);
        const out = (r.stdout ?? '').trim();
        if (out.includes('FDS_OK')) return { status: 'pass', detail: 'only 0/1/2 open' };
        return { status: 'fail', detail: out || 'no output from fd assertion' };
      },
    },
    {
      name: 'creds_absent',
      async run(): Promise<CapabilityResult> {
        // Plant a credential canary in the HARNESS env, then scan EVERY process
        // the sandbox can see (pid 1 = bwrap included): environ, cmdline, and
        // every readable fd target. Robust to the legitimate
        // ANTHROPIC_BASE_URL / session token the gateway later sets.
        const canary = 'sk-ant-CANARY-' + Math.random().toString(36).slice(2);
        const prev = process.env.ASBX_CRED_CANARY;
        process.env.ASBX_CRED_CANARY = canary;
        try {
          const r = await runInSandbox(credScanScript(canary), common);
          const hits = parseCredScan(r.stdout ?? '');
          if (hits === undefined) return { status: 'fail', detail: 'credential scan produced no result' };
          if (hits.total > 0) {
            return { status: 'fail', detail: `harness credential canary visible in sandbox (${hits.where})` };
          }
          return { status: 'pass', detail: `harness canary absent from all ${hits.procs} visible processes (environ, cmdline, fds)` };
        } finally {
          if (prev === undefined) delete process.env.ASBX_CRED_CANARY;
          else process.env.ASBX_CRED_CANARY = prev;
        }
      },
    },
  ];
}

/** True when this host can run the launcher (Linux + root). */
export function canLaunch(): boolean {
  return process.platform === 'linux' && (process.geteuid?.() ?? -1) === 0;
}

/** Self-test used by tests and the preflight: allocate + release a worker. */
export async function selfTestWorker(): Promise<{ survivors: number }> {
  const w = await allocateWorker();
  return releaseWorker(w);
}

/**
 * Shell script that counts occurrences of `canary` across every visible
 * process: /proc/<pid>/environ, /proc/<pid>/cmdline, and each regular file an
 * fd points at (first 1 MiB). It never puts the joined canary in any argv
 * (that would make the scan match its own cmdline): the halves are joined
 * into a pattern file read by `grep -F -f`, and that file is excluded from the
 * fd scan. `cat` opens environ after exec (a `<` redirect reads EOF). Prints
 * counts only, never contents:
 *   CREDSCAN procs=<n> pid1=<n> environ=<n> cmdline=<n> fd=<n>
 */
export function credScanScript(canary: string): string {
  const mid = Math.floor(canary.length / 2);
  const pat = '/tmp/.asbx-credscan-pat';
  return [
    `printf '%s%s\\n' '${canary.slice(0, mid)}' '${canary.slice(mid)}' > ${pat}`,
    `cnt() { cat "$1" 2>/dev/null | tr '\\0' '\\n' | grep -c -F -f ${pat}; }`,
    'p1=$(cnt /proc/1/environ)',
    'procs=0; e=0; c=0; f=0',
    'for d in /proc/[0-9]*; do',
    '  procs=$((procs+1))',
    '  n=$(cnt "$d/environ"); e=$((e+n))',
    '  n=$(cnt "$d/cmdline"); c=$((c+n))',
    '  for fd in "$d"/fd/*; do',
    '    t=$(readlink "$fd" 2>/dev/null) || continue',
    `    case "$t" in /proc/*|${pat}) continue;; esac`,
    `    if [ -f "$t" ]; then n=$(head -c 1048576 "$t" 2>/dev/null | grep -c -F -f ${pat}); f=$((f+n)); fi`,
    '  done',
    'done',
    'echo "CREDSCAN procs=$procs pid1=$p1 environ=$e cmdline=$c fd=$f"',
  ].join('\n');
}

export interface CredScan {
  procs: number;
  pid1: number;
  environ: number;
  cmdline: number;
  fd: number;
  total: number;
  where: string;
}

export function parseCredScan(out: string): CredScan | undefined {
  const m = /CREDSCAN procs=(\d+) pid1=(\d+) environ=(\d+) cmdline=(\d+) fd=(\d+)/.exec(out);
  if (!m) return undefined;
  const [procs, pid1, environ, cmdline, fd] = m.slice(1).map(Number) as [number, number, number, number, number];
  return { procs, pid1, environ, cmdline, fd, total: environ + cmdline + fd, where: `pid1=${pid1} environ=${environ} cmdline=${cmdline} fd=${fd}` };
}
