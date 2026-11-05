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
        // Positive-control style: plant a credential canary in the HARNESS env,
        // then assert bwrap's --clearenv kept it out of the sandbox env and
        // /proc/self/environ. This measures the real property (the credential
        // lives outside the sandbox and must not cross) and is robust to the
        // legitimate ANTHROPIC_BASE_URL / session token the gateway later sets.
        const canary = 'sk-ant-CANARY-' + Math.random().toString(36).slice(2);
        const prev = process.env.ASBX_CRED_CANARY;
        process.env.ASBX_CRED_CANARY = canary;
        try {
          const r = await runInSandbox(
            // cat opens environ after exec; a `<` redirect would read EOF.
            'env; echo ---; cat /proc/self/environ 2>/dev/null | tr "\\0" "\\n"',
            common,
          );
          const out = r.stdout ?? '';
          if (out.includes(canary)) {
            return { status: 'fail', detail: 'harness credential canary leaked into sandbox env' };
          }
          if (out.includes('ASBX_CRED_CANARY')) {
            return { status: 'fail', detail: 'harness env var name leaked (env not cleared)' };
          }
          return { status: 'pass', detail: 'harness credential canary absent from sandbox' };
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
