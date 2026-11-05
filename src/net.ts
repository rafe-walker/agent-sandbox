/**
 * Per-attempt network cage.
 *
 * A dedicated network namespace joined by a veth pair to the host. Host-side
 * nftables (our OWN `inet asbx_<id>` table — we never touch the host's existing
 * ruleset) allow the sandbox to reach ONLY the gateway ports on the host veth
 * IP. No DNS, IPv6 disabled and dropped, no forwarding (the host keeps
 * `ip_forward=0`, so the sandbox cannot route past the host even if a rule were
 * missing). Setup and teardown are idempotent and clean up after a crash.
 *
 * Requires root. Names use the `asbx_` prefix with underscores (nft rejects
 * hyphens in unquoted identifiers; veth names are capped at 15 chars).
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes } from 'node:crypto';
import { open, readFile, unlink, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { MINIMAL_ENV } from './launcher.js';

const pExecFileRaw = promisify(execFile);
// Helpers never inherit the harness env (credentials, proxy URLs).
function pExecFile(cmd: string, args: string[]): Promise<{ stdout: string; stderr: string }> {
  return pExecFileRaw(cmd, args, { env: { ...MINIMAL_ENV } });
}

export const NET_PREFIX = 'asbx_';

export interface NetHandle {
  id: string;
  netns: string;
  vethHost: string;
  vethSandbox: string;
  table: string;
  /** Host-side IP the gateway binds to; the sandbox's only reachable address. */
  hostIp: string;
  /** The sandbox's IP inside the netns. */
  sandboxIp: string;
  gatewayPorts: number[];
}

export interface SetupOptions {
  /** TCP ports on `hostIp` the sandbox may reach. Usually one gateway port. */
  gatewayPorts: number[];
  /** Optional stable attempt id; a random one is generated otherwise. */
  attemptId?: string;
}

async function run(cmd: string, args: string[]): Promise<void> {
  await pExecFile(cmd, args);
}

async function tryRun(cmd: string, args: string[]): Promise<void> {
  try {
    await pExecFile(cmd, args);
  } catch {
    /* best-effort */
  }
}

function requireRoot(): void {
  if (process.platform !== 'linux') throw new Error('network cage requires Linux');
  if ((process.geteuid?.() ?? -1) !== 0) throw new Error('network cage requires root');
}

function validatePorts(ports: number[]): void {
  if (ports.length === 0) throw new Error('at least one gateway port is required');
  for (const p of ports) {
    if (!Number.isInteger(p) || p < 1 || p > 65535) {
      throw new Error(`invalid gateway port: ${String(p)}`);
    }
  }
}

function names(id: string): Omit<NetHandle, 'hostIp' | 'sandboxIp' | 'gatewayPorts'> {
  // id is 8 hex chars; veth names must be <= 15 chars: asbx_h + 8 = 14.
  return {
    id,
    netns: `${NET_PREFIX}${id}`,
    vethHost: `${NET_PREFIX}h${id}`,
    vethSandbox: `${NET_PREFIX}s${id}`,
    table: `${NET_PREFIX}${id}`,
  };
}

/** Pool for cage /30s: 10.213.0.0/16 (16384 subnets). */
const POOL_PREFIX = '10.213';
export const NET_LOCK_PATH = '/run/agent-sandbox/net.lock';

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/**
 * Cross-process exclusive lock (O_EXCL lock file holding the owner pid). A
 * lock whose owner is dead (crash) is broken. Held only for allocate+assign.
 */
async function withNetLock<T>(fn: () => Promise<T>): Promise<T> {
  await mkdir(path.dirname(NET_LOCK_PATH), { recursive: true, mode: 0o700 });
  const deadline = Date.now() + 15_000;
  for (;;) {
    try {
      const fh = await open(NET_LOCK_PATH, 'wx', 0o600);
      await fh.writeFile(String(process.pid));
      await fh.close();
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
      const owner = Number((await readFile(NET_LOCK_PATH, 'utf8').catch(() => '')).trim());
      if (Number.isInteger(owner) && owner > 0 && !pidAlive(owner)) {
        await unlink(NET_LOCK_PATH).catch(() => {});
        continue;
      }
      if (Date.now() > deadline) throw new Error(`timed out waiting for ${NET_LOCK_PATH}`);
      await new Promise((r) => setTimeout(r, 20));
    }
  }
  try {
    return await fn();
  } finally {
    await unlink(NET_LOCK_PATH).catch(() => {});
  }
}

/** /30 bases (as "a.b.c.d" of the network address) already present on the host. */
async function usedPoolSubnets(): Promise<Set<string>> {
  const used = new Set<string>();
  const add = (ip: string): void => {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || `${parts[0]}.${parts[1]}` !== POOL_PREFIX) return;
    used.add(`${parts[0]}.${parts[1]}.${parts[2]}.${(parts[3]! >> 2) << 2}`);
  };
  const { stdout: addrs } = await pExecFile('ip', ['-o', '-4', 'addr', 'show']);
  for (const m of addrs.matchAll(/inet (\d+\.\d+\.\d+\.\d+)/g)) add(m[1]!);
  const { stdout: routes } = await pExecFile('ip', ['-o', '-4', 'route', 'show']);
  for (const m of routes.matchAll(/^(\d+\.\d+\.\d+\.\d+)/gm)) add(m[1]!);
  return used;
}

/**
 * Atomically pick a free /30 and assign the host side to `vethHost`. The lock
 * covers both steps, so two concurrent setups can never pick the same /30.
 */
async function allocateAndAssign(vethHost: string): Promise<{ host: string; sandbox: string }> {
  return withNetLock(async () => {
    const used = await usedPoolSubnets();
    for (let idx = 0; idx < 16384; idx++) {
      const base = `${POOL_PREFIX}.${idx >> 6}.${(idx & 63) * 4}`;
      if (used.has(base)) continue;
      const [a, b, c, d] = base.split('.').map(Number) as [number, number, number, number];
      const host = `${a}.${b}.${c}.${d + 1}`;
      const sandbox = `${a}.${b}.${c}.${d + 2}`;
      await run('ip', ['addr', 'add', `${host}/30`, 'dev', vethHost]);
      return { host, sandbox };
    }
    throw new Error('network cage subnet pool exhausted');
  });
}

/** Remove any resources for this id. Idempotent; used by setup and teardown. */
async function destroy(h: Omit<NetHandle, 'hostIp' | 'sandboxIp' | 'gatewayPorts'>): Promise<void> {
  await tryRun('nft', ['delete', 'table', 'inet', h.table]);
  await tryRun('ip', ['netns', 'del', h.netns]);
  // Deleting the netns removes the sandbox-side veth; remove the host side if
  // it lingers (e.g. the move into the netns failed).
  await tryRun('ip', ['link', 'del', h.vethHost]);
}

/**
 * Create the network cage. Idempotent for a given id: any stale resources of
 * the same name are torn down first.
 */
export async function setupNetwork(opts: SetupOptions): Promise<NetHandle> {
  requireRoot();
  validatePorts(opts.gatewayPorts);
  const id = (opts.attemptId ?? randomBytes(4).toString('hex'))
    .replace(/[^a-f0-9]/gi, '')
    .slice(0, 8)
    .padEnd(8, '0');
  const n = names(id);

  await destroy(n); // crash cleanup / idempotency

  try {
    await run('ip', ['netns', 'add', n.netns]);
    await run('ip', ['link', 'add', n.vethHost, 'type', 'veth', 'peer', 'name', n.vethSandbox]);
    await run('ip', ['link', 'set', n.vethSandbox, 'netns', n.netns]);

    // Host side: allocate a free /30 and assign it under the cross-process lock.
    const { host, sandbox } = await allocateAndAssign(n.vethHost);
    const handle: NetHandle = { ...n, hostIp: host, sandboxIp: sandbox, gatewayPorts: [...opts.gatewayPorts] };
    await run('ip', ['link', 'set', n.vethHost, 'up']);

    // Sandbox side: disable IPv6, bring up lo + veth, default route to host.
    await tryRun('ip', ['netns', 'exec', n.netns, 'sysctl', '-wq', 'net.ipv6.conf.all.disable_ipv6=1']);
    await tryRun('ip', ['netns', 'exec', n.netns, 'sysctl', '-wq', 'net.ipv6.conf.default.disable_ipv6=1']);
    await run('ip', ['netns', 'exec', n.netns, 'ip', 'addr', 'add', `${sandbox}/30`, 'dev', n.vethSandbox]);
    await run('ip', ['netns', 'exec', n.netns, 'ip', 'link', 'set', n.vethSandbox, 'up']);
    await run('ip', ['netns', 'exec', n.netns, 'ip', 'link', 'set', 'lo', 'up']);
    await run('ip', ['netns', 'exec', n.netns, 'ip', 'route', 'add', 'default', 'via', host]);
    // No resolv.conf is installed in the netns -> no DNS. nft also drops :53.

    // Host-side nftables: OUR table only. input hook, policy accept (so host
    // traffic is untouched), with explicit rules for our veth iface. A drop in
    // our table wins over any accept in other tables.
    const ports = opts.gatewayPorts.join(', ');
    await run('nft', ['add', 'table', 'inet', n.table]);
    await run('nft', [
      'add',
      'chain',
      'inet',
      n.table,
      'input',
      '{ type filter hook input priority -10 ; policy accept ; }',
    ]);
    await run('nft', [
      'add',
      'chain',
      'inet',
      n.table,
      'forward',
      '{ type filter hook forward priority -10 ; policy accept ; }',
    ]);
    // Return traffic for established flows.
    await run('nft', [
      'add',
      'rule',
      'inet',
      n.table,
      'input',
      'iifname',
      n.vethHost,
      'ct',
      'state',
      'established,related',
      'accept',
    ]);
    // Drop all IPv6 from the sandbox iface.
    await run('nft', ['add', 'rule', 'inet', n.table, 'input', 'iifname', n.vethHost, 'meta', 'nfproto', 'ipv6', 'drop']);
    // Allow only TCP to the gateway ports on the host veth IP.
    await run('nft', [
      'add',
      'rule',
      'inet',
      n.table,
      'input',
      'iifname',
      n.vethHost,
      'ip',
      'daddr',
      host,
      'tcp',
      'dport',
      `{ ${ports} }`,
      'accept',
    ]);
    // Everything else arriving from the sandbox iface is dropped (incl. DNS,
    // other hosts, non-gateway ports).
    await run('nft', ['add', 'rule', 'inet', n.table, 'input', 'iifname', n.vethHost, 'drop']);
    // Never forward the sandbox anywhere (defence in depth; ip_forward is off).
    await run('nft', ['add', 'rule', 'inet', n.table, 'forward', 'iifname', n.vethHost, 'drop']);
    await run('nft', ['add', 'rule', 'inet', n.table, 'forward', 'oifname', n.vethHost, 'ct', 'state', 'established,related', 'accept']);
    await run('nft', ['add', 'rule', 'inet', n.table, 'forward', 'oifname', n.vethHost, 'drop']);

    return handle;
  } catch (e) {
    await destroy(n);
    throw e;
  }
}

/** Tear down the cage. Idempotent; safe after a crash. */
export async function teardownNetwork(handle: Pick<NetHandle, 'id'>): Promise<void> {
  if (process.platform !== 'linux') return;
  await destroy(names(handle.id));
}

/**
 * Remove every leftover `asbx_` netns, nft table and veth from crashed runs.
 * Returns what was cleaned.
 */
export async function cleanupStale(): Promise<{ netns: string[]; tables: string[]; links: string[] }> {
  if (process.platform !== 'linux') return { netns: [], tables: [], links: [] };
  const cleaned = { netns: [] as string[], tables: [] as string[], links: [] as string[] };

  try {
    const { stdout } = await pExecFile('ip', ['-o', 'netns', 'list']);
    for (const line of stdout.split('\n')) {
      const ns = line.split(/[ (]/)[0]?.trim();
      if (ns && ns.startsWith(NET_PREFIX)) {
        await tryRun('ip', ['netns', 'del', ns]);
        cleaned.netns.push(ns);
      }
    }
  } catch {
    /* none */
  }
  try {
    const { stdout } = await pExecFile('nft', ['list', 'tables']);
    for (const line of stdout.split('\n')) {
      // "table inet asbx_xxxx"
      const m = line.match(/^table\s+inet\s+(asbx_\S+)/);
      if (m?.[1]) {
        await tryRun('nft', ['delete', 'table', 'inet', m[1]]);
        cleaned.tables.push(m[1]);
      }
    }
  } catch {
    /* none */
  }
  try {
    const { stdout } = await pExecFile('ip', ['-o', 'link', 'show']);
    for (const line of stdout.split('\n')) {
      const m = line.match(/^\d+:\s+(asbx_\S+?)[@:]/);
      if (m?.[1]) {
        await tryRun('ip', ['link', 'del', m[1]]);
        cleaned.links.push(m[1]);
      }
    }
  } catch {
    /* none */
  }
  return cleaned;
}
