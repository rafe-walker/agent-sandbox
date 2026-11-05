/**
 * Assembles the capability probes available on this host. Later stacked
 * modules (network, collector) add their probes here; v0.1 wires the launcher
 * probes when the host can launch.
 */
import type { CapabilityProbe } from './preflight.js';
import { launcherProbes, canLaunch } from './launcher-probes.js';

export interface AssembleOptions {
  sourceDir?: string;
}

export function assembleCapabilityProbes(opts: AssembleOptions = {}): CapabilityProbe[] {
  const probes: CapabilityProbe[] = [];
  if (canLaunch()) probes.push(...launcherProbes(opts.sourceDir));
  // network (net_enforced) and collector (evidence_writer_separated) probes
  // are registered by their modules in the following stacked PRs.
  return probes;
}
