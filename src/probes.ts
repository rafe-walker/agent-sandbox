/**
 * Assembles the capability probes available on this host. Later stacked
 * modules (network, collector) add their probes here; v0.1 wires the launcher
 * probes when the host can launch.
 */
import type { CapabilityProbe } from './preflight.js';
import { launcherProbes, canLaunch } from './launcher-probes.js';
import { netEnforcedProbe, canEnforceNet } from './net-probes.js';
import { evidenceWriterProbe, canCollect } from './collector-probes.js';

export interface AssembleOptions {
  sourceDir?: string;
}

export function assembleCapabilityProbes(opts: AssembleOptions = {}): CapabilityProbe[] {
  const probes: CapabilityProbe[] = [];
  if (canLaunch()) probes.push(...launcherProbes(opts.sourceDir));
  if (canEnforceNet()) probes.push(netEnforcedProbe());
  if (canCollect()) probes.push(evidenceWriterProbe());
  return probes;
}
