/**
 * Isolation profiles.
 *
 * - `dev`           — no boundary, loud warning, NEVER publishable. Fast local
 *                     iteration and native macOS only.
 * - `linux-sandbox` — dedicated uid/gid + bwrap + netns/nftables. The only
 *                     publishable profile, and only when the preflight passes.
 * - `microvm`       — reserved for hostile customer code. Not implemented in
 *                     v0.1; selecting it throws.
 */
export const PROFILES = ['dev', 'linux-sandbox', 'microvm'] as const;
export type Profile = (typeof PROFILES)[number];

export function isProfile(x: unknown): x is Profile {
  return typeof x === 'string' && (PROFILES as readonly string[]).includes(x);
}

/** Profiles that are implemented in this version. */
export const IMPLEMENTED_PROFILES: readonly Profile[] = ['dev', 'linux-sandbox'];

/** The single profile that a publishable run may use. */
export const PUBLISHABLE_PROFILE: Profile = 'linux-sandbox';

export function assertImplemented(profile: Profile): void {
  if (profile === 'microvm') {
    throw new Error(
      'profile "microvm" is reserved for hostile customer code and is not implemented in v0.1',
    );
  }
}
