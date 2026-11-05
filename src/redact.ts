/**
 * Echoed-credential redaction. This is a MITIGATION, not a proof: a server that
 * holds a token can encode it in ways we do not anticipate. We cover the forms
 * an honest-but-buggy or lightly-malicious endpoint is likely to use — exact,
 * JSON-string-escaped, URL-encoded, base64 (std + url), and split — and we FAIL
 * CLOSED on text we cannot scan.
 *
 * `buildRedactor(secrets)` returns a function that replaces every known form of
 * any secret with a fixed marker. Secrets shorter than 8 chars are ignored
 * (too collision-prone to redact safely).
 */
export const REDACTION_MARKER = '[REDACTED]';

function jsonEscape(s: string): string {
  // What JSON.stringify would produce, minus the surrounding quotes.
  return JSON.stringify(s).slice(1, -1);
}

function urlEncodings(s: string): string[] {
  return [encodeURIComponent(s), encodeURI(s)].filter((x) => x !== s);
}

function base64Variants(s: string): string[] {
  const std = Buffer.from(s, 'utf8').toString('base64');
  const url = std.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const noPad = std.replace(/=+$/, '');
  return Array.from(new Set([std, url, noPad]));
}

/** Insertions that defeat a naive exact match but preserve the secret visually. */
function splitVariants(s: string): string[] {
  if (s.length < 12) return [];
  const mid = Math.floor(s.length / 2);
  const left = s.slice(0, mid);
  const right = s.slice(mid);
  // The secret with a separator at the midpoint (common "split field" trick).
  return [`${left} ${right}`, `${left}\n${right}`, `${left}","${right}`];
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export interface Redactor {
  (text: string): string;
  /** Returns true if the text contains any known form of a secret. */
  contains(text: string): boolean;
  /** The compiled needle count (for tests). */
  readonly needleCount: number;
}

export function buildRedactor(secrets: Iterable<string>): Redactor {
  const needles = new Set<string>();
  for (const raw of secrets) {
    if (!raw || raw.length < 8) continue;
    needles.add(raw);
    needles.add(jsonEscape(raw));
    for (const u of urlEncodings(raw)) needles.add(u);
    for (const b of base64Variants(raw)) needles.add(b);
    for (const sp of splitVariants(raw)) needles.add(sp);
  }
  // Longest-first so a split form is replaced before its substrings.
  const ordered = [...needles].sort((a, b) => b.length - a.length);
  const re =
    ordered.length > 0 ? new RegExp(ordered.map(escapeRegExp).join('|'), 'g') : null;

  const fn = ((text: string): string => {
    if (re === null) return text;
    return text.replace(re, REDACTION_MARKER);
  }) as Redactor;

  Object.defineProperty(fn, 'contains', {
    value: (text: string): boolean => {
      if (re === null) return false;
      re.lastIndex = 0; // the shared regex is global/stateful
      return re.test(text);
    },
  });
  Object.defineProperty(fn, 'needleCount', { value: ordered.length });
  return fn;
}
