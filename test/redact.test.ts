import { describe, it, expect } from 'vitest';
import { buildRedactor, REDACTION_MARKER } from '../src/redact.js';

const SECRET = 'sk-ant-SECRET-abcdef0123456789';

describe('buildRedactor', () => {
  const r = buildRedactor([SECRET]);

  it('redacts an exact match', () => {
    expect(r(`key=${SECRET} end`)).toBe(`key=${REDACTION_MARKER} end`);
    expect(r(`key=${SECRET}`)).not.toContain(SECRET);
  });

  it('redacts a JSON-escaped form', () => {
    const escaped = JSON.stringify(SECRET).slice(1, -1);
    expect(r(`{"k":"${escaped}"}`)).not.toContain(SECRET);
  });

  it('redacts URL-encoded', () => {
    expect(r(`q=${encodeURIComponent(SECRET)}`)).not.toContain(encodeURIComponent(SECRET));
  });

  it('redacts base64 (std and url-safe)', () => {
    const std = Buffer.from(SECRET, 'utf8').toString('base64');
    const url = std.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    expect(r(`b=${std}`)).not.toContain(std);
    expect(r(`b=${url}`)).not.toContain(url);
  });

  it('redacts a split form', () => {
    const mid = Math.floor(SECRET.length / 2);
    const split = `${SECRET.slice(0, mid)} ${SECRET.slice(mid)}`;
    expect(r(split)).not.toContain(SECRET.slice(0, mid) + ' ' + SECRET.slice(mid));
  });

  it('contains() is stable across calls (no stateful regex bug)', () => {
    const text = `x ${SECRET} y`;
    expect(r.contains(text)).toBe(true);
    expect(r.contains(text)).toBe(true);
    expect(r.contains('nothing here')).toBe(false);
  });

  it('ignores secrets shorter than 8 chars', () => {
    const r2 = buildRedactor(['abc']);
    expect(r2('abc abc')).toBe('abc abc');
    expect(r2.needleCount).toBe(0);
  });
});
