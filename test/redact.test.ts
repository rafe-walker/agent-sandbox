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

describe('stream redactor', () => {
  const r = buildRedactor([SECRET]);
  const b64 = Buffer.from(SECRET).toString('base64');
  const text = `a ${SECRET} b ${encodeURIComponent(SECRET)} c ${b64} d ${SECRET.slice(0, 12)} ${SECRET.slice(12)} e`;
  const whole = r(text);

  it('equals one-shot redaction for every 2-way split point', () => {
    for (let i = 0; i <= text.length; i++) {
      const s = r.stream();
      const out = s.push(text.slice(0, i)) + s.push(text.slice(i)) + s.flush();
      expect(out, `split at ${i}`).toBe(whole);
    }
  });

  it('equals one-shot redaction when fed 1 char at a time', () => {
    const s = r.stream();
    let out = '';
    for (const ch of text) out += s.push(ch);
    out += s.flush();
    expect(out).toBe(whole);
    expect(out).not.toContain(SECRET);
  });

  it('passes text through unchanged when there are no secrets', () => {
    const s = buildRedactor([]).stream();
    expect(s.push('abc') + s.flush()).toBe('abc');
  });
});
