import { describe, it, expect } from 'vitest';
import { SUITE_VERSION } from '../src/index.js';

describe('scaffold', () => {
  it('exports a suite version', () => {
    expect(SUITE_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
