import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    testTimeout: 30_000,
    // One worker: the suite manipulates uids/netns/nft and runs on shared hosts.
    fileParallelism: false,
    maxWorkers: 1,
    minWorkers: 1,
    // Attacker/launcher tests need root + namespaces; they self-skip when the
    // capability is missing but MUST NOT be silently skipped in CI (see ci.yml).
  },
});
