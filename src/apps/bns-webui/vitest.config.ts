import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
    // live.test.ts 会真的打线上 bns-server，给足超时。
    testTimeout: 30_000,
  },
})
