/// <reference types="vitest" />
import { defineConfig } from 'vite';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      reportsDirectory: './coverage',
      include: ['src/**/*.ts'],
      exclude: [
        'src/types.ts',
        'src/constants.ts',
        'src/__tests__/test-utils.ts',
        // 'src/__tests__/**/*',
        // 'src/index.ts', // Example: Exclude main if it's mostly orchestration
      ],
    },
  },
});