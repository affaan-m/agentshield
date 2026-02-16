import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    include: ["tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: [
        // CLI and GitHub Action entry points — auto-execute on import,
        // tested via integration (running the CLI) rather than unit tests
        "src/index.ts",
        "src/action.ts",
        // Opus pipeline makes live API calls to Anthropic —
        // tested via E2E with real API key
        "src/opus/pipeline.ts",
        // New modules being built in parallel — dynamically imported,
        // excluded until modules are ready
        "src/injection/**",
        "src/sandbox/**",
        "src/taint/**",
        "src/logger/**",
        "src/corpus/**",
      ],
      thresholds: {
        statements: 80,
        branches: 70,
        functions: 90,
        lines: 80,
      },
    },
  },
});
