import { createRequire } from 'node:module';
import { defineConfig } from 'tsup';

const require = createRequire(import.meta.url);
const pkg = require('./package.json') as { dependencies?: Record<string, string> };

// Every declared runtime dependency, bundled into the action entry below.
// Reading this from package.json rather than listing names keeps the action
// build correct when a dependency is added later.
const runtimeDependencies = Object.keys(pkg.dependencies ?? {});

export default defineConfig([
  // Library and CLI entries. Dependencies stay external: consumers install
  // them through npm, and bundling would ship duplicate copies.
  {
    entry: ['src/index.ts', 'src/miniclaw/index.ts'],
    format: ['esm'],
    dts: true,
    clean: true,
    splitting: false,
  },

  // GitHub Action entry. The runner executes dist/action.js straight from a
  // checkout of this repo — `runs.main` in action.yml — and that checkout has
  // no node_modules, so an external import resolves against nothing and the
  // action dies before it scans anything:
  //
  //   Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'yaml' imported from
  //     /home/runner/work/_actions/affaan-m/agentshield/<ref>/dist/action.js
  //
  // Inlining the runtime dependencies makes the file self-contained. Node
  // builtins stay external, which is what the node24 runtime expects.
  {
    entry: ['src/action.ts'],
    format: ['esm'],
    dts: true,
    clean: false,
    splitting: false,
    noExternal: runtimeDependencies,

    // Some of those dependencies ship CommonJS that calls require() at load
    // time — yaml reaches for require("process"). Inlining CJS into an ESM
    // bundle leaves those calls pointing at esbuild's stub, which throws
    // `Dynamic require of "process" is not supported`. Defining a real require
    // from the module URL lets the stub delegate to it instead.
    banner: {
      js: [
        "import { createRequire as __ecc_createRequire } from 'node:module';",
        'const require = __ecc_createRequire(import.meta.url);',
      ].join('\n'),
    },
  },
]);
