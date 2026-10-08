import { defineConfig } from 'tsup';

const entry = ['src/index.ts', 'src/canonicalize.ts', 'src/keys.ts'];

// The two builds run in parallel, so each cleans only its own files.
export default defineConfig([
  { entry, format: 'esm', dts: true, clean: ['!**/*.cjs'] },
  // @noble/ed25519 is ESM-only: bundled into the CJS build so require() works
  // on Node versions that can't require() ESM (before 20.19 / 22.12; P-52).
  // Types come from the .d.ts files (package.json points require there too).
  { entry, format: 'cjs', noExternal: ['@noble/ed25519'], clean: ['!**/*.js', '!**/*.d.ts'] },
]);
