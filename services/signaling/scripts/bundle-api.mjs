/**
 * Production bundler for the API entries (`pnpm build:api`).
 *
 * The source tree uses NodeNext `.ts`-extension imports so that `tsx`
 * (standalone dev server, tests, vercel dev) runs TypeScript natively.
 * @vercel/node transpiles each traced file in place WITHOUT rewriting
 * those specifiers, so the deployed ESM output cannot resolve
 * `./lib/envelope.ts` at runtime (first production deploy, 2026-10-01).
 * Bundling each entry with esbuild sidesteps specifier rewriting
 * entirely: one self-contained .js per function, node builtins external.
 *
 * Output: `api/<name>.js` (next to the .ts sources, gitignored) — Vercel
 * only collects Serverless Functions from inside `api/`, so the bundles
 * land there and `vercel.json` pins the runtime on the .js files. The
 * `.ts` sources stay the single source of truth for dev and tests.
 */
import { build } from 'esbuild';
import { rmSync } from 'node:fs';

const entries = ['api/signal.ts', 'api/health.ts', 'api/account.ts'];
const outputs = ['api/signal.js', 'api/health.js', 'api/account.js'];

for (const out of outputs) rmSync(out, { force: true });

await build({
  entryPoints: entries,
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  outdir: 'api',
  outExtension: { '.js': '.js' },
  sourcemap: false,
  minify: false,
  logLevel: 'info',
  // Node builtins + ws/zod resolve natively in the deployed image.
  packages: 'external',
  metafile: false,
});

console.log(`bundled ${entries.length} entries -> api/*.js`);
