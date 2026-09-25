/**
 * Headless contract-matrix launcher (QA F41): same suite as
 * `pnpm test:contract` but without any Vercel dependency — emulator +
 * standalone instances only. Used by `scripts/test.sh` so the merge gate
 * covers the signaling contract without CLI auth or the dev pipeline.
 *
 * Run: node --import tsx scripts/contract-headless.mjs
 */
process.env.CONTRACT_NO_VERCEL = '1';
await import('../tests/contract.test.ts');
