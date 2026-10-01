/**
 * The account/roster endpoint (Vercel function, Node runtime).
 *
 * Serves `POST /api/account` (register/login_pre/login/logout/roster_get/
 * roster_put/presence) as plain HTTP request/response. All authoritative
 * state lives in the external store (Upstash Redis REST); the service never
 * sees passwords or unwrapped DEKs — only scrypt verifiers and ciphertext.
 */
import { createAccountServer } from '../lib/account-server.ts';

const account = createAccountServer();

// The Vercel runtime bridges an exported http.Server directly. Do NOT
// call `listen()` here: with no arguments it binds a random port and
// keeps the worker alive (INTERNAL_FUNCTION_INVOCATION_FAILED in
// production, first deploy 2026-10-01).
export default account.server;
