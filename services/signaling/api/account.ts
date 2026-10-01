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

// The @vercel/node dev builder and the Vercel runtime capture the exported
// server by intercepting `listen` — no real bind happens in either place.
account.server.listen();

export default account.server;
