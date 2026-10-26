/**
 * The circle-directory endpoint (Vercel function, Node runtime; ADR-006).
 *
 * Serves `POST /api/directory` (put/list/remove) as plain HTTP
 * request/response. Sealed entries only — the service sees device ids,
 * ciphertext, server-minted timestamps, and online flags, never nicknames.
 */
import { createDirectoryServer } from '../lib/directory-server.ts';

const directory = createDirectoryServer();

// The Vercel runtime bridges an exported http.Server directly. Do NOT
// call `listen()` (see api/account.ts for the first-deploy lesson).
export default directory.server;
