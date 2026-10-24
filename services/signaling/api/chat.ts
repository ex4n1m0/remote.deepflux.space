/**
 * The machine-chat inbox endpoint (ADR-005 RD-022). See lib/chat-schema.ts
 * for the contract; lib/chat-server.ts for the discipline.
 */
import { createChatServer } from '../lib/chat-server.ts';

const chat = createChatServer();

// The Vercel runtime bridges an exported http.Server directly. Do NOT
// call `listen()` here (see api/account.ts note).
export default chat.server;
