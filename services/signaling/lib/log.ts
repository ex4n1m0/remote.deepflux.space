/**
 * Redaction-safe logging (AGENTS.md invariant 6).
 *
 * The mailbox necessarily carries SDP bodies and the one-time session secret
 * inside `Accept` envelopes — they transit the store, but they must never
 * appear in logs. This module is the only logging choke point: it logs
 * scalars (ids, counters, error codes) and never raw envelopes or frame
 * payloads. Keep it that way in every call site.
 */

type Level = 'debug' | 'info' | 'warn' | 'error';
type Fields = Record<string, string | number>;

function emit(level: Level, msg: string, fields: Fields, svc: string = 'signaling'): void {
  const line = JSON.stringify({
    t: new Date().toISOString(),
    lvl: level,
    svc,
    msg,
    ...fields,
  });
  // Single line, no envelope bodies, no tokens, no SDP material, no account
  // key material (auth_key/salts/verifiers/session tokens/roster ciphertext).
  (level === 'error' ? console.error : level === 'warn' ? console.warn : console.log)(line);
}

export const log = {
  debug: (msg: string, fields: Fields = {}, svc?: string) => {
    if (process.env['SIGNALING_LOG_DEBUG'] === '1') emit('debug', msg, fields, svc);
  },
  info: (msg: string, fields: Fields = {}, svc?: string) => emit('info', msg, fields, svc),
  warn: (msg: string, fields: Fields = {}, svc?: string) => emit('warn', msg, fields, svc),
  error: (msg: string, fields: Fields = {}, svc?: string) => emit('error', msg, fields, svc),
};
