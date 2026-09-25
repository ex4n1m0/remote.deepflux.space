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

function emit(level: Level, msg: string, fields: Record<string, string | number>): void {
  const line = JSON.stringify({
    t: new Date().toISOString(),
    lvl: level,
    svc: 'signaling',
    msg,
    ...fields,
  });
  // Single line, no envelope bodies, no tokens, no SDP material.
  (level === 'error' ? console.error : level === 'warn' ? console.warn : console.log)(line);
}

export const log = {
  debug: (msg: string, fields: Record<string, string | number> = {}) => {
    if (process.env['SIGNALING_LOG_DEBUG'] === '1') emit('debug', msg, fields);
  },
  info: (msg: string, fields: Record<string, string | number> = {}) => emit('info', msg, fields),
  warn: (msg: string, fields: Record<string, string | number> = {}) => emit('warn', msg, fields),
  error: (msg: string, fields: Record<string, string | number> = {}) => emit('error', msg, fields),
};
