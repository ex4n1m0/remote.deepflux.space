/**
 * Client <-> service transport framing (NOT the signaling envelope contract).
 *
 * This is the service's own control protocol over the WebSocket and the
 * HTTP fallback: `op` frames as JSON text. `svc_version` is this framing's
 * version (independent of the envelope `protocol_version`); bumps are
 * additive-only in the same way.
 *
 * Frames carry envelopes opaquely as JSON values — the service validates
 * envelopes with lib/envelope.ts and never interprets SDP/ICE contents.
 */
import { z } from 'zod';

export const SERVICE_PROTOCOL_VERSION = 1 as const;

// --- client -> service -----------------------------------------------------

export const helloFrameSchema = z.object({
  op: z.literal('hello'),
  device_id: z.string().min(1).max(64),
  /** Resume delivery after this mailbox seq (at-least-once until acked). */
  resume_seq: z.number().int().nonnegative().default(0),
  svc_version: z.number().int().optional(),
});

export const sendFrameSchema = z.object({
  op: z.literal('send'),
  envelope: z.unknown(),
});

export const ackFrameSchema = z.object({
  op: z.literal('ack'),
  seq: z.number().int().nonnegative(),
});

/** Force one mailbox drain (otherwise the interval drives it). */
export const pollFrameSchema = z.object({ op: z.literal('poll') });

export const clientFrameSchema = z.discriminatedUnion('op', [
  helloFrameSchema,
  sendFrameSchema,
  ackFrameSchema,
  pollFrameSchema,
]);

// --- HTTP fallback bodies (POST /api/signal) -------------------------------

export const httpSendSchema = sendFrameSchema;
export const httpPollSchema = z.object({
  op: z.literal('poll'),
  device_id: z.string().min(1).max(64),
  after_seq: z.number().int().nonnegative().default(0),
  max: z.number().int().positive().max(1000).default(64),
});
export const httpAckSchema = z.object({
  op: z.literal('ack'),
  device_id: z.string().min(1).max(64),
  seq: z.number().int().nonnegative(),
});

// --- service -> client ------------------------------------------------------

export type HelloOkFrame = {
  op: 'hello_ok';
  svc_version: number;
  device_id: string;
  resume_seq: number;
  latest_seq: number;
  ttl_device_s: number;
  /**
   * false when the device had no live presence at hello time: the client
   * must (re-)send Register on this socket; deliveries start once it lands.
   */
  authed: boolean;
};

export type DeliverFrame = {
  op: 'deliver';
  seq: number;
  envelope: unknown;
};

export type SendResultFrame = {
  op: 'send_result';
  message_id: string;
  ok: boolean;
  duplicate?: boolean;
  error?: string;
};

export type ByeFrame = { op: 'bye'; reason: 'shutdown' | 'max_duration' | 'unauthorized' | 'not_registered' };

export type ErrorFrame = { op: 'error'; error: string; detail?: string };

export type ServerFrame = HelloOkFrame | DeliverFrame | SendResultFrame | ByeFrame | ErrorFrame;

export type HttpPollResponse = {
  ok: true;
  envelopes: Array<{ seq: number; envelope: unknown }>;
  latest_seq: number;
};

export type HttpSendResponse = { ok: true; duplicate: boolean } | { ok: false; error: string };
