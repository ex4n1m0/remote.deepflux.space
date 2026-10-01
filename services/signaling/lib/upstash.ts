/**
 * Upstash Redis REST driver for the `Store` seam.
 *
 * Speaks the documented Upstash REST pipeline protocol:
 *   POST {url}/pipeline
 *   Authorization: Bearer {token}
 *   body: [["SET","key","value","EX","30"], ...]
 *   reply: [{"result":"OK"}] | [{"error":"ERR ..."}]
 *
 * The same driver runs against production Upstash and against the local
 * emulator (`tools/upstash-emulator.mjs`), which implements this exact
 * protocol — one code path, verified locally, deployed unchanged.
 *
 * Keys/values are UTF-8 JSON strings only (no binary), so plain JSON string
 * encoding is sufficient (Upstash REST accepts it; binary would need base64).
 */
import type { Store } from './store.ts';
import { log } from './log.ts';

interface PipelineResult {
  result?: unknown;
  error?: string;
}

export class UpstashRestStore implements Store {
  private readonly url: string;
  private readonly token: string;

  constructor(url: string, token: string) {
    this.url = url.replace(/\/+$/, '');
    this.token = token;
  }

  static fromEnv(): UpstashRestStore {
    // Two credential namespaces, both official: Upstash-native
    // UPSTASH_REDIS_REST_* and the Vercel Marketplace integration's
    // legacy KV_* names (what `vercel integration resource connect
    // upstash-kv` injects). UPSTASH_* wins when both exist. The read-only
    // KV_REST_API_READ_ONLY_TOKEN is deliberately never considered — the
    // service needs write access.
    const url = process.env['UPSTASH_REDIS_REST_URL'] ?? process.env['KV_REST_API_URL'];
    const token = process.env['UPSTASH_REDIS_REST_TOKEN'] ?? process.env['KV_REST_API_TOKEN'];
    if (!url || !token) {
      throw new Error(
        'missing UPSTASH_REDIS_REST_URL/TOKEN (or KV_REST_API_URL/TOKEN from the Vercel Upstash integration; see .env.example; never print real values)',
      );
    }
    return new UpstashRestStore(url, token);
  }

  /** Execute one pipeline batch; throws on transport or command errors. */
  private async pipeline(commands: string[][]): Promise<unknown[]> {
    const res = await fetch(`${this.url}/pipeline`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${this.token}`,
        'content-type': 'application/json',
      },
      // Wire shape verified against production Upstash (first deploy,
      // 2026-10-01): an array of command arrays — NOT [{command:[...]}]
      // objects, which real Upstash rejects with
      // "ERR failed to parse pipeline command".
      body: JSON.stringify(commands),
    });
    if (!res.ok) {
      throw new Error(`store pipeline http ${res.status}`);
    }
    const body = (await res.json()) as PipelineResult[];
    const out: unknown[] = body.map((entry, i) => {
      if (entry && typeof entry === 'object' && 'error' in entry && entry.error) {
        throw new Error(`store cmd ${commands[i]?.[0]} failed: ${entry.error}`);
      }
      return (entry as { result?: unknown }).result ?? null;
    });
    return out;
  }

  async get(key: string): Promise<string | null> {
    const [v] = await this.pipeline([['GET', key]]);
    return typeof v === 'string' ? v : null;
  }

  async setNxEx(key: string, value: string, ttlSec: number): Promise<boolean> {
    const [v] = await this.pipeline([['SET', key, value, 'EX', String(ttlSec), 'NX']]);
    return v === 'OK';
  }

  async setEx(key: string, value: string, ttlSec: number): Promise<void> {
    await this.pipeline([['SET', key, value, 'EX', String(ttlSec)]]);
  }

  async setExMany(entries: ReadonlyArray<[string, string, number]>): Promise<void> {
    if (entries.length === 0) return;
    await this.pipeline(entries.map(([k, v, ttl]) => ['SET', k, v, 'EX', String(ttl)]));
  }

  async expire(key: string, ttlSec: number): Promise<boolean> {
    const [v] = await this.pipeline([['EXPIRE', key, String(ttlSec)]]);
    return v === 1;
  }

  async del(...keys: string[]): Promise<number> {
    if (keys.length === 0) return 0;
    const [v] = await this.pipeline([['DEL', ...keys]]);
    return typeof v === 'number' ? v : 0;
  }

  async incr(key: string): Promise<number> {
    const [v] = await this.pipeline([['INCR', key]]);
    return typeof v === 'number' ? v : 0;
  }

  async expireAfterIncr(key: string, ttlSec: number): Promise<void> {
    try {
      await this.pipeline([['EXPIRE', key, String(ttlSec)]]);
    } catch (err) {
      // Counter TTL refresh is best-effort: the mailbox key TTL bounds it.
      log.warn('store.expire_after_incr_failed', { key, err: String(err).slice(0, 80) });
    }
  }

  async zadd(key: string, score: number, member: string): Promise<void> {
    await this.pipeline([['ZADD', key, String(score), member]]);
  }

  async zrangebyscore(key: string, min: number, limit: number): Promise<string[]> {
    const [v] = await this.pipeline([
      ['ZRANGEBYSCORE', key, `(${min}`, '+INF', 'LIMIT', '0', String(limit)],
    ]);
    return Array.isArray(v) ? (v as string[]) : [];
  }

  async zoldest(key: string, limit: number): Promise<string[]> {
    const [v] = await this.pipeline([
      ['ZRANGE', key, '0', String(Math.max(0, limit - 1))],
    ]);
    return Array.isArray(v) ? (v as string[]) : [];
  }

  async zremrangebyscoreMax(key: string, maxInclusive: number): Promise<number> {
    const [v] = await this.pipeline([
      ['ZREMRANGEBYSCORE', key, '-INF', String(maxInclusive)],
    ]);
    return typeof v === 'number' ? v : 0;
  }

  async ztrimToNewest(key: string, limit: number): Promise<void> {
    // Keep ranks [-limit, -1] (the newest `limit`); drop everything older.
    const stop = -(limit + 1);
    await this.pipeline([['ZREMRANGEBYRANK', key, '0', String(stop)]]);
  }

  async zrem(key: string, ...members: string[]): Promise<number> {
    if (members.length === 0) return 0;
    const [v] = await this.pipeline([['ZREM', key, ...members]]);
    return typeof v === 'number' ? v : 0;
  }
}
