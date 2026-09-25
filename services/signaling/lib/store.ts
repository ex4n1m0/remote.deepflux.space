/**
 * The thin storage seam (deliverable: "design the storage behind a thin
 * interface").
 *
 * One interface, two interchangeable backends:
 *  - `lib/upstash.ts` — the Upstash Redis REST driver (production; also used
 *    locally against the bundled emulator, which speaks the identical REST
 *    pipeline protocol).
 *  - `tools/upstash-emulator.mjs` — an out-of-process local emulator with
 *    real TTL semantics, so `vercel dev` function instances never hold
 *    authoritative state in memory.
 *
 * The interface is deliberately tiny: string KV with TTL + one sorted-set
 * shape for the mailbox. Everything the service needs (presence refresh,
 * NX dedupe tombstones, seq counters, capped ZSET mailbox) composes from
 * these primitives, so a different store (DynamoDB, KV) is a single-file
 * adapter away.
 */

export interface Store {
  /** GET; null when missing. */
  get(key: string): Promise<string | null>;

  /** SET key value EX ttl NX — true when the key was newly set. */
  setNxEx(key: string, value: string, ttlSec: number): Promise<boolean>;

  /** SET key value EX ttl (unconditional write/refresh). */
  setEx(key: string, value: string, ttlSec: number): Promise<void>;

  /** Batched SET key value EX ttl — one round trip where the store allows. */
  setExMany(entries: ReadonlyArray<[string, string, number]>): Promise<void>;

  /** EXPIRE — refresh TTL; false when the key does not exist. */
  expire(key: string, ttlSec: number): Promise<boolean>;

  /** DEL keys — count removed. */
  del(...keys: string[]): Promise<number>;

  /** INCR — atomic counter. */
  incr(key: string): Promise<number>;

  /** Refresh TTL on the counter key after INCR (best effort). */
  expireAfterIncr(key: string, ttlSec: number): Promise<void>;

  /** ZADD key score member. */
  zadd(key: string, score: number, member: string): Promise<void>;

  /**
   * ZRANGEBYSCORE key (min +INF LIMIT 0 count — ascending, exclusive min.
   * (The max bound was always +INF; removed — QA F43c.)
   */
  zrangebyscore(key: string, min: number, limit: number): Promise<string[]>;

  /** Read the oldest `limit` members by score (ascending). */
  zoldest(key: string, limit: number): Promise<string[]>;

  /** ZREMRANGEBYSCORE key -inf max (inclusive). */
  zremrangebyscoreMax(key: string, maxInclusive: number): Promise<number>;

  /** ZREMRANGEBYRANK key 0 -(limit+1) — trim to newest `limit` entries. */
  ztrimToNewest(key: string, limit: number): Promise<void>;

  /** ZREM key members. */
  zrem(key: string, ...members: string[]): Promise<number>;
}
