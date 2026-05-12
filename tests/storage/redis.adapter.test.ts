import Redis from "ioredis-mock";
import { RedisStoreAdapter } from "../../src/storage/adapters/redis.adapter";
import { runAdapterContractTests } from "./adapter-contract.suite";

/**
 * RedisStoreAdapter Test Suite
 * 
 * Uses ioredis-mock for high-speed testing with full polyfills for
 * the custom atomic Lua commands used in the production adapter.
 */
runAdapterContractTests("RedisStoreAdapter", async () => {
  const redis = new Redis();
  const adapter = new RedisStoreAdapter(redis);

  /**
   * Polyfill: ossecCreateSession
   * Atomic creation with limit enforcement.
   */
  // @ts-expect-error - Custom Lua polyfill
  redis.ossecCreateSession = async (
    userKey: string,
    sessKey: string,
    tokenKey: string,
    maxSessions: number,
    now: number,
    recordJson: string,
    id: string,
    tokenHash: string,
    ttl: number,
    score: number,
    maxAbsTtl: number,
    status: string
  ) => {
    if (maxSessions > 0 && status === "active") {
      await redis.zremrangebyscore(userKey, "-inf", now);
      const count = await redis.zcount(userKey, now, "+inf");
      if (count >= maxSessions) {
        throw new Error("ERR_SESSION_LIMIT_REACHED");
      }
    }

    const pipeline = redis.pipeline();
    pipeline.set(sessKey, recordJson, "EX", ttl);
    pipeline.set(tokenKey, id, "EX", ttl);
    if (status === "active") {
      pipeline.zadd(userKey, score, `${id}:${tokenHash}`);
      pipeline.expire(userKey, maxAbsTtl);
    }
    await pipeline.exec();
    return 1;
  };

  /**
   * Polyfill: ossecUpdateSession
   * Atomic update with rotation sync.
   */
  // @ts-expect-error - Custom Lua polyfill
  redis.ossecUpdateSession = async (
    sessKey: string,
    userKey: string,
    updatesJson: string,
    ttl: number,
    score: number,
    tokenPrefix: string,
    maxAbsTtl: number
  ) => {
    const data = await redis.get(sessKey);
    if (!data) return null;

    const record = JSON.parse(data);
    const oldTokenHash = record.tokenHash;
    const updates = JSON.parse(updatesJson);
    const updatedRecord = { ...record, ...updates };
    const newTokenHash = updatedRecord.tokenHash;

    const pipeline = redis.pipeline();
    pipeline.set(sessKey, JSON.stringify(updatedRecord), "EX", ttl);

    if (oldTokenHash !== newTokenHash) {
      pipeline.unlink(tokenPrefix + oldTokenHash);
    }
    pipeline.set(tokenPrefix + newTokenHash, updatedRecord.id, "EX", ttl);

    if (updatedRecord.status === "active") {
      if (oldTokenHash !== newTokenHash) {
        pipeline.zrem(userKey, `${updatedRecord.id}:${oldTokenHash}`);
      }
      pipeline.zadd(userKey, score, `${updatedRecord.id}:${newTokenHash}`);
      pipeline.expire(userKey, maxAbsTtl);
    } else {
      pipeline.zrem(userKey, `${updatedRecord.id}:${oldTokenHash}`);
      pipeline.zrem(userKey, `${updatedRecord.id}:${newTokenHash}`);
    }

    await pipeline.exec();
    return 1;
  };

  /**
   * Polyfill: ossecDeleteSession
   * Atomic annihilation of record and indices.
   */
  // @ts-expect-error - Custom Lua polyfill
  redis.ossecDeleteSession = async (sessKey: string, userKey: string, tokenPrefix: string) => {
    const data = await redis.get(sessKey);
    if (!data) return 0;

    const record = JSON.parse(data);
    const pipeline = redis.pipeline();
    pipeline.unlink(sessKey);
    pipeline.unlink(tokenPrefix + record.tokenHash);
    pipeline.zrem(userKey, `${record.id}:${record.tokenHash}`);
    await pipeline.exec();
    return 1;
  };

  return adapter;
});
