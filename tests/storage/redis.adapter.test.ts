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
   * Atomic creation with native time sync and limit enforcement.
   */
  // @ts-expect-error - Custom Lua polyfill
  redis.ossecCreateSession = async (
    userKey: string,
    sessKey: string,
    tokenKey: string,
    maxSessions: number,
    recordJson: string,
    id: string,
    tokenHash: string,
    ttl: number,
    score: number,
    maxAbsTtl: number,
    status: string
  ) => {
    // Mimic redis.call('TIME')
    const now = Date.now();

    if (maxSessions > 0 && status === "active") {
      await redis.zremrangebyscore(userKey, "-inf", now);
      const count = await redis.zcount(userKey, now, "+inf");
      if (count >= maxSessions) {
        throw new Error("ERR_SESSION_LIMIT_REACHED");
      }
    }

    const pipeline = redis.pipeline();
    // SET ... NX simulation
    const exists = await redis.exists(sessKey);
    if (exists) throw new Error("ERR_SESSION_ALREADY_EXISTS");

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
   * Atomic update with native time sync and rotation guard.
   */
  // @ts-expect-error - Custom Lua polyfill
  redis.ossecUpdateSession = async (
    sessKey: string,
    userKey: string,
    updatesJson: string,
    ttl: number,
    score: number,
    tokenPrefix: string,
    maxSessions: number,
    maxAbsTtl: number
  ) => {
    const data = await redis.get(sessKey);
    if (!data) return null;

    const record = JSON.parse(data);
    const oldTokenHash = record.tokenHash;
    const oldStatus = record.status;
    const updates = JSON.parse(updatesJson);
    const updatedRecord = { ...record, ...updates };
    const newTokenHash = updatedRecord.tokenHash;
    const status = updatedRecord.status;

    // Mimic redis.call('TIME')
    const now = Date.now();

    if (status === "active") {
      await redis.zremrangebyscore(userKey, "-inf", now);
      
      // Enforce limit if becoming active
      if (oldStatus !== "active" && maxSessions > 0) {
        const count = await redis.zcount(userKey, now, "+inf");
        if (count >= maxSessions) {
          throw new Error("ERR_SESSION_LIMIT_REACHED");
        }
      }
    }

    const pipeline = redis.pipeline();
    pipeline.set(sessKey, JSON.stringify(updatedRecord), "EX", ttl);

    if (oldTokenHash !== newTokenHash) {
      pipeline.unlink(tokenPrefix + oldTokenHash);
    }
    pipeline.set(tokenPrefix + newTokenHash, updatedRecord.id, "EX", ttl);

    if (status === "active") {
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
   * Polyfill: ossecRotateSession
   * Atomic session rotation (1-to-1 replacement).
   */
  // @ts-expect-error - Custom Lua polyfill
  redis.ossecRotateSession = async (
    oldSessKey: string,
    oldTokenKey: string,
    userKey: string,
    newSessKey: string,
    newTokenKey: string,
    maxSessions: number,
    oldUpdateJson: string,
    newRecordJson: string,
    newId: string,
    newTokenHash: string,
    ttl: number,
    score: number,
    maxAbsTtl: number
  ) => {
    const data = await redis.get(oldSessKey);
    if (!data) throw new Error("ERR_SESSION_NOT_FOUND");
    const record = JSON.parse(data);
    if (record.status !== "active") throw new Error("ERR_SESSION_NOT_ACTIVE");

    const now = Date.now();
    await redis.zremrangebyscore(userKey, "-inf", now);
    
    if (maxSessions > 0) {
      const count = await redis.zcount(userKey, now, "+inf");
      if (count >= maxSessions) throw new Error("ERR_SESSION_LIMIT_REACHED");
    }

    const pipeline = redis.pipeline();
    // Update OLD
    pipeline.set(oldSessKey, oldUpdateJson, "EX", ttl);
    pipeline.unlink(oldTokenKey);
    pipeline.zrem(userKey, `${record.id}:${record.tokenHash}`);

    // Create NEW
    pipeline.set(newSessKey, newRecordJson, "EX", ttl);
    pipeline.set(newTokenKey, newId, "EX", ttl);
    pipeline.zadd(userKey, score, `${newId}:${newTokenHash}`);
    pipeline.expire(userKey, maxAbsTtl);

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
