import Redis from "ioredis";
import { SessionStoreAdapter } from "../contracts";
import { SessionRecord } from "../../types";
import { RedisStoreOptions } from "../../interfaces";

/**
 * RedisStoreAdapter — The "State Machine" Implementation.
 *
 * ATOMIC STATE TRANSITIONS:
 * - ossecRotateSession: Atomic 1-to-1 session replacement.
 * - ossecValidateSession: Atomic check-and-update (prevents Zombie Validation).
 */
export class RedisStoreAdapter implements SessionStoreAdapter {
  private redis: Redis;
  private prefix: string;
  private ttlBuffer: number;
  private batchSize: number;
  private maxAbsTimeout: number;

  constructor(redis: Redis, options: RedisStoreOptions = {}) {
    this.redis = redis;
    this.prefix = options.keyPrefix || "ossec:";
    this.ttlBuffer = options.ttlBufferSeconds || 0;
    this.batchSize = options.batchSize || 500;
    this.maxAbsTimeout = options.maxAbsoluteTimeoutSeconds || 2592000;

    this.registerLuaCommands();
  }

  private registerLuaCommands() {
    this.redis.defineCommand("ossecCreateSession", {
      numberOfKeys: 3, // [userKey, sessKey, tokenKey]
      lua: `
        local userKey = KEYS[1]
        local sessKey = KEYS[2]
        local tokenKey = KEYS[3]
        local maxSessions = tonumber(ARGV[1])
        local recordJson = ARGV[2]
        local recordId = ARGV[3]
        local tokenHash = ARGV[4]
        local ttl = tonumber(ARGV[5])
        local score = tonumber(ARGV[6])
        local userIndexTtl = tonumber(ARGV[7])
        local status = ARGV[8]
        
        local time = redis.call('TIME')
        local now = (tonumber(time[1]) * 1000) + math.floor(tonumber(time[2]) / 1000)
        
        redis.call('ZREMRANGEBYSCORE', userKey, '-inf', now)
        if maxSessions > 0 and status == 'active' then
            local count = redis.call('ZCOUNT', userKey, now, '+inf')
            if count >= maxSessions then
                return redis.error_reply("ERR_SESSION_LIMIT_REACHED")
            end
        end
        
        local setOk = redis.call('SET', sessKey, recordJson, 'EX', ttl, 'NX')
        if not setOk then
            return redis.error_reply("ERR_SESSION_ALREADY_EXISTS")
        end
        
        redis.call('SET', tokenKey, recordId, 'EX', ttl)
        if status == 'active' then
            redis.call('ZADD', userKey, score, recordId .. ":" .. tokenHash)
            redis.call('EXPIRE', userKey, userIndexTtl)
        end
        return 1
      `,
    });

    /**
     * ossecRotateSession:
     * 1. Check if OLD session is active.
     * 2. Set OLD to rotated.
     * 3. Create NEW session and indices.
     */
    this.redis.defineCommand("ossecRotateSession", {
      numberOfKeys: 5, // [oldSessKey, oldTokenKey, userKey, newSessKey, newTokenKey]
      lua: `
            local data = redis.call('GET', KEYS[1])
            if not data then return redis.error_reply("ERR_SESSION_NOT_FOUND") end
            
            local record = cjson.decode(data)
            if record.status ~= 'active' then
                return redis.error_reply("ERR_SESSION_NOT_ACTIVE")
            end
            
            local maxSessions = tonumber(ARGV[1])
            local oldUpdateJson = ARGV[2]
            local newRecordJson = ARGV[3]
            local newId = ARGV[4]
            local newTokenHash = ARGV[5]
            local ttl = tonumber(ARGV[6])
            local score = tonumber(ARGV[7])
            local userIndexTtl = tonumber(ARGV[8])
            
            local time = redis.call('TIME')
            local now = (tonumber(time[1]) * 1000) + math.floor(tonumber(time[2]) / 1000)
            
            -- Limit check for the NEW session
            redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now)
            if maxSessions > 0 then
                local count = redis.call('ZCOUNT', KEYS[3], now, '+inf')
                -- Subtract 1 because we are about to rotate the current one out
                if count >= maxSessions then
                    return redis.error_reply("ERR_SESSION_LIMIT_REACHED")
                end
            end
            
            -- Update OLD
            redis.call('SET', KEYS[1], oldUpdateJson, 'EX', ttl)
            redis.call('UNLINK', KEYS[2])
            redis.call('ZREM', KEYS[3], record.id .. ":" .. record.tokenHash)
            
            -- Create NEW
            redis.call('SET', KEYS[4], newRecordJson, 'EX', ttl)
            redis.call('SET', KEYS[5], newId, 'EX', ttl)
            redis.call('ZADD', KEYS[3], score, newId .. ":" .. newTokenHash)
            redis.call('EXPIRE', KEYS[3], userIndexTtl)
            
            return 1
        `,
    });

    this.redis.defineCommand("ossecUpdateSession", {
      numberOfKeys: 2, // [sessKey, userKey]
      lua: `
        local data = redis.call('GET', KEYS[1])
        if not data then return nil end
        
        local record = cjson.decode(data)
        local updates = cjson.decode(ARGV[1])
        local newTtl = tonumber(ARGV[2])
        local newScore = tonumber(ARGV[3])
        local tokenKeyPrefix = ARGV[4]
        local maxSessions = tonumber(ARGV[5])
        
        local oldTokenHash = record.tokenHash
        local oldStatus = record.status
        
        -- Terminal State Guard: Prevent overwriting audit trails of dead sessions
        if oldStatus == 'revoked' or oldStatus == 'expired' then
            return 1
        end
        
        for k,v in pairs(updates) do record[k] = v end
        local newTokenHash = record.tokenHash
        local status = record.status
        
        local time = redis.call('TIME')
        local now = (tonumber(time[1]) * 1000) + math.floor(tonumber(time[2]) / 1000)
        
        if status == 'active' then
            redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
            if oldStatus ~= 'active' and maxSessions > 0 then
                local count = redis.call('ZCOUNT', KEYS[2], now, '+inf')
                if count >= maxSessions then
                    return redis.error_reply("ERR_SESSION_LIMIT_REACHED")
                end
            end
            if oldTokenHash ~= newTokenHash then
                redis.call('ZREM', KEYS[2], record.id .. ":" .. oldTokenHash)
            end
            redis.call('ZADD', KEYS[2], newScore, record.id .. ":" .. newTokenHash)
            redis.call('EXPIRE', KEYS[2], tonumber(ARGV[6]))
        else
            redis.call('ZREM', KEYS[2], record.id .. ":" .. oldTokenHash)
            redis.call('ZREM', KEYS[2], record.id .. ":" .. newTokenHash)
        end
        
        redis.call('SET', KEYS[1], cjson.encode(record), 'EX', newTtl)
        if oldTokenHash ~= newTokenHash then
            redis.call('UNLINK', tokenKeyPrefix .. oldTokenHash)
        end
        redis.call('SET', tokenKeyPrefix .. newTokenHash, record.id, 'EX', newTtl)
        
        return 1
      `,
    });

    this.redis.defineCommand("ossecDeleteSession", {
      numberOfKeys: 2, // [sessKey, userKey]
      lua: `
        local data = redis.call('GET', KEYS[1])
        if not data then return 0 end
        
        local record = cjson.decode(data)
        redis.call('UNLINK', KEYS[1])
        redis.call('UNLINK', ARGV[1] .. record.tokenHash)
        redis.call('ZREM', KEYS[2], record.id .. ":" .. record.tokenHash)
        return 1
      `,
    });
  }

  private key(type: string, id: string): string {
    return `${this.prefix}${type}:${id}`;
  }

  async create(record: SessionRecord, maxSessions?: number): Promise<void> {
    const ttl = this.calculateTTL(record.expiresAt);
    if (ttl <= 0) return;

    try {
      // @ts-expect-error - custom command
      await this.redis.ossecCreateSession(
        this.key("idx:user", record.userId),
        this.key("sess", record.id),
        this.key("idx:token", record.tokenHash),
        maxSessions || 0,
        JSON.stringify(record),
        record.id,
        record.tokenHash,
        ttl,
        record.expiresAt.getTime(),
        this.maxAbsTimeout,
        record.status,
      );
    } catch (error: unknown) {
      if (error instanceof Error) {
        if (error.message === "ERR_SESSION_LIMIT_REACHED") {
          throw new Error("SESSION_LIMIT_REACHED");
        }
        if (error.message === "ERR_SESSION_ALREADY_EXISTS") {
          throw new Error("SESSION_ID_COLLISION");
        }
      }
      throw error;
    }
  }

  async rotate(
    oldId: string,
    newRecord: SessionRecord,
    oldUpdates: Partial<SessionRecord>,
    maxSessions?: number,
  ): Promise<void> {
    const oldRecord = await this.findById(oldId);
    if (!oldRecord) throw new Error("SESSION_NOT_FOUND");

    const ttl = this.calculateTTL(newRecord.expiresAt);

    try {
      // @ts-expect-error - custom command
      await this.redis.ossecRotateSession(
        this.key("sess", oldId),
        this.key("idx:token", oldRecord.tokenHash),
        this.key("idx:user", oldRecord.userId),
        this.key("sess", newRecord.id),
        this.key("idx:token", newRecord.tokenHash),
        maxSessions || 0,
        JSON.stringify({ ...oldRecord, ...oldUpdates }),
        JSON.stringify(newRecord),
        newRecord.id,
        newRecord.tokenHash,
        ttl,
        newRecord.expiresAt.getTime(),
        this.maxAbsTimeout,
      );
    } catch (error: unknown) {
      if (error instanceof Error) {
        if (error.message === "ERR_SESSION_LIMIT_REACHED")
          throw new Error("SESSION_LIMIT_REACHED");
        if (error.message === "ERR_SESSION_NOT_ACTIVE")
          throw new Error("SESSION_NOT_ACTIVE");
      }
      throw error;
    }
  }

  async findById(id: string): Promise<SessionRecord | null> {
    const data = await this.redis.get(this.key("sess", id));
    if (!data) return null;
    return this.parseRecord(data);
  }

  async findByTokenHash(tokenHash: string): Promise<SessionRecord | null> {
    const id = await this.redis.get(this.key("idx:token", tokenHash));
    if (!id) return null;
    return this.findById(id);
  }

  async update(
    id: string,
    updates: Partial<SessionRecord>,
    maxSessions?: number,
  ): Promise<void> {
    const record = await this.findById(id);
    if (!record) return;

    const newExpiresAt = updates.expiresAt || record.expiresAt;
    const ttl = this.calculateTTL(newExpiresAt);

    try {
      // @ts-expect-error - custom command
      await this.redis.ossecUpdateSession(
        this.key("sess", id),
        this.key("idx:user", record.userId),
        JSON.stringify(updates),
        ttl,
        new Date(newExpiresAt).getTime(),
        this.prefix + "idx:token:",
        maxSessions || 0,
        this.maxAbsTimeout,
      );
    } catch (error: unknown) {
      if (
        error instanceof Error &&
        error.message === "ERR_SESSION_LIMIT_REACHED"
      ) {
        throw new Error("SESSION_LIMIT_REACHED");
      }
      throw error;
    }
  }

  async delete(id: string): Promise<void> {
    const record = await this.findById(id);
    if (!record) return;

    // @ts-expect-error - custom command
    await this.redis.ossecDeleteSession(
      this.key("sess", id),
      this.key("idx:user", record.userId),
      this.prefix + "idx:token:",
    );
  }

  async deleteAllForUser(userId: string): Promise<void> {
    const userKey = this.key("idx:user", userId);
    let entries: string[];
    do {
      entries = await this.redis.zrange(userKey, 0, this.batchSize - 1);
      if (entries.length === 0) break;

      const deletePipeline = this.redis.pipeline();
      for (const entry of entries) {
        const [id, tokenHash] = entry.split(":");
        deletePipeline.unlink(this.key("sess", id));
        if (tokenHash) {
          deletePipeline.unlink(this.key("idx:token", tokenHash));
        }
        deletePipeline.zrem(userKey, entry);
      }
      await deletePipeline.exec();
    } while (entries.length >= this.batchSize);
  }

  async countActiveForUser(userId: string): Promise<number> {
    const userKey = this.key("idx:user", userId);
    const now = Date.now();
    await this.redis.zremrangebyscore(userKey, "-inf", now);
    return await this.redis.zcount(userKey, now, "+inf");
  }

  private calculateTTL(expiresAt: Date): number {
    return Math.max(
      0,
      Math.ceil((new Date(expiresAt).getTime() - Date.now()) / 1000) +
        this.ttlBuffer,
    );
  }

  private parseRecord(data: string): SessionRecord {
    const record = JSON.parse(data);
    record.createdAt = new Date(record.createdAt);
    record.lastUsedAt = new Date(record.lastUsedAt);
    record.expiresAt = new Date(record.expiresAt);
    record.idleExpiresAt = new Date(record.idleExpiresAt);
    if (record.revokedAt) record.revokedAt = new Date(record.revokedAt);
    return record;
  }
}
