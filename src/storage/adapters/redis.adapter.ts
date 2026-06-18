import Redis from "ioredis";
import { SessionStoreAdapter } from "../contracts";
import {
  SessionRecord,
  SessionStatus,
  SessionReasonCode,
  SessionListParams,
  SessionListResult,
} from "../../types";
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
     * 1. Check if OLD session is active (read once, atomically, inside Lua).
     * 2. Set OLD to rotated.
     * 3. Create NEW session and indices.
     * ARGV[9] = oldTokenHash, ARGV[10] = oldId (passed from TS to avoid pre-fetch round-trip)
     */
    this.redis.defineCommand("ossecRotateSession", {
      numberOfKeys: 5, // [oldSessKey, oldTokenKey, userKey, newSessKey, newTokenKey]
      lua: `
            -- 1. Retrieve the existing session record
            local data = redis.call('GET', KEYS[1])
            if not data then return redis.error_reply("ERR_SESSION_NOT_FOUND") end
            
            -- 2. Validate that the existing session is active before allowing rotation
            local record = cjson.decode(data)
            if record.status ~= 'active' then
                return redis.error_reply("ERR_SESSION_NOT_ACTIVE")
            end
            
            -- 3. Parse input arguments
            local maxSessions = tonumber(ARGV[1])
            local oldUpdateJson = ARGV[2]
            local newRecordJson = ARGV[3]
            local newId = ARGV[4]
            local newTokenHash = ARGV[5]
            local ttl = tonumber(ARGV[6])
            local score = tonumber(ARGV[7])
            local userIndexTtl = tonumber(ARGV[8])
            local oldTokenHash = ARGV[9]
            local oldId = ARGV[10]
            
            -- 4. Calculate the current timestamp in milliseconds
            local time = redis.call('TIME')
            local now = (tonumber(time[1]) * 1000) + math.floor(tonumber(time[2]) / 1000)
            
            -- 5. Purge expired sessions and enforce the session limits for the new active session
            redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now)
            if maxSessions > 0 then
                local count = redis.call('ZCOUNT', KEYS[3], now, '+inf')
                -- Note: The old session is still in the active count and will be removed.
                -- Thus, net change in session count is 0 (old session deleted, new session added).
                if count > maxSessions then
                    return redis.error_reply("ERR_SESSION_LIMIT_REACHED")
                end
            end
            
            -- 6. Update the old session status to 'rotated' and update its token index
            redis.call('SET', KEYS[1], oldUpdateJson, 'EX', ttl)
            redis.call('EXPIRE', KEYS[2], ttl)
            redis.call('ZREM', KEYS[3], oldId .. ":" .. oldTokenHash)
            
            -- 7. Persist the new active session and index it under the user's active set
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
        -- 1. Retrieve the existing session record
        local data = redis.call('GET', KEYS[1])
        if not data then return nil end
        
        -- 2. Decode the old record and parse input arguments
        local record = cjson.decode(data)
        local updates = cjson.decode(ARGV[1])
        local newTtl = tonumber(ARGV[2])
        local newScore = tonumber(ARGV[3])
        local tokenKeyPrefix = ARGV[4]
        local maxSessions = tonumber(ARGV[5])
        
        local oldTokenHash = record.tokenHash
        local oldStatus = record.status
        
        -- 3. Terminal State Guard: Prevent overwriting dead session audits (revoked or expired)
        if oldStatus == 'revoked' or oldStatus == 'expired' then
            return 1
        end
        
        -- 4. Apply the requested field updates to the session record object
        for k,v in pairs(updates) do record[k] = v end
        local newTokenHash = record.tokenHash
        local status = record.status
        
        -- 5. Calculate the current timestamp in milliseconds
        local time = redis.call('TIME')
        local now = (tonumber(time[1]) * 1000) + math.floor(tonumber(time[2]) / 1000)
        
        -- 6. Update user's active session indices
        if status == 'active' then
            -- Purge expired entries
            redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
            
            -- If session is becoming active from an inactive state, enforce active limit count
            if oldStatus ~= 'active' and maxSessions > 0 then
                local count = redis.call('ZCOUNT', KEYS[2], now, '+inf')
                if count >= maxSessions then
                    return redis.error_reply("ERR_SESSION_LIMIT_REACHED")
                end
            end
            
            -- If token hash has rotated, remove old token entry from active list
            if oldTokenHash ~= newTokenHash then
                redis.call('ZREM', KEYS[2], record.id .. ":" .. oldTokenHash)
            end
            
            -- Add new token entry to active list and renew key expiry
            redis.call('ZADD', KEYS[2], newScore, record.id .. ":" .. newTokenHash)
            redis.call('EXPIRE', KEYS[2], tonumber(ARGV[6]))
        else
            -- If session has been deactivated (revoked/expired), remove token entries from active list
            redis.call('ZREM', KEYS[2], record.id .. ":" .. oldTokenHash)
            redis.call('ZREM', KEYS[2], record.id .. ":" .. newTokenHash)
        end
        
        -- 7. Persist the updated session record back to Redis
        redis.call('SET', KEYS[1], cjson.encode(record), 'EX', newTtl)
        
        -- 8. Update individual token lookup indexes (Unlink old one if rotated)
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
    // Read the old record ONCE here to build the merged update JSON and derive
    // key components. The Lua script reuses the passed-in fields directly,
    // eliminating the redundant second GET that existed before inside Lua.
    const oldRecord = await this.findById(oldId);
    if (!oldRecord) throw new Error("SESSION_NOT_FOUND");

    const ttl = this.calculateTTL(newRecord.expiresAt);
    const mergedOldJson = JSON.stringify({ ...oldRecord, ...oldUpdates });

    try {
      // @ts-expect-error - custom command
      await this.redis.ossecRotateSession(
        this.key("sess", oldId),
        this.key("idx:token", oldRecord.tokenHash),
        this.key("idx:user", oldRecord.userId),
        this.key("sess", newRecord.id),
        this.key("idx:token", newRecord.tokenHash),
        maxSessions || 0,
        mergedOldJson,
        JSON.stringify(newRecord),
        newRecord.id,
        newRecord.tokenHash,
        ttl,
        newRecord.expiresAt.getTime(),
        this.maxAbsTimeout,
        oldRecord.tokenHash, // ARGV[9]: passed to Lua to avoid re-decoding JSON
        oldId, // ARGV[10]: passed to Lua to avoid re-decoding JSON
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

  async revokeAllForUser(
    userId: string,
    reason: SessionReasonCode,
    revokedAt: Date,
  ): Promise<string[]> {
    const affected: string[] = [];
    const userKey = this.key("idx:user", userId);

    // WHY: Batch pipeline approach (like deleteAllForUser) but with soft-revocation.
    // Reads session data, checks if not already revoked, updates status in-place.
    // Preserves records for audit trail instead of hard-deleting.
    let entries: string[];
    do {
      entries = await this.redis.zrange(userKey, 0, this.batchSize - 1);
      if (entries.length === 0) break;

      const readPipeline = this.redis.pipeline();
      const entryIds: string[] = [];
      for (const entry of entries) {
        const [id] = entry.split(":");
        readPipeline.get(this.key("sess", id));
        entryIds.push(id);
      }
      const results = await readPipeline.exec();
      if (!results) break;

      const writePipeline = this.redis.pipeline();
      for (let i = 0; i < results.length; i++) {
        const result = results[i];
        if (!result || result[0] || !result[1]) continue;
        const record = this.parseRecord(result[1] as string);
        if (record.status === SessionStatus.REVOKED) continue;

        record.status = SessionStatus.REVOKED;
        record.revokedAt = revokedAt;
        record.revocationReason = reason;
        const ttl = this.calculateTTL(record.expiresAt);

        writePipeline.set(
          this.key("sess", record.id),
          JSON.stringify(record),
          "EX",
          ttl,
        );
        // WHY: Remove from active session index since status is no longer active.
        writePipeline.zrem(userKey, `${record.id}:${record.tokenHash}`);
        affected.push(record.id);
      }
      await writePipeline.exec();
    } while (entries.length >= this.batchSize);

    // WHY: The sorted set only contains ACTIVE sessions. ROTATED sessions are
    // removed from the set during rotation but are still live within their grace
    // period. We must SCAN for them to ensure revokeAll truly revokes ALL live
    // sessions, not just ACTIVE ones. Safety bounds (timeout + max iterations)
    // prevent runaway scans on large Redis instances.
    const affectedSet = new Set(affected);
    const pattern = this.key("sess", "*");
    let cursorVal: string | undefined;
    let scanned = 0;
    const SCAN_BATCH = 100;
    const SCAN_TIMEOUT_MS = 5000;
    const SCAN_MAX_KEYS = 10000;
    const scanStart = Date.now();

    do {
      const result = await this.redis.scan(
        cursorVal === undefined ? "0" : cursorVal,
        "MATCH",
        pattern,
        "COUNT",
        SCAN_BATCH,
      );
      cursorVal = result[0];
      const keys = result[1];
      scanned += keys.length;

      if (keys.length > 0) {
        const newKeys = keys.filter((k) => {
          const id = k.split(":").pop()!;
          return !affectedSet.has(id);
        });

        if (newKeys.length > 0) {
          const readPipeline = this.redis.pipeline();
          for (const k of newKeys) readPipeline.get(k);
          const scanResults = await readPipeline.exec();
          if (scanResults) {
            const writePipeline = this.redis.pipeline();
            for (const r of scanResults) {
              if (!r || r[0] || !r[1]) continue;
              const record = this.parseRecord(r[1] as string);
              if (
                record.userId !== userId ||
                record.status !== SessionStatus.ROTATED
              )
                continue;
              // WHY: Skip expired ROTATED sessions — grace period is moot if
              // the session already expired by absolute timeout.
              if (record.expiresAt.getTime() <= Date.now()) continue;

              record.status = SessionStatus.REVOKED;
              record.revokedAt = revokedAt;
              record.revocationReason = reason;
              const ttl = this.calculateTTL(record.expiresAt);

              writePipeline.set(
                this.key("sess", record.id),
                JSON.stringify(record),
                "EX",
                ttl,
              );
              affected.push(record.id);
            }
            await writePipeline.exec();
          }
        }
      }

      if (Date.now() - scanStart > SCAN_TIMEOUT_MS) break;
      if (scanned > SCAN_MAX_KEYS) break;
    } while (cursorVal !== "0");

    return affected;
  }

  /**
   * WHY: Returns only ACTIVE + ROTATED sessions. ACTIVE sessions come from the
   * sorted set (fast O(N) where N = active count). ROTATED sessions are found via
   * bounded SCAN — they're few because ROTATED has a short grace period (typically 5min).
   * Excludes REVOKED/EXPIRED to avoid loading audit-piled records.
   *
   * SECURITY: SCAN iterates all sess:* keys (not user-scoped) because ROTATED sessions
   * are removed from the user sorted set. Safety bounds (timeout + max iterations)
   * prevent runaway scans from blocking Redis on large instances.
   */
  async findLiveSessionsForUser(userId: string): Promise<SessionRecord[]> {
    const userKey = this.key("idx:user", userId);
    const now = Date.now();

    // 1. Purge expired entries from sorted set, then fetch ACTIVE sessions
    await this.redis.zremrangebyscore(userKey, "-inf", now);
    const activeEntries = await this.redis.zrange(userKey, 0, -1);

    const live: SessionRecord[] = [];
    const hydrateIds: string[] = [];

    for (const entry of activeEntries) {
      const [id] = entry.split(":");
      hydrateIds.push(id);
    }

    // 2. Hydrate ACTIVE sessions via pipeline
    if (hydrateIds.length > 0) {
      const pipeline = this.redis.pipeline();
      for (const id of hydrateIds) pipeline.get(this.key("sess", id));
      const results = await pipeline.exec();
      if (results) {
        for (const r of results) {
          if (!r || r[0] || !r[1]) continue;
          const record = this.parseRecord(r[1] as string);
          if (
            record.userId === userId &&
            record.status === SessionStatus.ACTIVE
          ) {
            live.push(record);
          }
        }
      }
    }

    // 3. SCAN for ROTATED sessions (bounded — short grace period, few per user)
    // WHY: ROTATED sessions are removed from the sorted set but still usable
    // within the grace period. We must include them in "live" results.
    // SECURITY: Safety bounds prevent runaway SCAN on large Redis instances.
    const pattern = this.key("sess", "*");
    let cursorVal: string | undefined;
    const activeIds = new Set(hydrateIds);
    let scanned = 0;
    const SCAN_BATCH = 100;
    const SCAN_TIMEOUT_MS = 5000;
    const SCAN_MAX_KEYS = 10000;
    const scanStart = Date.now();

    do {
      const result = await this.redis.scan(
        cursorVal === undefined ? "0" : cursorVal,
        "MATCH",
        pattern,
        "COUNT",
        SCAN_BATCH,
      );
      cursorVal = result[0];
      const keys = result[1];
      scanned += keys.length;

      if (keys.length > 0) {
        const newKeys = keys.filter((k) => {
          const id = k.split(":").pop()!;
          return !activeIds.has(id);
        });

        if (newKeys.length > 0) {
          const pipeline = this.redis.pipeline();
          for (const k of newKeys) pipeline.get(k);
          const scanResults = await pipeline.exec();
          if (scanResults) {
            for (const r of scanResults) {
              if (!r || r[0] || !r[1]) continue;
              const record = this.parseRecord(r[1] as string);
              if (
                record.userId === userId &&
                record.status === SessionStatus.ROTATED
              ) {
                // WHY: ROTATED sessions with expired absolute timeout are stale —
                // the grace period is moot if the session already expired.
                if (record.expiresAt.getTime() <= now) continue;
                live.push(record);
              }
            }
          }
        }
      }

      // WHY: Prevent indefinite hangs on slow Redis instances.
      if (Date.now() - scanStart > SCAN_TIMEOUT_MS) break;
      if (scanned > SCAN_MAX_KEYS) break;
    } while (cursorVal !== "0");

    return live;
  }

  async findAllForUser(
    userId: string,
    params?: SessionListParams,
  ): Promise<SessionListResult> {
    const limit = Math.min(Math.max(params?.limit || 20, 1), 100);
    const status = params?.status;
    const cursor = params?.cursor;
    const userKey = this.key("idx:user", userId);
    const now = Date.now();

    // Active sessions are indexed in the sorted set with scores = expiresAt timestamp.
    // WHY: Fetch ALL entries then sort in memory by createdAt descending. The sorted set
    // is ordered by expiresAt (score), but clients expect newest-first (createdAt).
    // Sessions per user are bounded by maxSessions config (small), so O(N) is acceptable.
    if (!status || status === SessionStatus.ACTIVE) {
      // Purge expired entries first
      await this.redis.zremrangebyscore(userKey, "-inf", now);

      // Fetch all active entries from sorted set
      const entries = await this.redis.zrange(userKey, 0, -1);
      if (entries.length === 0) {
        return {
          sessions: [],
          total: 0,
          totalIsApproximate: false,
          nextCursor: null,
        };
      }

      // Hydrate all session records
      const sessions: SessionRecord[] = [];
      const pipeline = this.redis.pipeline();
      for (const entry of entries) {
        const [id] = entry.split(":");
        pipeline.get(this.key("sess", id));
      }
      const results = await pipeline.exec();

      if (results) {
        for (const result of results) {
          if (!result || result[0] || !result[1]) continue;
          sessions.push(this.parseRecord(result[1] as string));
        }
      }

      // Sort by createdAt descending to match Memory adapter's sort order
      sessions.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

      const total = sessions.length;

      // Cursor-based pagination on the sorted-in-memory array
      let startIndex = 0;
      if (cursor) {
        const cursorIndex = sessions.findIndex((s) => s.id === cursor);
        if (cursorIndex < 0) {
          // WHY: Cursor not found means the session was deleted between pages.
          // Returning empty page is safer than restarting from beginning.
          return {
            sessions: [],
            total,
            totalIsApproximate: false,
            nextCursor: null,
          };
        }
        startIndex = cursorIndex + 1;
      }

      const page = sessions.slice(startIndex, startIndex + limit);
      const nextCursor =
        startIndex + limit < total ? page[page.length - 1]?.id || null : null;

      return { sessions: page, total, totalIsApproximate: false, nextCursor };
    }

    // For non-active statuses, scan session keys and filter in memory.
    // This is O(N) but only used for revoked/expired queries (audit use).
    const pattern = this.key("sess", "*");
    let cursorVal: string | undefined;
    const found: SessionRecord[] = [];
    let scanned = 0;
    const SCAN_BATCH = 100;
    const SCAN_TIMEOUT_MS = 5000;
    const scanStart = Date.now();
    let scanTruncated = false;

    do {
      const result = await this.redis.scan(
        cursorVal === undefined ? "0" : cursorVal,
        "MATCH",
        pattern,
        "COUNT",
        SCAN_BATCH,
      );
      cursorVal = result[0];
      const keys = result[1];
      scanned += keys.length;

      if (keys.length > 0) {
        const pipeline = this.redis.pipeline();
        for (const k of keys) pipeline.get(k);
        const scanResults = await pipeline.exec();
        if (scanResults) {
          for (const r of scanResults) {
            if (!r || r[0] || !r[1]) continue;
            const record = this.parseRecord(r[1] as string);
            if (record.userId !== userId) continue;
            if (record.status !== status) continue;
            found.push(record);
          }
        }
      }

      // WHY: Prevent indefinite hangs on slow Redis instances.
      // OWASP A05 — every IO operation must have a timeout boundary.
      if (Date.now() - scanStart > SCAN_TIMEOUT_MS) {
        scanTruncated = true;
        break;
      }

      // Safety valve: cap scan iterations to prevent runaway
      if (scanned > 10000) {
        scanTruncated = true;
        break;
      }
    } while (cursorVal !== "0" && found.length < limit + 1);

    // Sort by createdAt descending
    found.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

    // WHY: total = found.length (what was actually found within the scan window).
    // If SCAN hit the 10K key cap or 5s timeout, this total is APPROXIMATE.
    const total = found.length;

    let startIndex = 0;
    if (cursor) {
      const cursorIndex = found.findIndex((s) => s.id === cursor);
      if (cursorIndex < 0) {
        return {
          sessions: [],
          total,
          totalIsApproximate: true,
          nextCursor: null,
        };
      }
      startIndex = cursorIndex + 1;
    }

    const page = found.slice(startIndex, startIndex + limit);
    const nextCursor =
      startIndex + limit < total ? page[page.length - 1]?.id || null : null;

    return {
      sessions: page,
      total,
      totalIsApproximate: scanTruncated,
      nextCursor,
    };
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

  async acquireLock(key: string, ttlMs: number): Promise<boolean> {
    const res = await this.redis.set(key, "locked", "PX", ttlMs, "NX");
    return res === "OK";
  }

  async releaseLock(key: string): Promise<void> {
    await this.redis.del(key);
  }

  async isLocked(key: string): Promise<boolean> {
    const exists = await this.redis.exists(key);
    return exists === 1;
  }
}
