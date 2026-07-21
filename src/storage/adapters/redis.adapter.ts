import Redis from "ioredis";
import { SessionStoreAdapter } from "../contracts";
import {
  SessionRecord,
  SessionStatus,
  SessionReasonCode,
  AdapterListParams,
  SessionListResult,
  SessionLimits,
} from "../../types";
import { RedisStoreOptions } from "../../interfaces";

/**
 * RedisStoreAdapter — The "State Machine" Implementation.
 *
 * ATOMIC STATE TRANSITIONS:
 * - owlSessionGuardRotateSession: Atomic 1-to-1 session replacement.
 * - owlSessionGuardUpdateSession: Atomic check-and-update (prevents Zombie Validation).
 */
export class RedisStoreAdapter implements SessionStoreAdapter {
  private redis: Redis;
  private prefix: string;
  private ttlBuffer: number;
  private batchSize: number;
  private maxAbsTimeout: number;

  constructor(redis: Redis, options: RedisStoreOptions = {}) {
    this.redis = redis;
    this.prefix = options.keyPrefix || "owlsessionguard:";
    this.ttlBuffer = options.ttlBufferSeconds || 0;
    this.batchSize = options.batchSize || 500;
    this.maxAbsTimeout = options.maxAbsoluteTimeoutSeconds || 2592000;

    this.registerLuaCommands();
  }

  private registerLuaCommands() {
    this.redis.defineCommand("owlSessionGuardCreateSession", {
      numberOfKeys: 4, // [userKey, sessKey, tokenKey, rolePrefix]
      lua: `
        local userKey = KEYS[1]
        local sessKey = KEYS[2]
        local tokenKey = KEYS[3]
        local rolePrefix = KEYS[4]
        local maxSessions = tonumber(ARGV[1])
        local recordJson = ARGV[2]
        local recordId = ARGV[3]
        local tokenHash = ARGV[4]
        local ttl = tonumber(ARGV[5])
        local score = tonumber(ARGV[6])
        local userIndexTtl = tonumber(ARGV[7])
        local status = ARGV[8]
        local rolesJson = ARGV[9]
        local roleLimitsJson = ARGV[10]
        
        local time = redis.call('TIME')
        local now = (tonumber(time[1]) * 1000) + math.floor(tonumber(time[2]) / 1000)
        
        -- Purge expired entries
        redis.call('ZREMRANGEBYSCORE', userKey, '-inf', now)
        
        -- Global limit check
        if maxSessions > 0 and status == 'active' then
            local count = redis.call('ZCOUNT', userKey, now, '+inf')
            if count >= maxSessions then
                return redis.error_reply("ERR_SESSION_LIMIT_REACHED")
            end
        end
        
        -- Role-specific limit check
        local roles = cjson.decode(rolesJson)
        local roleLimits = cjson.decode(roleLimitsJson)
        if status == 'active' then
            for _, role in ipairs(roles) do
                local roleLimit = roleLimits[role]
                if roleLimit and roleLimit > 0 then
                    local roleKey = rolePrefix .. role
                    redis.call('ZREMRANGEBYSCORE', roleKey, '-inf', now)
                    local roleCount = redis.call('ZCOUNT', roleKey, now, '+inf')
                    if roleCount >= roleLimit then
                        return redis.error_reply("ERR_SESSION_LIMIT_REACHED")
                    end
                end
            end
        end
        
        -- Persist session and indices
        local setOk = redis.call('SET', sessKey, recordJson, 'EX', ttl, 'NX')
        if not setOk then
            return redis.error_reply("ERR_SESSION_ALREADY_EXISTS")
        end
        
        redis.call('SET', tokenKey, recordId, 'EX', ttl)
        if status == 'active' then
            redis.call('ZADD', userKey, score, recordId .. ":" .. tokenHash)
            redis.call('EXPIRE', userKey, userIndexTtl)
            -- Index into role-specific sorted sets
            for _, role in ipairs(roles) do
                local roleKey = rolePrefix .. role
                redis.call('ZADD', roleKey, score, recordId .. ":" .. tokenHash)
                redis.call('EXPIRE', roleKey, userIndexTtl)
            end
        end
        return 1
      `,
    });

    /**
     * owlSessionGuardRotateSession:
     * 1. Check if OLD session is active (read once, atomically, inside Lua).
     * 2. Set OLD to rotated.
     * 3. Create NEW session and indices.
     * ARGV[9] = oldTokenHash, ARGV[10] = oldId (passed from TS to avoid pre-fetch round-trip)
     */
    this.redis.defineCommand("owlSessionGuardRotateSession", {
      numberOfKeys: 6, // [oldSessKey, oldTokenKey, userKey, newSessKey, newTokenKey, rolePrefix]
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
            local rolesJson = ARGV[11]
            local roleLimitsJson = ARGV[12]
            local oldRolesJson = ARGV[13]
            
            -- 4. Calculate the current timestamp in milliseconds
            local time = redis.call('TIME')
            local now = (tonumber(time[1]) * 1000) + math.floor(tonumber(time[2]) / 1000)
            
            -- 5. Purge expired sessions
            redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now)
            
            -- 6. Global limit check (1-to-1 replacement: use strict gt)
            if maxSessions > 0 then
                local count = redis.call('ZCOUNT', KEYS[3], now, '+inf')
                if count > maxSessions then
                    return redis.error_reply("ERR_SESSION_LIMIT_REACHED")
                end
            end
            
            -- 7. Role-specific limit check with per-role comparator selection
            -- WHY: Roles in BOTH old and new use ">" (1-to-1 replacement).
            --       Roles ONLY in new use ">=" (net increase, old session doesn't count).
            local roles = cjson.decode(rolesJson)
            local roleLimits = cjson.decode(roleLimitsJson)
            local oldRoles = cjson.decode(oldRolesJson)
            local oldRolesSet = {}
            for _, r in ipairs(oldRoles) do oldRolesSet[r] = true end
            local rolePrefix = KEYS[6]
            for _, role in ipairs(roles) do
                local roleLimit = roleLimits[role]
                if roleLimit and roleLimit > 0 then
                    local roleKey = rolePrefix .. role
                    redis.call('ZREMRANGEBYSCORE', roleKey, '-inf', now)
                    local roleCount = redis.call('ZCOUNT', roleKey, now, '+inf')
                    -- Per-role comparator: old session has this role → ">" (replacement)
                    -- old session doesn't have this role → ">=" (net increase)
                    if oldRolesSet[role] then
                        if roleCount > roleLimit then
                            return redis.error_reply("ERR_SESSION_LIMIT_REACHED")
                        end
                    else
                        if roleCount >= roleLimit then
                            return redis.error_reply("ERR_SESSION_LIMIT_REACHED")
                        end
                    end
                end
            end
            
            -- 8. Update the old session status to 'rotated' and update its token index
            redis.call('SET', KEYS[1], oldUpdateJson, 'EX', ttl)
            redis.call('EXPIRE', KEYS[2], ttl)
            redis.call('ZREM', KEYS[3], oldId .. ":" .. oldTokenHash)
            
            -- Remove from role indices (reuse already-decoded record)
            if record.roles then
                for _, role in ipairs(record.roles) do
                    local roleKey = rolePrefix .. role
                    redis.call('ZREM', roleKey, oldId .. ":" .. oldTokenHash)
                end
            end
            
            -- 9. Persist the new active session and index it under the user's active set
            redis.call('SET', KEYS[4], newRecordJson, 'EX', ttl)
            redis.call('SET', KEYS[5], newId, 'EX', ttl)
            redis.call('ZADD', KEYS[3], score, newId .. ":" .. newTokenHash)
            redis.call('EXPIRE', KEYS[3], userIndexTtl)
            
            -- Index into role-specific sorted sets
            for _, role in ipairs(roles) do
                local roleKey = rolePrefix .. role
                redis.call('ZADD', roleKey, score, newId .. ":" .. newTokenHash)
                redis.call('EXPIRE', roleKey, userIndexTtl)
            end
            
            return 1
        `,
    });

    this.redis.defineCommand("owlSessionGuardUpdateSession", {
      numberOfKeys: 3, // [sessKey, userKey, rolePrefix]
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
        local roles = cjson.decode(ARGV[6])
        local roleLimits = cjson.decode(ARGV[7])
        local userIndexTtl = tonumber(ARGV[8])
        local rolePrefix = KEYS[3]
        
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
            
            -- Role-specific limit check when becoming active
            if oldStatus ~= 'active' then
                for _, role in ipairs(roles) do
                    local roleLimit = roleLimits[role]
                    if roleLimit and roleLimit > 0 then
                        local roleKey = rolePrefix .. role
                        redis.call('ZREMRANGEBYSCORE', roleKey, '-inf', now)
                        local roleCount = redis.call('ZCOUNT', roleKey, now, '+inf')
                        if roleCount >= roleLimit then
                            return redis.error_reply("ERR_SESSION_LIMIT_REACHED")
                        end
                    end
                end
            end
            
            -- If token hash has rotated, remove old token entry from active list
            if oldTokenHash ~= newTokenHash then
                redis.call('ZREM', KEYS[2], record.id .. ":" .. oldTokenHash)
            end
            
            -- Add new token entry to active list and renew key expiry
            redis.call('ZADD', KEYS[2], newScore, record.id .. ":" .. newTokenHash)
            redis.call('EXPIRE', KEYS[2], userIndexTtl)
            
            -- Update role indices
            for _, role in ipairs(roles) do
                local roleKey = rolePrefix .. role
                if oldTokenHash ~= newTokenHash then
                    redis.call('ZREM', roleKey, record.id .. ":" .. oldTokenHash)
                end
                redis.call('ZADD', roleKey, newScore, record.id .. ":" .. newTokenHash)
                redis.call('EXPIRE', roleKey, userIndexTtl)
            end
        else
            -- If session has been deactivated (revoked/expired), remove token entries from active list
            redis.call('ZREM', KEYS[2], record.id .. ":" .. oldTokenHash)
            redis.call('ZREM', KEYS[2], record.id .. ":" .. newTokenHash)
            
            -- Remove from role indices
            for _, role in ipairs(roles) do
                local roleKey = rolePrefix .. role
                redis.call('ZREM', roleKey, record.id .. ":" .. oldTokenHash)
                redis.call('ZREM', roleKey, record.id .. ":" .. newTokenHash)
            end
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

    this.redis.defineCommand("owlSessionGuardDeleteSession", {
      numberOfKeys: 3, // [sessKey, userKey, rolePrefix]
      lua: `
        local data = redis.call('GET', KEYS[1])
        if not data then return 0 end
        
        local record = cjson.decode(data)
        redis.call('UNLINK', KEYS[1])
        redis.call('UNLINK', ARGV[1] .. record.tokenHash)
        redis.call('ZREM', KEYS[2], record.id .. ":" .. record.tokenHash)
        
        -- Remove from role indices
        local rolePrefix = KEYS[3]
        if record.roles then
            for _, role in ipairs(record.roles) do
                local roleKey = rolePrefix .. role
                redis.call('ZREM', roleKey, record.id .. ":" .. record.tokenHash)
            end
        end
        
        return 1
      `,
    });
  }

  private key(type: string, id: string): string {
    return `${this.prefix}${type}:${id}`;
  }

  async create(record: SessionRecord, limits?: SessionLimits): Promise<void> {
    const ttl = this.calculateTTL(record.expiresAt);
    if (ttl <= 0) return;

    const maxSessions = limits?.maxSessionsPerUser || 0;
    const rolesJson = JSON.stringify(record.roles || []);
    const roleLimitsJson = JSON.stringify(limits?.maxSessionsPerRole || {});

    try {
      // @ts-expect-error - custom command
      await this.redis.owlSessionGuardCreateSession(
        this.key("idx:user", record.userId),
        this.key("sess", record.id),
        this.key("idx:token", record.tokenHash),
        this.key("idx:role", record.userId) + ":",
        maxSessions,
        JSON.stringify(record),
        record.id,
        record.tokenHash,
        ttl,
        record.expiresAt.getTime(),
        this.maxAbsTimeout,
        record.status,
        rolesJson,
        roleLimitsJson,
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
    limits?: SessionLimits,
    oldRoles?: string[],
  ): Promise<void> {
    const oldRecord = await this.findById(oldId);
    if (!oldRecord) throw new Error("SESSION_NOT_FOUND");

    const ttl = this.calculateTTL(newRecord.expiresAt);
    const mergedOldJson = JSON.stringify({ ...oldRecord, ...oldUpdates });
    const maxSessions = limits?.maxSessionsPerUser || 0;
    const rolesJson = JSON.stringify(newRecord.roles || []);
    const roleLimitsJson = JSON.stringify(limits?.maxSessionsPerRole || {});
    const oldRolesJson = JSON.stringify(oldRoles || oldRecord.roles || []);

    try {
      // @ts-expect-error - custom command
      await this.redis.owlSessionGuardRotateSession(
        this.key("sess", oldId),
        this.key("idx:token", oldRecord.tokenHash),
        this.key("idx:user", oldRecord.userId),
        this.key("sess", newRecord.id),
        this.key("idx:token", newRecord.tokenHash),
        this.key("idx:role", oldRecord.userId) + ":",
        maxSessions,
        mergedOldJson,
        JSON.stringify(newRecord),
        newRecord.id,
        newRecord.tokenHash,
        ttl,
        newRecord.expiresAt.getTime(),
        this.maxAbsTimeout,
        oldRecord.tokenHash,
        oldId,
        rolesJson,
        roleLimitsJson,
        oldRolesJson,
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
    limits?: SessionLimits,
  ): Promise<void> {
    const record = await this.findById(id);
    if (!record) return;

    const newExpiresAt = updates.expiresAt || record.expiresAt;
    const ttl = this.calculateTTL(newExpiresAt);
    const maxSessions = limits?.maxSessionsPerUser || 0;
    const rolesJson = JSON.stringify(record.roles || []);
    const roleLimitsJson = JSON.stringify(limits?.maxSessionsPerRole || {});

    try {
      // @ts-expect-error - custom command
      await this.redis.owlSessionGuardUpdateSession(
        this.key("sess", id),
        this.key("idx:user", record.userId),
        this.key("idx:role", record.userId) + ":",
        JSON.stringify(updates),
        ttl,
        new Date(newExpiresAt).getTime(),
        this.prefix + "idx:token:",
        maxSessions,
        rolesJson,
        roleLimitsJson,
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
    await this.redis.owlSessionGuardDeleteSession(
      this.key("sess", id),
      this.key("idx:user", record.userId),
      this.key("idx:role", record.userId) + ":",
      this.prefix + "idx:token:",
    );
  }

  async deleteAllForUser(userId: string): Promise<void> {
    const userKey = this.key("idx:user", userId);
    const rolePrefix = this.key("idx:role", userId) + ":";
    let entries: string[];
    do {
      entries = await this.redis.zrange(userKey, 0, this.batchSize - 1);
      if (entries.length === 0) break;

      // Read sessions to get role info for cleanup
      const readPipeline = this.redis.pipeline();
      for (const entry of entries) {
        const [id] = entry.split(":");
        readPipeline.get(this.key("sess", id));
      }
      const results = await readPipeline.exec();

      const deletePipeline = this.redis.pipeline();
      for (let i = 0; i < entries.length; i++) {
        const [id, tokenHash] = entries[i].split(":");
        deletePipeline.unlink(this.key("sess", id));
        if (tokenHash) {
          deletePipeline.unlink(this.key("idx:token", tokenHash));
        }
        deletePipeline.zrem(userKey, entries[i]);

        // Clean up role indices
        if (results && results[i] && !results[i]![0] && results[i]![1]) {
          const record = this.parseRecord(results[i]![1] as string);
          if (record.roles) {
            for (const role of record.roles) {
              deletePipeline.zrem(rolePrefix + role, entries[i]);
            }
          }
        }
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
    const rolePrefix = this.key("idx:role", userId) + ":";

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
        // Clean up role indices
        if (record.roles) {
          for (const role of record.roles) {
            writePipeline.zrem(
              rolePrefix + role,
              `${record.id}:${record.tokenHash}`,
            );
          }
        }
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
    params?: AdapterListParams,
  ): Promise<SessionListResult> {
    const status = params?.status;
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
          const record = this.parseRecord(result[1] as string);
          if (record.status === SessionStatus.ACTIVE) {
            if (
              record.expiresAt.getTime() <= now ||
              record.idleExpiresAt.getTime() <= now
            )
              continue;
          }
          sessions.push(record);
        }
      }

      // Sort by createdAt descending to match Memory adapter's sort order
      sessions.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

      return {
        sessions,
        total: sessions.length,
        totalIsApproximate: false,
        nextCursor: null,
      };
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
    } while (cursorVal !== "0");

    // Sort by createdAt descending
    found.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

    // WHY: total = found.length (what was actually found within the scan window).
    // If SCAN hit the 10K key cap or 5s timeout, this total is APPROXIMATE.
    const total = found.length;

    return {
      sessions: found,
      total,
      totalIsApproximate: scanTruncated,
      nextCursor: null,
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
