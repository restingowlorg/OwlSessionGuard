import Redis from "ioredis-mock";
import { RedisStoreAdapter } from "../../src/storage/adapters/redis.adapter";
import { runAdapterContractTests } from "./adapter-contract.suite";

/**
 * RedisStoreAdapter Test Suite
 *
 * Uses ioredis-mock for high-speed testing with full polyfills for
 * the custom atomic Lua commands used in the production adapter.
 *
 * WHY: ioredis-mock pipelines don't reliably persist state, so polyfills
 * use sequential await calls instead of pipeline.exec().
 */
runAdapterContractTests(
  "RedisStoreAdapter",
  async () => {
    const redis = new Redis();
    const adapter = new RedisStoreAdapter(redis);

    /**
     * Polyfill: owlSessionGuardCreateSession
     * Atomic creation with native time sync and dual limit enforcement.
     */
    // @ts-expect-error - Custom Lua polyfill
    redis.owlSessionGuardCreateSession = async (
      userKey: string,
      sessKey: string,
      tokenKey: string,
      rolePrefix: string,
      maxSessions: number,
      recordJson: string,
      id: string,
      tokenHash: string,
      ttl: number,
      score: number,
      maxAbsTtl: number,
      status: string,
      rolesJson: string,
      roleLimitsJson: string,
    ) => {
      const now = Date.now();

      if (maxSessions > 0 && status === "active") {
        await redis.zremrangebyscore(userKey, "-inf", String(now));
        const count = await redis.zcount(userKey, String(now), "+inf");
        if (count >= maxSessions) {
          throw new Error("ERR_SESSION_LIMIT_REACHED");
        }
      }

      // Role-specific limit check
      const roles: string[] = JSON.parse(rolesJson);
      const roleLimits: Record<string, number> = JSON.parse(roleLimitsJson);
      if (status === "active") {
        for (const role of roles) {
          const roleLimit = roleLimits[role];
          if (roleLimit && roleLimit > 0) {
            const roleKey = rolePrefix + role;
            await redis.zremrangebyscore(roleKey, "-inf", String(now));
            const roleCount = await redis.zcount(roleKey, String(now), "+inf");
            if (roleCount >= roleLimit) {
              throw new Error("ERR_SESSION_LIMIT_REACHED");
            }
          }
        }
      }

      // SET ... NX simulation
      const exists = await redis.exists(sessKey);
      if (exists) throw new Error("ERR_SESSION_ALREADY_EXISTS");

      // WHY: Sequential awaits instead of pipeline — ioredis-mock pipelines
      // don't reliably persist state between awaits in the same test.
      await redis.set(sessKey, recordJson, "EX", ttl);
      await redis.set(tokenKey, id, "EX", ttl);
      if (status === "active") {
        await redis.zadd(userKey, String(score), `${id}:${tokenHash}`);
        await redis.expire(userKey, maxAbsTtl);
        // Index into role-specific sorted sets
        for (const role of roles) {
          const roleKey = rolePrefix + role;
          await redis.zadd(roleKey, String(score), `${id}:${tokenHash}`);
          await redis.expire(roleKey, maxAbsTtl);
        }
      }
      return 1;
    };

    /**
     * Polyfill: owlSessionGuardUpdateSession
     * Atomic update with native time sync, dual limit enforcement, and rotation guard.
     */
    // @ts-expect-error - Custom Lua polyfill
    redis.owlSessionGuardUpdateSession = async (
      sessKey: string,
      userKey: string,
      rolePrefix: string,
      updatesJson: string,
      ttl: number,
      score: number,
      tokenPrefix: string,
      maxSessions: number,
      rolesJson: string,
      roleLimitsJson: string,
      maxAbsTtl: number,
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
      const roles: string[] = updatedRecord.roles || [];

      const now = Date.now();

      if (status === "active") {
        await redis.zremrangebyscore(userKey, "-inf", String(now));

        if (oldStatus !== "active" && maxSessions > 0) {
          const count = await redis.zcount(userKey, String(now), "+inf");
          if (count >= maxSessions) {
            throw new Error("ERR_SESSION_LIMIT_REACHED");
          }
        }

        // Role-specific limit check when becoming active
        if (oldStatus !== "active") {
          const roleLimits: Record<string, number> = JSON.parse(roleLimitsJson);
          for (const role of roles) {
            const roleLimit = roleLimits[role];
            if (roleLimit && roleLimit > 0) {
              const roleKey = rolePrefix + role;
              await redis.zremrangebyscore(roleKey, "-inf", String(now));
              const roleCount = await redis.zcount(
                roleKey,
                String(now),
                "+inf",
              );
              if (roleCount >= roleLimit) {
                throw new Error("ERR_SESSION_LIMIT_REACHED");
              }
            }
          }
        }
      }

      await redis.set(sessKey, JSON.stringify(updatedRecord), "EX", ttl);

      if (oldTokenHash !== newTokenHash) {
        await redis.unlink(tokenPrefix + oldTokenHash);
      }
      await redis.set(tokenPrefix + newTokenHash, updatedRecord.id, "EX", ttl);

      if (status === "active") {
        if (oldTokenHash !== newTokenHash) {
          await redis.zrem(userKey, `${updatedRecord.id}:${oldTokenHash}`);
        }
        await redis.zadd(
          userKey,
          String(score),
          `${updatedRecord.id}:${newTokenHash}`,
        );
        await redis.expire(userKey, maxAbsTtl);

        // Update role indices
        for (const role of roles) {
          const roleKey = rolePrefix + role;
          if (oldTokenHash !== newTokenHash) {
            await redis.zrem(roleKey, `${updatedRecord.id}:${oldTokenHash}`);
          }
          await redis.zadd(
            roleKey,
            String(score),
            `${updatedRecord.id}:${newTokenHash}`,
          );
          await redis.expire(roleKey, maxAbsTtl);
        }
      } else {
        await redis.zrem(userKey, `${updatedRecord.id}:${oldTokenHash}`);
        await redis.zrem(userKey, `${updatedRecord.id}:${newTokenHash}`);

        // Remove from role indices
        for (const role of roles) {
          const roleKey = rolePrefix + role;
          await redis.zrem(roleKey, `${updatedRecord.id}:${oldTokenHash}`);
          await redis.zrem(roleKey, `${updatedRecord.id}:${newTokenHash}`);
        }
      }

      return 1;
    };

    /**
     * Polyfill: owlSessionGuardRotateSession
     * Atomic session rotation (1-to-1 replacement) with per-role limit enforcement.
     */
    // @ts-expect-error - Custom Lua polyfill
    redis.owlSessionGuardRotateSession = async (
      oldSessKey: string,
      oldTokenKey: string,
      userKey: string,
      newSessKey: string,
      newTokenKey: string,
      rolePrefix: string,
      maxSessions: number,
      oldUpdateJson: string,
      newRecordJson: string,
      newId: string,
      newTokenHash: string,
      ttl: number,
      score: number,
      maxAbsTtl: number,
      oldTokenHash: string,
      oldId: string,
      rolesJson: string,
      roleLimitsJson: string,
      oldRolesJson: string,
    ) => {
      const data = await redis.get(oldSessKey);
      if (!data) throw new Error("ERR_SESSION_NOT_FOUND");
      const record = JSON.parse(data);
      if (record.status !== "active") throw new Error("ERR_SESSION_NOT_ACTIVE");

      const now = Date.now();
      await redis.zremrangebyscore(userKey, "-inf", String(now));

      // Global limit check (1-to-1 replacement: use strict gt)
      if (maxSessions > 0) {
        const count = await redis.zcount(userKey, String(now), "+inf");
        if (count > maxSessions) throw new Error("ERR_SESSION_LIMIT_REACHED");
      }

      // Role-specific limit check with per-role comparator selection
      // WHY: Roles in BOTH old and new use ">" (1-to-1 replacement).
      //       Roles ONLY in new use ">=" (net increase, old session doesn't count).
      const roles: string[] = JSON.parse(rolesJson);
      const roleLimits: Record<string, number> = JSON.parse(roleLimitsJson);
      const oldRoles: string[] = JSON.parse(oldRolesJson);
      const oldRolesSet = new Set(oldRoles);
      for (const role of roles) {
        const roleLimit = roleLimits[role];
        if (roleLimit && roleLimit > 0) {
          const roleKey = rolePrefix + role;
          await redis.zremrangebyscore(roleKey, "-inf", String(now));
          const roleCount = await redis.zcount(roleKey, String(now), "+inf");
          // Per-role comparator: old session has this role → ">" (replacement)
          // old session doesn't have this role → ">=" (net increase)
          if (oldRolesSet.has(role)) {
            if (roleCount > roleLimit) {
              throw new Error("ERR_SESSION_LIMIT_REACHED");
            }
          } else {
            if (roleCount >= roleLimit) {
              throw new Error("ERR_SESSION_LIMIT_REACHED");
            }
          }
        }
      }

      // Update OLD
      await redis.set(oldSessKey, oldUpdateJson, "EX", ttl);
      await redis.unlink(oldTokenKey);
      await redis.zrem(userKey, `${record.id}:${record.tokenHash}`);

      // Remove from role indices
      if (record.roles) {
        for (const role of record.roles) {
          const roleKey = rolePrefix + role;
          await redis.zrem(roleKey, `${record.id}:${record.tokenHash}`);
        }
      }

      // Create NEW
      await redis.set(newSessKey, newRecordJson, "EX", ttl);
      await redis.set(newTokenKey, newId, "EX", ttl);
      await redis.zadd(userKey, String(score), `${newId}:${newTokenHash}`);
      await redis.expire(userKey, maxAbsTtl);

      // Index into role-specific sorted sets
      for (const role of roles) {
        const roleKey = rolePrefix + role;
        await redis.zadd(roleKey, String(score), `${newId}:${newTokenHash}`);
        await redis.expire(roleKey, maxAbsTtl);
      }

      return 1;
    };

    /**
     * Polyfill: owlSessionGuardDeleteSession
     * Atomic annihilation of record and indices including role cleanup.
     */
    // @ts-expect-error - Custom Lua polyfill
    redis.owlSessionGuardDeleteSession = async (
      sessKey: string,
      userKey: string,
      rolePrefix: string,
      tokenPrefix: string,
    ) => {
      const data = await redis.get(sessKey);
      if (!data) return 0;

      const record = JSON.parse(data);
      await redis.unlink(sessKey);
      await redis.unlink(tokenPrefix + record.tokenHash);
      await redis.zrem(userKey, `${record.id}:${record.tokenHash}`);

      // Clean up role indices
      if (record.roles) {
        for (const role of record.roles) {
          const roleKey = rolePrefix + role;
          await redis.zrem(roleKey, `${record.id}:${record.tokenHash}`);
        }
      }

      return 1;
    };

    return adapter;
  },
  async () => {
    // Cleanup: flush Redis between tests to prevent key collisions
    const redis = new Redis();
    await redis.flushdb();
    await redis.quit();
  },
);
