import { SessionStoreAdapter } from "../contracts";
import {
  SessionRecord,
  SessionStatus,
  SessionReasonCode,
  SessionListParams,
  SessionListResult,
  SessionLimits,
} from "../../types";

/**
 * MemoryStoreAdapter — Simple in-memory storage for development and testing.
 * Note: Does not support horizontal scaling.
 */
export class MemoryStoreAdapter implements SessionStoreAdapter {
  private sessions = new Map<string, SessionRecord>();
  private locks = new Map<string, Date>();

  async create(record: SessionRecord, limits?: SessionLimits): Promise<void> {
    if (limits) {
      this.checkLimits(record.userId, limits, record.roles, ">=");
    }
    this.sessions.set(record.id, { ...record });
  }

  async rotate(
    oldId: string,
    newRecord: SessionRecord,
    oldUpdates: Partial<SessionRecord>,
    limits?: SessionLimits,
    oldRoles?: string[],
  ): Promise<void> {
    const oldRecord = this.sessions.get(oldId);
    if (!oldRecord) throw new Error("SESSION_NOT_FOUND");
    if (oldRecord.status !== SessionStatus.ACTIVE)
      throw new Error("SESSION_NOT_ACTIVE");

    // Atomic limit check for the NEW session
    // WHY: Per-role comparator selection:
    //   - Roles in BOTH old and new: ">" (1-to-1 replacement, old session will be removed)
    //   - Roles ONLY in new: ">=" (net increase, old session doesn't count against new role)
    if (limits) {
      this.checkLimits(
        oldRecord.userId,
        limits,
        newRecord.roles,
        ">",
        oldRoles || oldRecord.roles,
      );
    }

    this.sessions.set(oldId, { ...oldRecord, ...oldUpdates });
    this.sessions.set(newRecord.id, { ...newRecord });
  }

  async findById(id: string): Promise<SessionRecord | null> {
    const session = this.sessions.get(id);
    return session ? { ...session } : null;
  }

  async findByTokenHash(tokenHash: string): Promise<SessionRecord | null> {
    for (const session of this.sessions.values()) {
      if (session.tokenHash === tokenHash) {
        return { ...session };
      }
    }
    return null;
  }

  async update(
    id: string,
    updates: Partial<SessionRecord>,
    limits?: SessionLimits,
  ): Promise<void> {
    const record = this.sessions.get(id);
    if (!record) return;

    const newRecord = { ...record, ...updates };

    // Enforce limit if session is becoming active
    if (
      newRecord.status === SessionStatus.ACTIVE &&
      record.status !== SessionStatus.ACTIVE
    ) {
      if (limits) {
        this.checkLimits(record.userId, limits, newRecord.roles, ">=");
      }
    }

    this.sessions.set(id, newRecord);
  }

  async delete(id: string): Promise<void> {
    this.sessions.delete(id);
  }

  async deleteAllForUser(userId: string): Promise<void> {
    for (const [id, session] of this.sessions.entries()) {
      if (session.userId === userId) {
        this.sessions.delete(id);
      }
    }
  }

  async revokeAllForUser(
    userId: string,
    reason: SessionReasonCode,
    revokedAt: Date,
  ): Promise<string[]> {
    const affected: string[] = [];
    for (const [id, session] of this.sessions.entries()) {
      if (
        session.userId === userId &&
        session.status !== SessionStatus.REVOKED
      ) {
        this.sessions.set(id, {
          ...session,
          status: SessionStatus.REVOKED,
          revokedAt,
          revocationReason: reason,
        });
        affected.push(id);
      }
    }
    return affected;
  }

  /**
   * WHY: Returns only ACTIVE + ROTATED sessions. Excludes REVOKED and EXPIRED
   * to avoid loading audit-piled revoked sessions into memory.
   * No pagination — bounded by maxSessionsPerUser (typically 5-10).
   */
  async findLiveSessionsForUser(userId: string): Promise<SessionRecord[]> {
    const now = new Date();
    const live: SessionRecord[] = [];
    for (const session of this.sessions.values()) {
      if (session.userId !== userId) continue;
      if (session.status === SessionStatus.REVOKED) continue;
      if (session.status === SessionStatus.EXPIRED) continue;
      // WHY: Both ACTIVE and ROTATED sessions must be checked for expiration.
      // ACTIVE: expired absolute/idle timeouts are stale.
      // ROTATED: expired absolute timeout means the grace period is moot.
      if (session.expiresAt <= now || session.idleExpiresAt <= now) continue;
      live.push({ ...session });
    }
    return live;
  }

  /**
   * Check both global and per-role limits atomically.
   * WHY: Single enforcement path for create (>=), rotate (per-role), and
   * update operations.
   * @param op Default comparison operator — ">=" for create, ">" for rotation
   * @param oldRoles Roles of the old session during rotation — used for per-role
   *   comparator selection. Roles in BOTH old and new use ">" (1-to-1 replacement).
   *   Roles ONLY in new use ">=" (net increase).
   */
  private checkLimits(
    userId: string,
    limits: SessionLimits,
    roles: string[],
    op: ">=" | ">",
    oldRoles?: string[],
  ): void {
    const activeCount = this.countActiveForUserSync(userId);
    if (limits.maxSessionsPerUser > 0) {
      if (
        op === ">="
          ? activeCount >= limits.maxSessionsPerUser
          : activeCount > limits.maxSessionsPerUser
      ) {
        throw new Error("SESSION_LIMIT_REACHED");
      }
    }
    if (limits.maxSessionsPerRole) {
      for (const role of roles) {
        const roleLimit = limits.maxSessionsPerRole[role];
        if (roleLimit !== undefined) {
          const roleCount = this.countActiveForUserByRoleSync(userId, role);
          // Per-role comparator: if old session has this role, use ">" (1-to-1 replacement).
          // If old session doesn't have this role, use ">=" (net increase).
          const roleOp = oldRoles?.includes(role) ? ">" : ">=";
          if (
            roleOp === ">=" ? roleCount >= roleLimit : roleCount > roleLimit
          ) {
            throw new Error("SESSION_LIMIT_REACHED");
          }
        }
      }
    }
  }

  /**
   * Synchronous count of active sessions for a user.
   * WHY: Avoids async overhead in the memory adapter's enforceLimits path.
   */
  private countActiveForUserSync(userId: string): number {
    let count = 0;
    const now = new Date();
    for (const session of this.sessions.values()) {
      if (
        session.userId === userId &&
        session.status === SessionStatus.ACTIVE &&
        session.expiresAt > now &&
        session.idleExpiresAt > now
      ) {
        count++;
      }
    }
    return count;
  }

  /**
   * Count active sessions for a user that include a specific role.
   * WHY: Role-specific limits are independent counters — only sessions with
   * the matching role count against that role's limit.
   */
  private countActiveForUserByRoleSync(userId: string, role: string): number {
    let count = 0;
    const now = new Date();
    for (const session of this.sessions.values()) {
      if (
        session.userId === userId &&
        session.roles.includes(role) &&
        session.status === SessionStatus.ACTIVE &&
        session.expiresAt > now &&
        session.idleExpiresAt > now
      ) {
        count++;
      }
    }
    return count;
  }

  async countActiveForUser(userId: string): Promise<number> {
    let count = 0;
    const now = new Date();
    for (const session of this.sessions.values()) {
      if (
        session.userId === userId &&
        session.status === SessionStatus.ACTIVE &&
        session.expiresAt > now &&
        session.idleExpiresAt > now
      ) {
        count++;
      }
    }
    return count;
  }

  async findAllForUser(
    userId: string,
    params?: SessionListParams,
  ): Promise<SessionListResult> {
    const limit = Math.min(Math.max(params?.limit || 20, 1), 100);
    const status = params?.status;
    const cursor = params?.cursor;

    const allUserSessions: SessionRecord[] = [];
    const now = new Date();
    for (const session of this.sessions.values()) {
      if (session.userId !== userId) continue;
      if (status && session.status !== status) continue;
      // WHY: Expired sessions should not appear in active listings.
      // Consistent with countActiveForUser's expiration check.
      if (session.status === SessionStatus.ACTIVE) {
        if (session.expiresAt <= now || session.idleExpiresAt <= now) continue;
      }
      allUserSessions.push({ ...session });
    }

    // Sort by createdAt descending (most recent first)
    allUserSessions.sort(
      (a, b) => b.createdAt.getTime() - a.createdAt.getTime(),
    );

    const total = allUserSessions.length;

    // Find cursor position
    let startIndex = 0;
    if (cursor) {
      const cursorIndex = allUserSessions.findIndex((s) => s.id === cursor);
      if (cursorIndex < 0) {
        // WHY: Cursor not found means the session was deleted between pages.
        // Returning empty page is safer than restarting from beginning (silent duplicates).
        return {
          sessions: [],
          total,
          totalIsApproximate: false,
          nextCursor: null,
        };
      }
      startIndex = cursorIndex + 1;
    }

    const page = allUserSessions.slice(startIndex, startIndex + limit);
    const nextCursor =
      startIndex + limit < total ? page[page.length - 1]?.id || null : null;

    return { sessions: page, total, totalIsApproximate: false, nextCursor };
  }

  async acquireLock(key: string, ttlMs: number): Promise<boolean> {
    const now = new Date();
    const existingLock = this.locks.get(key);
    if (existingLock && existingLock > now) {
      return false; // Lock already held
    }
    this.locks.set(key, new Date(now.getTime() + ttlMs));
    return true;
  }

  async releaseLock(key: string): Promise<void> {
    this.locks.delete(key);
  }

  async isLocked(key: string): Promise<boolean> {
    const now = new Date();
    const existingLock = this.locks.get(key);
    if (existingLock && existingLock > now) {
      return true;
    }
    if (existingLock) {
      this.locks.delete(key); // Lazy cleanup of expired locks
    }
    return false;
  }
}
