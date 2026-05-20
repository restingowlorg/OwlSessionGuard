import { SessionStoreAdapter } from "../contracts";
import { SessionRecord, SessionStatus } from "../../types";

/**
 * MemoryStoreAdapter — Simple in-memory storage for development and testing.
 * Note: Does not support horizontal scaling.
 */
export class MemoryStoreAdapter implements SessionStoreAdapter {
  private sessions = new Map<string, SessionRecord>();
  private locks = new Map<string, Date>();

  async create(record: SessionRecord, maxSessions?: number): Promise<void> {
    if (maxSessions && maxSessions > 0) {
      const activeCount = await this.countActiveForUser(record.userId);
      if (activeCount >= maxSessions) {
        throw new Error("SESSION_LIMIT_REACHED");
      }
    }
    this.sessions.set(record.id, { ...record });
  }

  async rotate(
    oldId: string,
    newRecord: SessionRecord,
    oldUpdates: Partial<SessionRecord>,
    maxSessions?: number,
  ): Promise<void> {
    const oldRecord = this.sessions.get(oldId);
    if (!oldRecord) throw new Error("SESSION_NOT_FOUND");
    if (oldRecord.status !== SessionStatus.ACTIVE)
      throw new Error("SESSION_NOT_ACTIVE");

    // Atomic limit check for the NEW session
    if (maxSessions && maxSessions > 0) {
      const activeCount = await this.countActiveForUser(oldRecord.userId);
      // Because this is a 1-to-1 replacement, we only fail if they are strictly OVER the limit.
      if (activeCount > maxSessions) {
        throw new Error("SESSION_LIMIT_REACHED");
      }
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
    maxSessions?: number,
  ): Promise<void> {
    const record = this.sessions.get(id);
    if (!record) return;

    const newRecord = { ...record, ...updates };

    // Enforce limit if session is becoming active
    if (
      newRecord.status === SessionStatus.ACTIVE &&
      record.status !== SessionStatus.ACTIVE
    ) {
      const activeCount = await this.countActiveForUser(record.userId);
      if (maxSessions && maxSessions > 0 && activeCount >= maxSessions) {
        throw new Error("SESSION_LIMIT_REACHED");
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
