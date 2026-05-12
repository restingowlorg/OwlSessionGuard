import { SessionStoreAdapter } from "../contracts";
import { SessionRecord, SessionStatus } from "../../types";

/**
 * MemoryStoreAdapter — Simple in-memory storage for development and testing.
 * Note: Does not support horizontal scaling.
 */
export class MemoryStoreAdapter implements SessionStoreAdapter {
  private sessions = new Map<string, SessionRecord>();

  async create(record: SessionRecord, maxSessions?: number): Promise<void> {
    if (maxSessions && maxSessions > 0) {
      const activeCount = await this.countActiveForUser(record.userId);
      if (activeCount >= maxSessions) {
        throw new Error("SESSION_LIMIT_REACHED");
      }
    }
    this.sessions.set(record.id, { ...record });
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

  async update(id: string, updates: Partial<SessionRecord>): Promise<void> {
    const session = this.sessions.get(id);
    if (session) {
      this.sessions.set(id, { ...session, ...updates });
    }
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
}
