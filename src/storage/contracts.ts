import { SessionRecord } from "../types";

/**
 * SessionStoreAdapter — Uniform interface for all session storage backends.
 */
export interface SessionStoreAdapter {
  /**
   * Persist a new session record.
   * @param record The session to create
   * @param maxSessions Optional limit to enforce atomically during creation
   */
  create(record: SessionRecord, maxSessions?: number): Promise<void>;

  /**
   * Retrieve a session by its unique ID.
   */
  findById(id: string): Promise<SessionRecord | null>;

  /**
   * Retrieve a session by its token hash.
   */
  findByTokenHash(tokenHash: string): Promise<SessionRecord | null>;

  /**
   * Update specific fields of an existing session.
   */
  update(id: string, updates: Partial<SessionRecord>): Promise<void>;

  /**
   * Permanently remove a session record.
   */
  delete(id: string): Promise<void>;

  /**
   * Revoke/Delete all sessions belonging to a specific user.
   */
  deleteAllForUser(userId: string): Promise<void>;

  /**
   * Count active sessions for a user (used for session limits).
   */
  countActiveForUser(userId: string): Promise<number>;
}
