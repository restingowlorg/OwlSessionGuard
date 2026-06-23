import {
  SessionRecord,
  SessionListParams,
  SessionListResult,
  SessionReasonCode,
  SessionLimits,
} from "../types";

/**
 * SessionStoreAdapter — Uniform interface for all session storage backends.
 */
export interface SessionStoreAdapter {
  /**
   * Persist a new session record.
   * @param record The session to create
   * @param limits Optional limits to enforce atomically during creation.
   *   The adapter checks BOTH the global user cap and per-role caps
   *   in a single atomic operation.
   */
  create(record: SessionRecord, limits?: SessionLimits): Promise<void>;

  /**
   * Atomic session rotation (1-to-1 replacement).
   * @param oldId The ID of the session being replaced
   * @param newRecord The new session record to create
   * @param oldUpdates Updates to apply to the old session (e.g. status = ROTATED)
   * @param limits Optional limits to enforce
   * @param oldRoles Roles of the session being replaced — used for per-role
   *   comparator selection. Roles in BOTH old and new use ">" (1-to-1 replacement).
   *   Roles ONLY in new use ">=" (net increase).
   */
  rotate(
    oldId: string,
    newRecord: SessionRecord,
    oldUpdates: Partial<SessionRecord>,
    limits?: SessionLimits,
    oldRoles?: string[],
  ): Promise<void>;

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
   * @param id The session ID
   * @param updates The fields to update
   * @param limits Optional limits to enforce if the session becomes active
   */
  update(
    id: string,
    updates: Partial<SessionRecord>,
    limits?: SessionLimits,
  ): Promise<void>;

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

  /**
   * List sessions for a user with optional status filter and pagination.
   * Returns raw SessionRecord[] — projection to SessionSnapshot happens in the service layer.
   */
  findAllForUser(
    userId: string,
    params?: SessionListParams,
  ): Promise<SessionListResult>;

  /**
   * Optional: Acquire a transient lock for concurrency control.
   */
  acquireLock?(key: string, ttlMs: number): Promise<boolean>;

  /**
   * Optional: Release a previously acquired concurrency lock.
   */
  releaseLock?(key: string): Promise<void>;

  /**
   * Optional: Check if a concurrency lock is currently active.
   */
  isLocked?(key: string): Promise<boolean>;

  /**
   * Optional: Retrieve all "live" (non-terminal) sessions for a user.
   * WHY: Returns only ACTIVE + ROTATED sessions. Excludes REVOKED and EXPIRED.
   * Used by SelectiveRevocationEngine to avoid loading audit-piled revoked sessions.
   * No pagination — bounded by maxSessionsPerUser config (typically 5-10).
   * Adapters that don't implement this fall back to findAllForUser() + filter.
   */
  findLiveSessionsForUser?(userId: string): Promise<SessionRecord[]>;

  /**
   * Optional: Soft-revoke all sessions for a user (status → REVOKED).
   * WHY: Atomic bulk soft-revoke preserves audit trail. Adapters that don't implement
   * this fall back to findAllForUser() + update() loop in SelectiveRevocationEngine.
   * @returns IDs of sessions that were soft-revoked (excludes already-revoked sessions).
   */
  revokeAllForUser?(
    userId: string,
    reason: SessionReasonCode,
    revokedAt: Date,
  ): Promise<string[]>;
}
