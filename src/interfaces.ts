import {
  SessionOpResult,
  CreateSessionParams,
  ValidateSessionParams,
  RotateSessionParams,
  RevokeSessionParams,
  SessionRecord,
  SessionReasonCode,
  SessionSuccess,
} from "./types";

/**
 * ISessionEngine — The core framework-agnostic session handling logic.
 */
export interface ISessionEngine {
  /**
   * Create a new session for a successfully authenticated user.
   */
  createSession(params: CreateSessionParams): Promise<
    SessionOpResult<{
      token: string;
      record: SessionRecord;
    }>
  >;

  /**
   * Validate a session token and check security policies.
   */
  validateSession(
    params: ValidateSessionParams,
  ): Promise<SessionOpResult<SessionRecord>>;

  /**
   * Rotate a session token (e.g., on login or privilege change).
   */
  rotateSession(params: RotateSessionParams): Promise<
    SessionOpResult<{
      newToken: string;
      record: SessionRecord;
    }>
  >;

  /**
   * Revoke a specific session.
   */
  revokeSession(
    params: RevokeSessionParams,
  ): Promise<SessionOpResult<SessionSuccess>>;

  /**
   * Revoke all sessions for a specific user.
   */
  revokeAllSessionsForUser(
    userId: string,
    reason: SessionReasonCode,
  ): Promise<SessionOpResult<SessionSuccess>>;
}
