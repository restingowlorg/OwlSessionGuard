import { SessionStatus, SessionReasonCode } from "../types";

export interface StateTransition {
  from: SessionStatus;
  to: SessionStatus;
  reason: SessionReasonCode;
}

/**
 * SessionStateMachine — Enforces valid state transitions and lifecycle rules.
 */
export class SessionStateMachine {
  /**
   * Validates if a transition from currentStatus to nextStatus is allowed.
   */
  public static isValidTransition(
    currentStatus: SessionStatus,
    nextStatus: SessionStatus,
  ): boolean {
    const validTransitions: Record<SessionStatus, SessionStatus[]> = {
      [SessionStatus.ACTIVE]: [
        SessionStatus.ROTATED,
        SessionStatus.REVOKED,
        SessionStatus.EXPIRED,
      ],
      [SessionStatus.ROTATED]: [SessionStatus.REVOKED, SessionStatus.EXPIRED],
      [SessionStatus.REVOKED]: [], // Terminal state
      [SessionStatus.EXPIRED]: [], // Terminal state
    };

    return validTransitions[currentStatus]?.includes(nextStatus) ?? false;
  }

  /**
   * Checks if the current state allows session usage.
   * Note: ROTATED sessions might still be usable during a grace period.
   */
  public static isUsable(
    status: SessionStatus,
    isWithinGracePeriod = false,
  ): boolean {
    if (status === SessionStatus.ACTIVE) return true;
    if (status === SessionStatus.ROTATED && isWithinGracePeriod) return true;
    return false;
  }

  /**
   * Determines if a session should be considered expired based on timestamps.
   */
  public static checkExpiration(
    now: Date,
    expiresAt: Date,
    idleExpiresAt: Date,
  ): { isExpired: boolean; reason?: SessionReasonCode } {
    if (now >= expiresAt) {
      return { isExpired: true, reason: SessionReasonCode.ABSOLUTE_TIMEOUT };
    }
    if (now >= idleExpiresAt) {
      return { isExpired: true, reason: SessionReasonCode.IDLE_TIMEOUT };
    }
    return { isExpired: false };
  }

  /**
   * Gets the next status based on an action or reason.
   */
  public static getNextStatus(
    currentStatus: SessionStatus,
    reason: SessionReasonCode,
  ): SessionStatus {
    if (
      reason === SessionReasonCode.ROTATION &&
      currentStatus === SessionStatus.ACTIVE
    ) {
      return SessionStatus.ROTATED;
    }

    if (
      reason === SessionReasonCode.IDLE_TIMEOUT ||
      reason === SessionReasonCode.ABSOLUTE_TIMEOUT ||
      reason === SessionReasonCode.ROTATION_GRACE_EXPIRED
    ) {
      return SessionStatus.EXPIRED;
    }

    // Default to REVOKED for everything else (manual logout, security violations, etc.)
    return SessionStatus.REVOKED;
  }
}
