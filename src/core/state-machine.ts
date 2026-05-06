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
}
