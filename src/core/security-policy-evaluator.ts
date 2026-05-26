import { SessionStateMachine } from "./state-machine";
import {
  SessionRecord,
  SessionStatus,
  SessionReasonCode,
  SessionLibraryConfig,
  SecurityEvaluationContext,
  SecurityEvaluationResult,
} from "../types";

/**
 * SecurityPolicyEvaluator — Enforces session security rules, context bindings,
 * immediate mutation blocks, and automatic reuse detection (ARD).
 */
export class SecurityPolicyEvaluator {
  private readonly hardCapMs = 50; // 50ms hard-capped concurrency window

  constructor(private readonly config: SessionLibraryConfig) {}

  /**
   * Evaluates all security policies for a session record against the current client context.
   */
  public evaluate(
    record: SessionRecord,
    context: SecurityEvaluationContext,
    now: Date = new Date(),
  ): SecurityEvaluationResult {
    // 1. Lifecycle Status check
    if (record.status === SessionStatus.REVOKED) {
      return {
        isValid: false,
        isWithinGracePeriod: false,
        actionRequired: "none",
        reason: record.revocationReason || SessionReasonCode.ADMIN_REVOKED,
        message: "Session has been revoked",
      };
    }

    if (record.status === SessionStatus.EXPIRED) {
      return {
        isValid: false,
        isWithinGracePeriod: false,
        actionRequired: "none",
        reason: record.revocationReason || SessionReasonCode.ABSOLUTE_TIMEOUT,
        message: "Session has expired",
      };
    }

    // 2. Timeout Validation
    const expiry = SessionStateMachine.checkExpiration(
      now,
      record.expiresAt,
      record.idleExpiresAt,
    );
    if (expiry.isExpired) {
      return {
        isValid: false,
        isWithinGracePeriod: false,
        actionRequired: "revoke",
        reason: expiry.reason || SessionReasonCode.ABSOLUTE_TIMEOUT,
        message: `Session timed out: ${expiry.reason}`,
      };
    }

    // 3. Session Rotation & Micro-Concurrency Validation
    if (record.status === SessionStatus.ROTATED) {
      // Step A: Idempotency Gate (Strict mutation block)
      const methodUpper = (context.method || "GET").toUpperCase();
      const isIdempotent =
        methodUpper === "GET" ||
        methodUpper === "HEAD" ||
        methodUpper === "OPTIONS";

      if (!isIdempotent) {
        return {
          isValid: false,
          isWithinGracePeriod: false,
          actionRequired: "revoke_tree", // Instant tree self-destruct for unsafe method reuse
          reason: SessionReasonCode.SECURITY_BREACH,
          message: `Suspicious session write mutation (${context.method}) on rotated token`,
        };
      }

      // Step B: Concurrency Window check
      if (record.revokedAt) {
        const elapsedMs = now.getTime() - new Date(record.revokedAt).getTime();

        if (elapsedMs >= 0 && elapsedMs <= this.hardCapMs) {
          return {
            isValid: true,
            isWithinGracePeriod: true,
            actionRequired: "none",
            reason: SessionReasonCode.ROTATION,
            message: `Legitimate concurrent read-only request permitted within ${elapsedMs}ms window`,
          };
        }
      }

      // Step C: If outside the 50ms concurrency window, flag as a replay breach (stolen token)
      return {
        isValid: false,
        isWithinGracePeriod: false,
        actionRequired: "revoke_tree", // Automatic Reuse Detection (ARD) cascading revocation
        reason: SessionReasonCode.SECURITY_BREACH,
        message: "Session token reuse detected outside concurrency window",
      };
    }

    // 4. IP Context Binding check
    const ipConfig = this.config.security.ipBinding;
    if (ipConfig !== "off") {
      if (record.metadata.ipAddress !== context.ipAddress) {
        if (ipConfig === "hard") {
          return {
            isValid: false,
            isWithinGracePeriod: false,
            actionRequired: "revoke",
            reason: SessionReasonCode.IP_MISMATCH,
            message: `IP mismatch in strict mode (Expected: ${record.metadata.ipAddress}, Actual: ${context.ipAddress})`,
          };
        } else if (ipConfig === "soft") {
          // Soft binding allows request but triggers event/warning
          return {
            isValid: true,
            isWithinGracePeriod: false,
            actionRequired: "none",
            reason: SessionReasonCode.IP_MISMATCH,
            message: `Soft IP mismatch logged (Expected: ${record.metadata.ipAddress}, Actual: ${context.ipAddress})`,
          };
        }
      }
    }

    // 5. Device/User-Agent Fingerprinting check
    const fpConfig = this.config.security.fingerprinting;
    if (fpConfig !== "off" && record.metadata.userAgent) {
      const userAgentMatch = record.metadata.userAgent === context.userAgent;
      if (!userAgentMatch) {
        if (fpConfig === "hard") {
          return {
            isValid: false,
            isWithinGracePeriod: false,
            actionRequired: "revoke",
            reason: SessionReasonCode.DEVICE_MISMATCH,
            message: `User-Agent mismatch/missing in strict mode (Expected: ${record.metadata.userAgent}, Actual: ${context.userAgent || "None"})`,
          };
        } else if (fpConfig === "soft") {
          return {
            isValid: true,
            isWithinGracePeriod: false,
            actionRequired: "none",
            reason: SessionReasonCode.DEVICE_MISMATCH,
            message: `Soft User-Agent mismatch/missing logged (Expected: ${record.metadata.userAgent}, Actual: ${context.userAgent || "None"})`,
          };
        }
      }
    }

    // Happy Path — Request is valid and active
    return {
      isValid: true,
      isWithinGracePeriod: false,
      actionRequired: "none",
    };
  }
}
