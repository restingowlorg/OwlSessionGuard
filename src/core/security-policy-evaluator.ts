import { SessionStateMachine } from "./state-machine";
import { constantTimeCompare, fastHash } from "../infra/crypto/crypto";
import {
  SessionRecord,
  SessionStatus,
  SessionReasonCode,
  SessionLibraryConfig,
  SecurityEvaluationContext,
  SecurityEvaluationResult,
  FALLBACK_FP_PREFIX,
} from "../types";

/**
 * SecurityPolicyEvaluator — Enforces session security rules, context bindings,
 * immediate mutation blocks, and automatic reuse detection (ARD).
 */
export class SecurityPolicyEvaluator {
  // WHY: Grace window derived from config.rotation.gracePeriodSeconds (safe max: 30s).
  // OWASP recommends immediate invalidation, but industry implementations (Okta, Auth0)
  // use short grace windows for legitimate concurrency. Defaults to 50ms for backward
  // compatibility with the original hard-coded micro-concurrency window.
  private readonly graceWindowMs: number;

  constructor(private readonly config: SessionLibraryConfig) {
    const graceSeconds = config.rotation?.gracePeriodSeconds;
    this.graceWindowMs = graceSeconds !== undefined ? graceSeconds * 1000 : 50;
  }

  /**
   * WHY: Truncated SHA-256 preserves debuggability (compare hashes) while preventing
   * info disclosure. Raw fingerprints must never leave the secure internal log boundary.
   */
  private static hashFingerprint(fp: string): string {
    return fastHash(fp).substring(0, 16);
  }

  /**
   * WHY: Last-octet masking hides the exact host while preserving subnet-level debugging.
   * Full IPs in error messages leak network topology to the response chain.
   */
  private static maskIp(ip: string): string {
    const parts = ip.split(".");
    if (parts.length === 4) {
      parts[3] = "x";
      return parts.join(".");
    }
    return ip;
  }

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
      // WHY: Skip grace check entirely when graceWindowMs <= 0. A consumer setting
      // gracePeriodSeconds: 0 expects zero grace — no old tokens valid, period.
      // Without this guard, elapsedMs === 0 (same millisecond) would pass.
      if (record.revokedAt && this.graceWindowMs > 0) {
        const elapsedMs = now.getTime() - new Date(record.revokedAt).getTime();

        if (elapsedMs >= 0 && elapsedMs <= this.graceWindowMs) {
          return {
            isValid: true,
            isWithinGracePeriod: true,
            actionRequired: "none",
            reason: SessionReasonCode.ROTATION,
            message: `Legitimate concurrent read-only request permitted within ${elapsedMs}ms window`,
          };
        }
      }

      // Step C: If outside the grace concurrency window, flag as a replay breach (stolen token)
      return {
        isValid: false,
        isWithinGracePeriod: false,
        actionRequired: "revoke_tree", // Automatic Reuse Detection (ARD) cascading revocation
        reason: SessionReasonCode.SECURITY_BREACH,
        message: "Session token reuse detected outside concurrency window",
      };
    }

    // 4. CSRF Validation check
    if (this.config.security.csrf.enabled) {
      const m = context.method || "GET";
      // O(1) Zero-allocation boolean evaluation
      const isStateChanging =
        m === "POST" ||
        m === "PUT" ||
        m === "DELETE" ||
        m === "PATCH" ||
        m === "post" ||
        m === "put" ||
        m === "delete" ||
        m === "patch";

      if (isStateChanging) {
        if (
          !context.csrfToken ||
          !record.csrfToken ||
          !constantTimeCompare(context.csrfToken, record.csrfToken)
        ) {
          return {
            isValid: false,
            isWithinGracePeriod: false,
            actionRequired: "none", // Do not revoke, just block the request (standard CSRF behavior, though some strict configs might revoke)
            reason: SessionReasonCode.CSRF_VIOLATION,
            message: "CSRF token mismatch or missing",
          };
        }
      }
    }

    // 5. IP Context Binding check
    const ipConfig = this.config.security.ipBinding;
    if (ipConfig !== "off") {
      if (record.metadata.ipAddress !== context.ipAddress) {
        if (ipConfig === "hard") {
          return {
            isValid: false,
            isWithinGracePeriod: false,
            actionRequired: "revoke",
            reason: SessionReasonCode.IP_MISMATCH,
            message: `IP mismatch in strict mode (Expected: ${SecurityPolicyEvaluator.maskIp(record.metadata.ipAddress)}, Actual: ${SecurityPolicyEvaluator.maskIp(context.ipAddress)})`,
          };
        } else if (ipConfig === "soft") {
          // WHY: Soft binding allows request but triggers event/warning via softWarning flag.
          // Full details are emitted to the secure event boundary, not the result message.
          return {
            isValid: true,
            isWithinGracePeriod: false,
            actionRequired: "none",
            softWarning: true,
          };
        }
      }
    }

    // 6. Device/User-Agent Fingerprinting check
    const fpConfig = this.config.security.fingerprinting;
    if (fpConfig !== "off") {
      // Step A: Validate User-Agent (legacy check)
      if (record.metadata.userAgent) {
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
              softWarning: true,
            };
          }
        }
      }

      // Step B: Validate Device Fingerprint (primary security boundary check)
      // WHY: Only enforce if the stored fingerprint is persistent (not fallback).
      // Fallback fingerprints are ephemeral UUIDs generated for cookie-less clients
      // at session creation — they cannot be reproduced by the client on the next
      // request, so enforcing them would cause guaranteed false-positive logouts.
      const storedFp = record.metadata.deviceFingerprint;
      if (storedFp && !storedFp.startsWith(FALLBACK_FP_PREFIX)) {
        // WHY: constantTimeCompare prevents timing-attack-based brute force.
        // Plain === short-circuits on the first differing byte, leaking information
        // about how many leading characters an attacker has correct.
        const fpMatch = constantTimeCompare(
          storedFp,
          context.deviceFingerprint ?? "",
        );
        if (!fpMatch) {
          if (fpConfig === "hard") {
            return {
              isValid: false,
              isWithinGracePeriod: false,
              actionRequired: "revoke",
              reason: SessionReasonCode.DEVICE_MISMATCH,
              message: `Device fingerprint mismatch/missing in strict mode (Expected: ${SecurityPolicyEvaluator.hashFingerprint(storedFp)}, Actual: ${SecurityPolicyEvaluator.hashFingerprint(context.deviceFingerprint ?? "")})`,
            };
          } else if (fpConfig === "soft") {
            return {
              isValid: true,
              isWithinGracePeriod: false,
              actionRequired: "none",
              softWarning: true,
            };
          }
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
