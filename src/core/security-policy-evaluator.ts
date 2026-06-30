import { SessionStateMachine } from "./state-machine";
import {
  constantTimeCompare,
  fastHash,
  hmacSign,
  CSRF_SIGNING_PREFIX,
} from "../infra/crypto/crypto";
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
    // WHY: Normalize method once at the top to eliminate redundant toUpperCase() calls
    // in the rotation gate (Step 3) and CSRF gate (Step 4). All downstream checks
    // compare against the already-normalized value.
    const normalizedMethod = (context.method || "GET").toUpperCase();

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
      const isIdempotent =
        normalizedMethod === "GET" ||
        normalizedMethod === "HEAD" ||
        normalizedMethod === "OPTIONS";

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
      const isStateChanging =
        normalizedMethod === "POST" ||
        normalizedMethod === "PUT" ||
        normalizedMethod === "DELETE" ||
        normalizedMethod === "PATCH";

      if (isStateChanging) {
        // WHY: HMAC-SHA256 produces exactly 64 lowercase hex chars.
        // Reject tokens that don't match this format to prevent unsigned tokens.
        const HMAC_HEX = /^[a-f0-9]{64}$/;
        const clientTokenValid =
          context.csrfToken && HMAC_HEX.test(context.csrfToken);
        const recordTokenValid =
          record.csrfToken && HMAC_HEX.test(record.csrfToken);

        // Recompute expected HMAC from record.id and secret — never trust stored value
        const secret = this.config.security.csrf.secret;
        if (!secret) {
          return {
            isValid: false,
            isWithinGracePeriod: false,
            actionRequired: "none",
            reason: SessionReasonCode.CSRF_VIOLATION,
            message: "CSRF secret not configured",
          };
        }

        // WHY: Try current secret first, fall back to previous secret for gradual rotation.
        // This prevents thundering-herd logout when the HMAC secret is rotated.
        // OWASP Secrets Management Cheat Sheet: "Introducing new keys for Write operations,
        // leaving old keys for Read operations."
        const expectedToken = hmacSign(
          `${CSRF_SIGNING_PREFIX}${record.id}`,
          secret,
        );
        const expectedTokenValid = HMAC_HEX.test(expectedToken);

        const currentSecretValid =
          clientTokenValid &&
          recordTokenValid &&
          expectedTokenValid &&
          constantTimeCompare(context.csrfToken!, expectedToken) &&
          constantTimeCompare(record.csrfToken!, expectedToken);

        if (currentSecretValid) {
          // Current secret validation passed — continue to next check
        } else if (this.config.security.csrf.previousSecret) {
          // WHY: Fall back to previous secret during grace period.
          // Tokens signed with the old secret remain valid until sessions rotate.
          const previousExpectedToken = hmacSign(
            `${CSRF_SIGNING_PREFIX}${record.id}`,
            this.config.security.csrf.previousSecret,
          );
          const previousExpectedValid = HMAC_HEX.test(previousExpectedToken);

          const previousSecretValid =
            clientTokenValid &&
            recordTokenValid &&
            previousExpectedValid &&
            constantTimeCompare(context.csrfToken!, previousExpectedToken) &&
            constantTimeCompare(record.csrfToken!, previousExpectedToken);

          if (!previousSecretValid) {
            return {
              isValid: false,
              isWithinGracePeriod: false,
              actionRequired: "none",
              reason: SessionReasonCode.CSRF_VIOLATION,
              message: "CSRF token mismatch or missing",
            };
          }
          // Previous secret validation passed — continue to next check
        } else {
          return {
            isValid: false,
            isWithinGracePeriod: false,
            actionRequired: "none",
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
