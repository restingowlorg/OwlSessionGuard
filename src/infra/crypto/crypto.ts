import * as crypto from "crypto";
import * as CryptoJS from "crypto-js";

// ---------------- Session Helpers (Performance Optimized) ----------------
/**
 * Fast one-way hash for session tokens (SHA-256).
 * Used for session lookups where bcrypt is too slow.
 */
export function fastHash(data: string): string {
  return CryptoJS.SHA256(data).toString(CryptoJS.enc.Hex);
}

/**
 * Generates a Base64URL encoded secure token for sessions.
 */
export function generateBase64UrlToken(length = 32): string {
  return CryptoJS.lib.WordArray.random(length)
    .toString(CryptoJS.enc.Base64)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Constant-time string comparison to prevent timing attacks.
 * WHY: Pure JS XOR accumulation — no early returns on length mismatch,
 * no null-byte ambiguity. Uniform timing for all input pairs.
 */
export function constantTimeCompare(
  a: string | undefined,
  b: string | undefined,
): boolean {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  const lenA = a.length;
  const lenB = b.length;
  const maxLen = Math.max(lenA, lenB);
  if (maxLen === 0) return true;

  let result = 0;
  for (let i = 0; i < maxLen; i++) {
    result |=
      (i < lenA ? a.charCodeAt(i) : 0) ^ (i < lenB ? b.charCodeAt(i) : 0);
  }
  result |= lenA ^ lenB;
  return result === 0;
}

// WHY: HMAC-SHA256 binds CSRF tokens to session-specific data.
// Domain-separated: same session ID + different secret = different token.
export function hmacSign(data: string, secret: string): string {
  return crypto.createHmac("sha256", secret).update(data).digest("hex");
}
