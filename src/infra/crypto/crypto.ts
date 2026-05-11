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
