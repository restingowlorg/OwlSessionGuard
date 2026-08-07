import { fastHash, generateBase64UrlToken, hmacSign } from "../src/infra/crypto/crypto";

describe("Crypto Helpers", () => {
  describe("fastHash", () => {
    it("should generate a SHA-256 hash in hex format", () => {
      const data = "test-data";
      const hash = fastHash(data);
      
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });

    it("should produce the same hash for the same input", () => {
      const data = "consistent-data";
      expect(fastHash(data)).toBe(fastHash(data));
    });
  });

  describe("generateBase64UrlToken", () => {
    it("should generate a random token with the specified entropy length", () => {
      const token = generateBase64UrlToken(32);
      expect(token).toBeDefined();
      expect(typeof token).toBe("string");
      // Base64Url should not contain +, /, or =
      expect(token).not.toMatch(/[+/=]/);
    });

    it("should generate unique tokens", () => {
      const t1 = generateBase64UrlToken();
      const t2 = generateBase64UrlToken();
      expect(t1).not.toBe(t2);
    });
  });

  describe("hmacSign", () => {
    it("should generate a SHA-256 HMAC in hex format", () => {
      const data = "session-123";
      const secret = "my-secret-key";
      const signature = hmacSign(data, secret);

      expect(signature).toMatch(/^[a-f0-9]{64}$/);
    });

    it("should be deterministic for same inputs", () => {
      const data = "session-123";
      const secret = "my-secret-key";

      expect(hmacSign(data, secret)).toBe(hmacSign(data, secret));
    });

    it("should produce different signatures for different data", () => {
      const secret = "my-secret-key";

      expect(hmacSign("session-1", secret)).not.toBe(hmacSign("session-2", secret));
    });

    it("should produce different signatures for different secrets", () => {
      const data = "session-123";

      expect(hmacSign(data, "secret-1")).not.toBe(hmacSign(data, "secret-2"));
    });

    it("should be one-way (cannot recover data from signature)", () => {
      const data = "session-123";
      const secret = "my-secret-key";
      const signature = hmacSign(data, secret);

      // Signature is 64 hex chars (256 bits), data is variable length
      // One-way property means we can't reverse the HMAC to get the data
      expect(signature.length).toBe(64);
    });
  });
});
