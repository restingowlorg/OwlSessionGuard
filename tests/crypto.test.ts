import { fastHash, generateBase64UrlToken } from "../src/infra/crypto/crypto";

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
});
