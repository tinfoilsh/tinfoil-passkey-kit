import { describe, expect, it, vi } from "vitest";
import {
  deriveStableKeyId,
  deriveWrappingKey,
  generateKeyMaterial,
  unwrapKey,
  wrapKey,
} from "../../src/crypto.js";
import { PasskeyKeyError } from "../../src/errors.js";
import type { PasskeyKeyProfile } from "../../src/types.js";

const encoder = new TextEncoder();
const profile: PasskeyKeyProfile = {
  id: "tinfoil-v1",
  prfInput: encoder.encode("tinfoil-chat-key-encryption"),
  hkdfSalt: new Uint8Array(),
  hkdfInfo: encoder.encode("tinfoil-chat-kek-v1"),
  keyLengthBytes: 32,
};

describe("generic crypto API", () => {
  it("generates the profile's requested key length", () => {
    expect(generateKeyMaterial(profile)).toHaveLength(32);
  });

  it("preserves the existing Tinfoil AES-GCM/HKDF wire bytes", async () => {
    const prfOutput = new Uint8Array(32).map((_, index) => index);
    const keyMaterial = new Uint8Array(32).map((_, index) => 255 - index);
    const iv = new Uint8Array(12).map((_, index) => index + 1);
    const random = vi.spyOn(crypto, "getRandomValues").mockImplementation((value) => {
      new Uint8Array(value.buffer, value.byteOffset, value.byteLength).set(iv);
      return value;
    });
    const wrappingKey = await deriveWrappingKey(prfOutput, profile);
    const wrapped = await wrapKey({
      profile,
      credentialId: "AQID",
      wrappingKey,
      keyMaterial,
    });
    random.mockRestore();

    const adapterFixture = {
      credentialId: "AQID",
      kekIvHex: "0102030405060708090a0b0c",
      wrappedKeyHex:
        "53c8f700925c9f94a7cf679d8a892c82f7c443769103a322e477a38d9118f0a014a659136ee1b9f6ed4921877f17aca7",
    };
    expect(wrapped).toEqual({
      version: 1,
      profileId: "tinfoil-v1",
      credentialId: adapterFixture.credentialId,
      ivHex: adapterFixture.kekIvHex,
      ciphertextHex: adapterFixture.wrappedKeyHex,
    });
    expect(
      await unwrapKey({
        profile,
        wrappingKey,
        wrappedKey: {
          version: 1,
          profileId: profile.id,
          credentialId: adapterFixture.credentialId,
          ivHex: adapterFixture.kekIvHex,
          ciphertextHex: adapterFixture.wrappedKeyHex,
        },
      }),
    ).toEqual(keyMaterial);
  });

  it("rejects profile mismatches and malformed or tampered records", async () => {
    const prf = new Uint8Array(32);
    const wrappingKey = await deriveWrappingKey(prf, profile);
    const wrapped = await wrapKey({
      profile,
      credentialId: "AQ",
      wrappingKey,
      keyMaterial: new Uint8Array(32),
    });
    await expect(
      unwrapKey({ profile: { ...profile, id: "other" }, wrappingKey, wrappedKey: wrapped }),
    ).rejects.toMatchObject({ code: "invalidInput" });
    await expect(
      unwrapKey({
        profile,
        wrappingKey,
        wrappedKey: {
          ...wrapped,
          ciphertextHex: `${wrapped.ciphertextHex[0] === "0" ? "1" : "0"}${wrapped.ciphertextHex.slice(1)}`,
        },
      }),
    ).rejects.toMatchObject({ code: "cryptoFailure" });
    await expect(
      unwrapKey({ profile, wrappingKey, wrappedKey: { ...wrapped, ivHex: "xyz" } }),
    ).rejects.toMatchObject({ code: "invalidInput" });
  });

  it("validates profiles, key lengths, and PRF output length", async () => {
    expect(() => generateKeyMaterial({ ...profile, keyLengthBytes: 0 })).toThrow(PasskeyKeyError);
    expect(() => generateKeyMaterial({ ...profile, keyLengthBytes: 1.5 })).toThrow(PasskeyKeyError);
    expect(() => generateKeyMaterial({ ...profile, prfInput: new Uint8Array() })).toThrow(
      PasskeyKeyError,
    );
    await expect(deriveWrappingKey(new Uint8Array(31), profile)).rejects.toMatchObject({
      code: "invalidInput",
    });
  });

  it("derives stable identifiers and validates output lengths", async () => {
    const key = new Uint8Array(32).map((_, index) => index);
    expect(await deriveStableKeyId(key)).toEqual(await deriveStableKeyId(key));
    await expect(deriveStableKeyId(key, { lengthBytes: 0 })).rejects.toMatchObject({
      code: "invalidInput",
    });
  });
});
