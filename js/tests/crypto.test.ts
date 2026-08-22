import { describe, expect, it, vi } from "vitest";
import {
  copyAndValidateProfile,
  deriveWrappingKey,
  unwrapKey,
  validateKey,
  wrapKey,
} from "../../src/crypto.js";
import type { PasskeyKeyProfile } from "../../src/types.js";

const encoder = new TextEncoder();
const profile: PasskeyKeyProfile = {
  id: "tinfoil-v1",
  version: 1,
  relyingPartyId: "example.com",
  relyingPartyName: "Example",
  prfSalt: encoder.encode("tinfoil-chat-key-encryption"),
  hkdfInfo: encoder.encode("tinfoil-chat-kek-v1"),
};

describe("key wrapping", () => {
  it("preserves the existing adapter wire bytes", async () => {
    const prfOutput = new Uint8Array(32).map((_, index) => index);
    const key = new Uint8Array(32).map((_, index) => 255 - index);
    const iv = new Uint8Array(12).map((_, index) => index + 1);
    vi.spyOn(crypto, "getRandomValues").mockImplementation((value) => {
      new Uint8Array(value.buffer, value.byteOffset, value.byteLength).set(iv);
      return value;
    });

    const wrapped = await wrapKey(profile, "AQID", prfOutput, key);
    const adapterFixture = {
      credentialId: "AQID",
      kekIvHex: "0102030405060708090a0b0c",
      wrappedKeyHex:
        "53c8f700925c9f94a7cf679d8a892c82f7c443769103a322e477a38d9118f0a014a659136ee1b9f6ed4921877f17aca7",
    };
    expect(wrapped).toEqual({
      profileId: profile.id,
      version: profile.version,
      ...adapterFixture,
    });
    expect(
      await unwrapKey(profile, prfOutput, {
        profileId: profile.id,
        version: profile.version,
        ...adapterFixture,
      }),
    ).toEqual(key);
  });

  it("derives a non-extractable AES-256-GCM key", async () => {
    const key = await deriveWrappingKey(new Uint8Array(32), profile);
    expect(key.algorithm).toMatchObject({ name: "AES-GCM", length: 256 });
    expect(key.extractable).toBe(false);
  });

  it("accepts exactly 32 key bytes", () => {
    expect(() => validateKey(new Uint8Array(32))).not.toThrow();
    expect(() => validateKey(new Uint8Array(31))).toThrowError(
      expect.objectContaining({ category: "invalid_input" }),
    );
    expect(() => validateKey(new Uint8Array(33))).toThrowError(
      expect.objectContaining({ category: "invalid_input" }),
    );
  });

  it("strictly validates and defensively copies profiles", () => {
    const input = {
      ...profile,
      prfSalt: profile.prfSalt.slice(),
      hkdfInfo: profile.hkdfInfo.slice(),
    };
    const copied = copyAndValidateProfile(input);
    input.prfSalt[0] = 0;
    input.hkdfInfo[0] = 0;
    expect(copied.prfSalt).toEqual(profile.prfSalt);
    expect(copied.hkdfInfo).toEqual(profile.hkdfInfo);
    expect(() => copyAndValidateProfile({ ...profile, extra: true } as never)).toThrowError(
      expect.objectContaining({ category: "invalid_input" }),
    );
    expect(() => copyAndValidateProfile({ ...profile, version: 0 })).toThrowError(
      expect.objectContaining({ category: "invalid_input" }),
    );
  });

  it("rejects profile mismatches, malformed fields, and tampering", async () => {
    const prfOutput = new Uint8Array(32);
    const wrapped = await wrapKey(profile, "AQ", prfOutput, new Uint8Array(32));
    await expect(
      unwrapKey({ ...profile, id: "other" }, prfOutput, wrapped),
    ).rejects.toMatchObject({ category: "invalid_input" });
    await expect(
      unwrapKey(profile, prfOutput, { ...wrapped, kekIvHex: "bad" }),
    ).rejects.toMatchObject({ category: "invalid_input" });
    const first = wrapped.wrappedKeyHex[0] === "0" ? "1" : "0";
    await expect(
      unwrapKey(profile, prfOutput, {
        ...wrapped,
        wrappedKeyHex: `${first}${wrapped.wrappedKeyHex.slice(1)}`,
      }),
    ).rejects.toMatchObject({ category: "operation_failed" });
    await expect(deriveWrappingKey(new Uint8Array(31), profile)).rejects.toMatchObject({
      category: "invalid_input",
    });
  });
});
