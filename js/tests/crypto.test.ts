import { afterEach, describe, expect, it, vi } from "vitest";
import fixtures from "../../Fixtures/interop.json" with { type: "json" };
import { hexToBytes } from "../../src/codec.js";
import {
  copyAndValidateProfile,
  deriveWrappingKey,
  unwrapKey,
  validateCredentialId,
  validateKey,
  wrapKey,
} from "../../src/crypto.js";
import {
  decodeWrappedKeyRecord,
  encodeWrappedKeyRecord,
} from "../../src/wrapped-key-record-codec.js";
import type { PasskeyKeyProfile, WrappedKey } from "../../src/types.js";

type FixtureVector = (typeof fixtures.vectors)[keyof typeof fixtures.vectors];
type FixtureProfile = FixtureVector["wrappedKey"]["profile"];

function profileFromFixture(value: FixtureProfile): PasskeyKeyProfile {
  return {
    version: value.version as 1,
    relyingPartyId: value.relyingPartyId,
    prfSalt: hexToBytes(value.prfSaltHex),
    hkdfInfo: hexToBytes(value.hkdfInfoHex),
  };
}

function wrappedFromFixture(vector: FixtureVector): WrappedKey {
  return {
    profile: profileFromFixture(vector.wrappedKey.profile),
    credentialId: vector.wrappedKey.credentialId,
    kekIvHex: vector.wrappedKey.kekIvHex,
    wrappedKeyHex: vector.wrappedKey.wrappedKeyHex,
  };
}

const javascriptVector = fixtures.vectors.javascriptWrapped;
const profile = profileFromFixture(javascriptVector.wrappedKey.profile);

afterEach(() => {
  vi.restoreAllMocks();
});

describe("key wrapping interoperability", () => {
  it("produces the exact JavaScript vector and canonical record", async () => {
    const iv = hexToBytes(javascriptVector.wrappedKey.kekIvHex);
    vi.spyOn(crypto, "getRandomValues").mockImplementation((value) => {
      new Uint8Array(value.buffer, value.byteOffset, value.byteLength).set(iv);
      return value;
    });

    const wrapped = await wrapKey(
      profile,
      javascriptVector.wrappedKey.credentialId,
      hexToBytes(javascriptVector.prfOutputHex),
      hexToBytes(javascriptVector.keyHex),
    );

    expect(wrapped).toEqual(wrappedFromFixture(javascriptVector));
    expect(encodeWrappedKeyRecord(wrapped)).toBe(javascriptVector.canonicalRecord);
    expect(wrapped.profile).not.toBe(profile);
    expect(wrapped.profile.prfSalt).not.toBe(profile.prfSalt);
    expect(wrapped.profile.hkdfInfo).not.toBe(profile.hkdfInfo);
  });

  it("opens the exact Swift vector and canonical record", async () => {
    const vector = fixtures.vectors.swiftWrapped;
    const wrapped = decodeWrappedKeyRecord(vector.canonicalRecord);
    expect(wrapped).toEqual(wrappedFromFixture(vector));
    await expect(
      unwrapKey(
        profileFromFixture(vector.wrappedKey.profile),
        hexToBytes(vector.prfOutputHex),
        wrapped,
      ),
    ).resolves.toEqual(hexToBytes(vector.keyHex));
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

  it.each(
    fixtures.negative.malformedFields
      .filter(({ field }) => field === "credentialId")
      .map(({ value }) => value),
  )("rejects fixture malformed credential ID %s", (credentialId) => {
    expect(() => validateCredentialId(credentialId)).toThrowError(
      expect.objectContaining({ category: "invalid_input" }),
    );
  });

  it("accepts fixture canonical credential IDs", () => {
    expect(() => validateCredentialId("AQ")).not.toThrow();
    for (const vector of Object.values(fixtures.vectors)) {
      expect(() => validateCredentialId(vector.wrappedKey.credentialId)).not.toThrow();
    }
  });

  it("strictly validates and defensively copies version 1 profiles", () => {
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
    expect(() => copyAndValidateProfile({ ...profile, version: 0 } as never)).toThrowError(
      expect.objectContaining({ category: "invalid_input" }),
    );
    expect(() => copyAndValidateProfile({ ...profile, version: 2 } as never)).toThrowError(
      expect.objectContaining({ category: "invalid_input" }),
    );
  });

  it("rejects fixture profile mismatch, malformed fields, and tampering", async () => {
    const wrapped = wrappedFromFixture(javascriptVector);
    await expect(
      unwrapKey(
        profileFromFixture(fixtures.negative.profileMismatch),
        hexToBytes(javascriptVector.prfOutputHex),
        wrapped,
      ),
    ).rejects.toMatchObject({ category: "invalid_input" });

    for (const malformed of fixtures.negative.malformedFields) {
      await expect(
        unwrapKey(profile, hexToBytes(javascriptVector.prfOutputHex), {
          ...wrapped,
          [malformed.field]: malformed.value,
        }),
      ).rejects.toMatchObject({ category: "invalid_input" });
    }

    await expect(
      unwrapKey(profile, hexToBytes(javascriptVector.prfOutputHex), {
        ...wrapped,
        wrappedKeyHex: fixtures.negative.tamperedWrappedKeyHex,
      }),
    ).rejects.toMatchObject({ category: "operation_failed" });
    await expect(deriveWrappingKey(new Uint8Array(31), profile)).rejects.toMatchObject({
      category: "invalid_input",
    });
  });
});
