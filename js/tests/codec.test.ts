import { describe, expect, it } from "vitest";
import fixtures from "../../Fixtures/interop.json" with { type: "json" };
import {
  base64ToBytes,
  base64UrlToBytes,
  bufferSourceToArrayBuffer,
  bytesToBase64,
  bytesToBase64Url,
  bytesToHex,
  hexToBytes,
} from "../../src/codec.js";
import {
  decodeWrappedKeyRecord,
  encodeWrappedKeyRecord,
} from "../../src/wrapped-key-record-codec.js";
import type { WrappedKey } from "../../src/types.js";

describe("codec", () => {
  it("round-trips bytes through hex", () => {
    const bytes = crypto.getRandomValues(new Uint8Array(64));
    expect(hexToBytes(bytesToHex(bytes))).toEqual(bytes);
  });

  it("rejects malformed hex", () => {
    expect(() => hexToBytes("abc")).toThrow("odd-length");
    expect(() => hexToBytes("zz")).toThrow("invalid hex");
  });

  it("round-trips bytes through base64", () => {
    const bytes = new Uint8Array(100_000).map((_, i) => i % 256);
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });

  it("round-trips bytes through base64url without padding or unsafe chars", () => {
    const bytes = crypto.getRandomValues(new Uint8Array(33));
    const encoded = bytesToBase64Url(bytes);
    expect(encoded).not.toMatch(/[+/=]/);
    expect(base64UrlToBytes(encoded)).toEqual(bytes);
  });

  it("copies BufferSource views into standalone ArrayBuffers", () => {
    const backing = new Uint8Array([1, 2, 3, 4, 5]);
    const view = backing.subarray(1, 4);
    const copy = new Uint8Array(bufferSourceToArrayBuffer(view));
    expect(copy).toEqual(new Uint8Array([2, 3, 4]));
    backing[2] = 99;
    expect(copy[1]).toBe(3);
  });

  it("copies raw ArrayBuffers instead of returning the original reference", () => {
    const original = new Uint8Array([1, 2, 3]).buffer;
    const copy = bufferSourceToArrayBuffer(original);
    expect(copy).not.toBe(original);
    new Uint8Array(original)[0] = 99;
    expect(new Uint8Array(copy)[0]).toBe(1);
  });
});

describe("wrapped key JSON codec", () => {
  type FixtureVector = (typeof fixtures.vectors)[keyof typeof fixtures.vectors];

  function wrappedKey(vector: FixtureVector): WrappedKey {
    return {
      profile: {
        version: vector.wrappedKey.profile.version as 1,
        relyingPartyId: vector.wrappedKey.profile.relyingPartyId,
        prfSalt: hexToBytes(vector.wrappedKey.profile.prfSaltHex),
        hkdfInfo: hexToBytes(vector.wrappedKey.profile.hkdfInfoHex),
      },
      credentialId: vector.wrappedKey.credentialId,
      kekIvHex: vector.wrappedKey.kekIvHex,
      wrappedKeyHex: vector.wrappedKey.wrappedKeyHex,
    };
  }

  const javascriptVector = fixtures.vectors.javascriptWrapped;
  const canonical = javascriptVector.canonicalRecord;

  it("emits every exact cross-language canonical record", () => {
    for (const vector of Object.values(fixtures.vectors)) {
      const wrapped = wrappedKey(vector);
      expect(encodeWrappedKeyRecord(wrapped)).toBe(vector.canonicalRecord);
      expect(decodeWrappedKeyRecord(vector.canonicalRecord)).toEqual(wrapped);
    }
  });

  it("accepts insignificant whitespace and any key order", () => {
    const wrapped = wrappedKey(javascriptVector);
    const reordered = JSON.stringify({
      wrappedKeyHex: wrapped.wrappedKeyHex,
      credentialId: wrapped.credentialId,
      profile: {
        hkdfInfo: bytesToBase64Url(wrapped.profile.hkdfInfo),
        relyingPartyId: wrapped.profile.relyingPartyId,
        version: 1,
        prfSalt: bytesToBase64Url(wrapped.profile.prfSalt),
      },
      version: 1,
      kekIvHex: wrapped.kekIvHex,
    }, null, 2);
    expect(decodeWrappedKeyRecord(reordered)).toEqual(wrapped);
  });

  it.each([
    "not json",
    "{}",
    canonical.replace('"version":1', '"version":2'),
    canonical.replace('"profile":{"version":1', '"profile":{"version":2'),
    canonical.replace('"profile":{', '"extra":true,"profile":{'),
    canonical.replace('"profile":{"version":1,', '"profile":{"version":1,"extra":true,'),
    canonical.replace('"prfSalt":"', '"prfSalt":"='),
    canonical.replace('"hkdfInfo":"', '"hkdfInfo":"***'),
    canonical.replace('"credentialId":"AQID"', '"credentialId":"AQID="'),
    canonical.replace('"credentialId":"AQID"', '"credentialId":"AB"'),
    canonical.replace('"credentialId":"AQID"', '"credentialId":""'),
    canonical.replace('"kekIvHex":"01', '"kekIvHex":"AA'),
    canonical.replace(
      `"kekIvHex":"${javascriptVector.wrappedKey.kekIvHex}"`,
      `"kekIvHex":["${javascriptVector.wrappedKey.kekIvHex}"]`,
    ),
    canonical.replace(
      `"wrappedKeyHex":"${javascriptVector.wrappedKey.wrappedKeyHex}"`,
      `"wrappedKeyHex":["${javascriptVector.wrappedKey.wrappedKeyHex}"]`,
    ),
  ])("rejects malformed records", (value) => {
    expect(() => decodeWrappedKeyRecord(value)).toThrowError(
      expect.objectContaining({ category: "invalid_input" }),
    );
  });

  it.each([null, undefined])(
    "rejects a missing wrapped key during encoding",
    (value) => {
      expect(() => encodeWrappedKeyRecord(value as never)).toThrowError(
        expect.objectContaining({ category: "invalid_input" }),
      );
    },
  );

  it("returns defensive profile byte copies", () => {
    const first = decodeWrappedKeyRecord(canonical);
    const second = decodeWrappedKeyRecord(canonical);
    first.profile.prfSalt[0] = 99;
    first.profile.hkdfInfo[0] = 99;
    expect(second.profile.prfSalt).toEqual(
      hexToBytes(javascriptVector.wrappedKey.profile.prfSaltHex),
    );
    expect(second.profile.hkdfInfo).toEqual(
      hexToBytes(javascriptVector.wrappedKey.profile.hkdfInfoHex),
    );
  });
});
