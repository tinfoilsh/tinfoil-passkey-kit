import { describe, expect, it } from "vitest";
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
  const wrappedKey: WrappedKey = {
    profile: {
      version: 1,
      relyingPartyId: "example.com",
      prfSalt: new Uint8Array([0, 255]),
      hkdfInfo: new Uint8Array([1, 2, 3]),
    },
    credentialId: "AQID",
    kekIvHex: "00".repeat(12),
    wrappedKeyHex: "11".repeat(48),
  };
  const canonical =
    '{"version":1,"profile":{"version":1,"relyingPartyId":"example.com","prfSalt":"AP8","hkdfInfo":"AQID"},"credentialId":"AQID","kekIvHex":"000000000000000000000000","wrappedKeyHex":"111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"}';

  it("emits exact cross-language canonical JSON", () => {
    expect(encodeWrappedKeyRecord(wrappedKey)).toBe(canonical);
    expect(decodeWrappedKeyRecord(canonical)).toEqual(wrappedKey);
  });

  it("accepts insignificant whitespace and any key order", () => {
    const reordered = JSON.stringify({
      wrappedKeyHex: wrappedKey.wrappedKeyHex,
      credentialId: wrappedKey.credentialId,
      profile: {
        hkdfInfo: "AQID",
        relyingPartyId: "example.com",
        version: 1,
        prfSalt: "AP8",
      },
      version: 1,
      kekIvHex: wrappedKey.kekIvHex,
    }, null, 2);
    expect(decodeWrappedKeyRecord(reordered)).toEqual(wrappedKey);
  });

  it.each([
    "not json",
    "{}",
    canonical.replace('"version":1', '"version":2'),
    canonical.replace('"profile":{"version":1', '"profile":{"version":2'),
    canonical.replace('"profile":{', '"extra":true,"profile":{'),
    canonical.replace('"prfSalt":"AP8"', '"prfSalt":"AP8="'),
    canonical.replace('"hkdfInfo":"AQID"', '"hkdfInfo":"***"'),
    canonical.replace('"credentialId":"AQID"', '"credentialId":"AQID="'),
    canonical.replace('"credentialId":"AQID"', '"credentialId":"AB"'),
    canonical.replace('"credentialId":"AQID"', '"credentialId":""'),
    canonical.replace('"kekIvHex":"00', '"kekIvHex":"AA'),
  ])("rejects malformed records", (value) => {
    expect(() => decodeWrappedKeyRecord(value)).toThrowError(
      expect.objectContaining({ category: "invalid_input" }),
    );
  });

  it("returns defensive profile byte copies", () => {
    const first = decodeWrappedKeyRecord(canonical);
    const second = decodeWrappedKeyRecord(canonical);
    first.profile.prfSalt[0] = 99;
    first.profile.hkdfInfo[0] = 99;
    expect(second.profile.prfSalt).toEqual(new Uint8Array([0, 255]));
    expect(second.profile.hkdfInfo).toEqual(new Uint8Array([1, 2, 3]));
  });
});
