import { base64UrlToBytes, bytesToBase64Url } from "./codec.js";
import {
  copyAndValidateProfile,
  validateWrappedKey,
} from "./crypto.js";
import { invalidInput, PasskeyKeyError } from "./errors.js";
import type { WrappedKey, WrappedKeyRecord } from "./types.js";

const RECORD_FIELDS = [
  "version",
  "profile",
  "credentialId",
  "kekIvHex",
  "wrappedKeyHex",
] as const;
const PROFILE_FIELDS = [
  "version",
  "relyingPartyId",
  "prfSalt",
  "hkdfInfo",
] as const;

function hasExactFields(value: unknown, fields: readonly string[]): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value).sort();
  const expected = [...fields].sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

function decodeBase64Url(value: unknown, field: string): Uint8Array {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !/^[A-Za-z0-9_-]+$/.test(value) ||
    value.length % 4 === 1
  ) {
    throw invalidInput(`${field} must be unpadded base64url`);
  }
  try {
    const bytes = base64UrlToBytes(value);
    if (bytesToBase64Url(bytes) !== value) {
      throw invalidInput(`${field} must use canonical unpadded base64url`);
    }
    return bytes;
  } catch (cause) {
    if (cause instanceof PasskeyKeyError) throw cause;
    throw invalidInput(`${field} must be unpadded base64url`);
  }
}

export function encodeWrappedKeyRecord(wrappedKey: WrappedKey): string {
  const profile = copyAndValidateProfile(wrappedKey.profile);
  validateWrappedKey(wrappedKey, profile);
  const record: WrappedKeyRecord = {
    version: 1,
    profile: {
      version: 1,
      relyingPartyId: profile.relyingPartyId,
      prfSalt: bytesToBase64Url(profile.prfSalt),
      hkdfInfo: bytesToBase64Url(profile.hkdfInfo),
    },
    credentialId: wrappedKey.credentialId,
    kekIvHex: wrappedKey.kekIvHex,
    wrappedKeyHex: wrappedKey.wrappedKeyHex,
  };
  return JSON.stringify(record);
}

export function decodeWrappedKeyRecord(json: string): WrappedKey {
  if (typeof json !== "string") throw invalidInput("wrapped key JSON must be a string");
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw invalidInput("wrapped key JSON is malformed");
  }
  if (!hasExactFields(parsed, RECORD_FIELDS)) {
    throw invalidInput("wrapped key record has unexpected fields");
  }
  if (parsed.version !== 1) throw invalidInput("wrapped key record version must be 1");
  if (!hasExactFields(parsed.profile, PROFILE_FIELDS)) {
    throw invalidInput("wrapped key profile record has unexpected fields");
  }
  if (parsed.profile.version !== 1) {
    throw invalidInput("wrapped key profile version must be 1");
  }
  if (typeof parsed.profile.relyingPartyId !== "string") {
    throw invalidInput("profile.relyingPartyId must be a string");
  }
  const wrappedKey: WrappedKey = {
    profile: {
      version: 1,
      relyingPartyId: parsed.profile.relyingPartyId,
      prfSalt: decodeBase64Url(parsed.profile.prfSalt, "profile.prfSalt"),
      hkdfInfo: decodeBase64Url(parsed.profile.hkdfInfo, "profile.hkdfInfo"),
    },
    credentialId: parsed.credentialId as string,
    kekIvHex: parsed.kekIvHex as string,
    wrappedKeyHex: parsed.wrappedKeyHex as string,
  };
  const profile = copyAndValidateProfile(wrappedKey.profile);
  validateWrappedKey(wrappedKey, profile);
  return {
    ...wrappedKey,
    profile,
  };
}
