import { bytesToBase64Url } from "./codec.js";
import {
  copyAndValidateProfile,
  decodeCanonicalBase64Url,
  PROFILE_KEYS,
  validateWrappedKey,
} from "./crypto.js";
import { invalidInput } from "./errors.js";
import type { WrappedKey, WrappedKeyRecord } from "./types.js";

const RECORD_FIELDS = [
  "version",
  "profile",
  "credentialId",
  "kekIvHex",
  "wrappedKeyHex",
] as const;
function hasExactFields(value: unknown, fields: readonly string[]): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value).sort();
  const expected = [...fields].sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

export function encodeWrappedKeyRecord(wrappedKey: WrappedKey): string {
  if (!wrappedKey || typeof wrappedKey !== "object") {
    throw invalidInput("wrapped key is required");
  }
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
  if (!hasExactFields(parsed.profile, PROFILE_KEYS)) {
    throw invalidInput("wrapped key profile record has unexpected fields");
  }
  if (parsed.profile.version !== 1) {
    throw invalidInput("wrapped key profile version must be 1");
  }
  if (typeof parsed.profile.relyingPartyId !== "string") {
    throw invalidInput("profile.relyingPartyId must be a string");
  }
  if (typeof parsed.credentialId !== "string") {
    throw invalidInput("credentialId must be a string");
  }
  if (typeof parsed.kekIvHex !== "string") {
    throw invalidInput("kekIvHex must be a string");
  }
  if (typeof parsed.wrappedKeyHex !== "string") {
    throw invalidInput("wrappedKeyHex must be a string");
  }
  const wrappedKey: WrappedKey = {
    profile: {
      version: 1,
      relyingPartyId: parsed.profile.relyingPartyId,
      prfSalt: decodeCanonicalBase64Url(parsed.profile.prfSalt, "profile.prfSalt"),
      hkdfInfo: decodeCanonicalBase64Url(parsed.profile.hkdfInfo, "profile.hkdfInfo"),
    },
    credentialId: parsed.credentialId,
    kekIvHex: parsed.kekIvHex,
    wrappedKeyHex: parsed.wrappedKeyHex,
  };
  const profile = copyAndValidateProfile(wrappedKey.profile);
  validateWrappedKey(wrappedKey, profile);
  return {
    ...wrappedKey,
    profile,
  };
}
