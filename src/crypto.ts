import {
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToHex,
  hexToBytes,
} from "./codec.js";
import { invalidInput, operationFailed, PasskeyKeyError } from "./errors.js";
import type { PasskeyKeyProfile, WrappedKey } from "./types.js";

const KEY_BYTES = 32;
const PRF_OUTPUT_BYTES = 32;
const AES_GCM_IV_BYTES = 12;
const AES_GCM_TAG_BYTES = 16;
export const PROFILE_KEYS = [
  "version",
  "relyingPartyId",
  "prfSalt",
  "hkdfInfo",
] as const;

function assertBytes(
  value: unknown,
  name: string,
  allowEmpty = false,
): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || (!allowEmpty && value.length === 0)) {
    throw invalidInput(
      `${name} must be ${allowEmpty ? "a" : "a non-empty"} Uint8Array`,
    );
  }
}

export function copyAndValidateProfile(
  profile: PasskeyKeyProfile,
): PasskeyKeyProfile {
  if (!profile || typeof profile !== "object")
    throw invalidInput("profile is required");
  const keys = Object.keys(profile).sort();
  const expected = [...PROFILE_KEYS].sort();
  if (
    keys.length !== expected.length ||
    keys.some((key, index) => key !== expected[index])
  ) {
    throw invalidInput(
      `profile must contain exactly ${PROFILE_KEYS.join(", ")}`,
    );
  }
  if (profile.version !== 1) {
    throw invalidInput("profile.version must be 1");
  }
  if (
    typeof profile.relyingPartyId !== "string" ||
    profile.relyingPartyId.length === 0
  ) {
    throw invalidInput("profile.relyingPartyId must be a non-empty string");
  }
  assertBytes(profile.prfSalt, "profile.prfSalt");
  assertBytes(profile.hkdfInfo, "profile.hkdfInfo");
  return {
    version: profile.version,
    relyingPartyId: profile.relyingPartyId,
    prfSalt: profile.prfSalt.slice(),
    hkdfInfo: profile.hkdfInfo.slice(),
  };
}

export function profilesEqual(
  left: PasskeyKeyProfile,
  right: PasskeyKeyProfile,
): boolean {
  return (
    left.version === right.version &&
    left.relyingPartyId === right.relyingPartyId &&
    left.prfSalt.length === right.prfSalt.length &&
    left.prfSalt.every((byte, index) => byte === right.prfSalt[index]) &&
    left.hkdfInfo.length === right.hkdfInfo.length &&
    left.hkdfInfo.every((byte, index) => byte === right.hkdfInfo[index])
  );
}

export function decodeCanonicalBase64Url(
  value: unknown,
  field: string,
): Uint8Array {
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
    if (bytes.length === 0 || bytesToBase64Url(bytes) !== value) {
      throw invalidInput(`${field} must use canonical unpadded base64url`);
    }
    return bytes;
  } catch (cause) {
    if (cause instanceof PasskeyKeyError) throw cause;
    throw invalidInput(`${field} must be unpadded base64url`);
  }
}

export function validateCredentialId(credentialId: string): void {
  decodeCanonicalBase64Url(credentialId, "credentialId");
}

export function validateKey(key: Uint8Array, operation?: string): void {
  if (!(key instanceof Uint8Array) || key.length !== KEY_BYTES) {
    throw invalidInput(`key must be exactly ${KEY_BYTES} bytes`, operation);
  }
}

export function validateWrappedKey(
  wrapped: WrappedKey,
  profile: PasskeyKeyProfile,
): void {
  if (!wrapped || typeof wrapped !== "object")
    throw invalidInput("wrapped key is required");
  const keys = Object.keys(wrapped).sort();
  const expected = [
    "profile",
    "credentialId",
    "kekIvHex",
    "wrappedKeyHex",
  ].sort();
  if (
    keys.length !== expected.length ||
    keys.some((key, index) => key !== expected[index])
  ) {
    throw invalidInput("wrapped key has unexpected fields");
  }
  const wrappedProfile = copyAndValidateProfile(wrapped.profile);
  if (!profilesEqual(wrappedProfile, profile)) {
    throw invalidInput("wrapped key profile mismatch");
  }
  validateCredentialId(wrapped.credentialId);
  if (!/^[0-9a-f]{24}$/.test(wrapped.kekIvHex)) {
    throw invalidInput("kekIvHex must be a lowercase 12-byte hex value");
  }
  const ciphertextHexLength = (KEY_BYTES + AES_GCM_TAG_BYTES) * 2;
  if (
    !new RegExp(`^[0-9a-f]{${ciphertextHexLength}}$`).test(
      wrapped.wrappedKeyHex,
    )
  ) {
    throw invalidInput("wrappedKeyHex has an invalid format or length");
  }
}

export async function deriveWrappingKey(
  prfOutput: Uint8Array,
  profile: PasskeyKeyProfile,
): Promise<CryptoKey> {
  if (
    !(prfOutput instanceof Uint8Array) ||
    prfOutput.length !== PRF_OUTPUT_BYTES
  ) {
    throw invalidInput(`PRF output must be exactly ${PRF_OUTPUT_BYTES} bytes`);
  }
  try {
    const ikm = await crypto.subtle.importKey(
      "raw",
      prfOutput.slice(),
      "HKDF",
      false,
      ["deriveKey"],
    );
    return await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array() as BufferSource,
        info: profile.hkdfInfo as BufferSource,
      },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  } catch (cause) {
    if (cause instanceof PasskeyKeyError) throw cause;
    throw operationFailed("failed to derive wrapping key", cause);
  }
}

/**
 * Wraps exactly 32 key bytes with a key derived from raw WebAuthn PRF
 * output, without starting a ceremony or accessing storage. The PRF
 * output is secret key material: callers must avoid logging,
 * transmitting, or retaining it longer than necessary. High-level
 * applications should prefer a manager's `createAndWrapKey`.
 */
export async function wrapKey(
  profile: PasskeyKeyProfile,
  credentialId: string,
  prfOutput: Uint8Array,
  key: Uint8Array,
  operation = "wrapKey",
): Promise<WrappedKey> {
  validateCredentialId(credentialId);
  validateKey(key, operation);
  try {
    const wrappingKey = await deriveWrappingKey(prfOutput, profile);
    const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource },
      wrappingKey,
      key as BufferSource,
    );
    return {
      profile: copyAndValidateProfile(profile),
      credentialId,
      kekIvHex: bytesToHex(iv),
      wrappedKeyHex: bytesToHex(new Uint8Array(ciphertext)),
    };
  } catch (cause) {
    if (cause instanceof PasskeyKeyError) throw cause;
    throw operationFailed("failed to wrap key", cause, operation);
  }
}

/**
 * Unwraps a `WrappedKey` with a key derived from raw WebAuthn PRF
 * output, without starting a ceremony or accessing storage. The PRF
 * output is secret key material: callers must avoid logging,
 * transmitting, or retaining it longer than necessary. High-level
 * applications should prefer a manager's `recoverKey`.
 */
export async function unwrapKey(
  profile: PasskeyKeyProfile,
  prfOutput: Uint8Array,
  wrapped: WrappedKey,
  operation = "unwrapKey",
): Promise<Uint8Array> {
  validateWrappedKey(wrapped, profile);
  try {
    const wrappingKey = await deriveWrappingKey(prfOutput, profile);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: hexToBytes(wrapped.kekIvHex) as BufferSource },
      wrappingKey,
      hexToBytes(wrapped.wrappedKeyHex) as BufferSource,
    );
    const key = new Uint8Array(plaintext);
    validateKey(key, operation);
    return key;
  } catch (cause) {
    if (cause instanceof PasskeyKeyError) throw cause;
    throw operationFailed("failed to recover key", cause, operation);
  }
}
