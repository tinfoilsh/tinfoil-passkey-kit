import { bytesToHex, hexToBytes } from "./codec.js";
import { cryptoFailure, invalidInput, PasskeyKeyError } from "./errors.js";
import type { PasskeyKeyProfile, WrappedKey } from "./types.js";

const AES_GCM_IV_BYTES = 12;
const AES_GCM_TAG_BYTES = 16;
const PRF_OUTPUT_BYTES = 32;
const DEFAULT_STABLE_ID_BYTES = 16;
const MAX_RANDOM_KEY_BYTES = 65_536;
const DEFAULT_STABLE_ID_INFO = new TextEncoder().encode("tinfoil-key-id-v1");

function assertBytes(value: unknown, name: string, allowEmpty = false): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || (!allowEmpty && value.length === 0)) {
    throw invalidInput(`${name} must be ${allowEmpty ? "a" : "a non-empty"} Uint8Array`);
  }
}

export function copyAndValidateProfile(profile: PasskeyKeyProfile): PasskeyKeyProfile {
  if (!profile || typeof profile !== "object") throw invalidInput("profile is required");
  if (typeof profile.id !== "string" || profile.id.length === 0) {
    throw invalidInput("profile.id must be a non-empty string");
  }
  assertBytes(profile.prfInput, "profile.prfInput");
  assertBytes(profile.hkdfSalt, "profile.hkdfSalt", true);
  assertBytes(profile.hkdfInfo, "profile.hkdfInfo");
  if (
    !Number.isSafeInteger(profile.keyLengthBytes) ||
    profile.keyLengthBytes <= 0 ||
    profile.keyLengthBytes > MAX_RANDOM_KEY_BYTES
  ) {
    throw invalidInput(
      `profile.keyLengthBytes must be an integer from 1 through ${MAX_RANDOM_KEY_BYTES}`,
    );
  }
  return {
    id: profile.id,
    prfInput: profile.prfInput.slice(),
    hkdfSalt: profile.hkdfSalt.slice(),
    hkdfInfo: profile.hkdfInfo.slice(),
    keyLengthBytes: profile.keyLengthBytes,
  };
}

export function copyProfile(profile: PasskeyKeyProfile): PasskeyKeyProfile {
  return {
    ...profile,
    prfInput: profile.prfInput.slice(),
    hkdfSalt: profile.hkdfSalt.slice(),
    hkdfInfo: profile.hkdfInfo.slice(),
  };
}

export function generateKeyMaterial(profile: PasskeyKeyProfile): Uint8Array {
  const validated = copyAndValidateProfile(profile);
  try {
    return crypto.getRandomValues(new Uint8Array(validated.keyLengthBytes));
  } catch (cause) {
    throw cryptoFailure("failed to generate key material", cause, "generateKeyMaterial");
  }
}

export async function deriveWrappingKey(
  prfOutput: Uint8Array,
  profile: PasskeyKeyProfile,
): Promise<CryptoKey> {
  const validated = copyAndValidateProfile(profile);
  assertBytes(prfOutput, "prfOutput");
  if (prfOutput.length !== PRF_OUTPUT_BYTES) {
    throw invalidInput(`prfOutput must be ${PRF_OUTPUT_BYTES} bytes`, "deriveWrappingKey");
  }
  try {
    const ikm = await crypto.subtle.importKey("raw", prfOutput.slice(), "HKDF", false, [
      "deriveKey",
    ]);
    return await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: validated.hkdfSalt as BufferSource,
        info: validated.hkdfInfo as BufferSource,
      },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  } catch (cause) {
    if (cause instanceof PasskeyKeyError) throw cause;
    throw cryptoFailure("failed to derive wrapping key", cause, "deriveWrappingKey");
  }
}

function validateCredentialId(credentialId: string): void {
  if (
    typeof credentialId !== "string" ||
    !/^[A-Za-z0-9_-]+$/.test(credentialId) ||
    credentialId.length % 4 === 1
  ) {
    throw invalidInput("credentialId must be unpadded base64url");
  }
}

export function validateWrappedKey(
  wrappedKey: WrappedKey,
  profile: PasskeyKeyProfile,
): void {
  const validated = copyAndValidateProfile(profile);
  if (!wrappedKey || typeof wrappedKey !== "object") throw invalidInput("wrappedKey is required");
  if (wrappedKey.version !== 1) throw invalidInput("wrappedKey.version must be 1");
  if (wrappedKey.profileId !== validated.id) throw invalidInput("wrappedKey profile mismatch");
  validateCredentialId(wrappedKey.credentialId);
  if (!/^[0-9a-f]{24}$/.test(wrappedKey.ivHex)) {
    throw invalidInput("wrappedKey.ivHex must be a lowercase 12-byte hex value");
  }
  const expectedCiphertextHexLength = (validated.keyLengthBytes + AES_GCM_TAG_BYTES) * 2;
  if (!new RegExp(`^[0-9a-f]{${expectedCiphertextHexLength}}$`).test(wrappedKey.ciphertextHex)) {
    throw invalidInput("wrappedKey.ciphertextHex has an invalid format or length");
  }
}

export async function wrapKey(input: {
  profile: PasskeyKeyProfile;
  credentialId: string;
  wrappingKey: CryptoKey;
  keyMaterial: Uint8Array;
}): Promise<WrappedKey> {
  const profile = copyAndValidateProfile(input.profile);
  validateCredentialId(input.credentialId);
  assertBytes(input.keyMaterial, "keyMaterial");
  if (input.keyMaterial.length !== profile.keyLengthBytes) {
    throw invalidInput(`keyMaterial must be ${profile.keyLengthBytes} bytes`, "wrapKey");
  }
  try {
    const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource },
      input.wrappingKey,
      input.keyMaterial as BufferSource,
    );
    return {
      version: 1,
      profileId: profile.id,
      credentialId: input.credentialId,
      ivHex: bytesToHex(iv),
      ciphertextHex: bytesToHex(new Uint8Array(ciphertext)),
    };
  } catch (cause) {
    if (cause instanceof PasskeyKeyError) throw cause;
    throw cryptoFailure("failed to wrap key material", cause, "wrapKey");
  }
}

export async function unwrapKey(input: {
  profile: PasskeyKeyProfile;
  wrappingKey: CryptoKey;
  wrappedKey: WrappedKey;
}): Promise<Uint8Array> {
  const profile = copyAndValidateProfile(input.profile);
  validateWrappedKey(input.wrappedKey, profile);
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: hexToBytes(input.wrappedKey.ivHex) as BufferSource },
      input.wrappingKey,
      hexToBytes(input.wrappedKey.ciphertextHex) as BufferSource,
    );
    const result = new Uint8Array(plaintext);
    if (result.length !== profile.keyLengthBytes) throw new Error("wrong plaintext length");
    return result;
  } catch (cause) {
    if (cause instanceof PasskeyKeyError) throw cause;
    throw cryptoFailure("failed to unwrap key material", cause, "unwrapKey");
  }
}

export async function deriveStableKeyId(
  keyMaterial: Uint8Array,
  options: { salt?: Uint8Array; info?: Uint8Array; lengthBytes?: number } = {},
): Promise<Uint8Array> {
  assertBytes(keyMaterial, "keyMaterial");
  const salt = options.salt ?? new Uint8Array();
  const info = options.info ?? DEFAULT_STABLE_ID_INFO;
  const lengthBytes = options.lengthBytes ?? DEFAULT_STABLE_ID_BYTES;
  assertBytes(salt, "salt", true);
  assertBytes(info, "info");
  if (!Number.isSafeInteger(lengthBytes) || lengthBytes <= 0) {
    throw invalidInput("lengthBytes must be a positive integer", "deriveStableKeyId");
  }
  try {
    const ikm = await crypto.subtle.importKey("raw", keyMaterial.slice(), "HKDF", false, [
      "deriveBits",
    ]);
    const bits = await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: salt.slice() as BufferSource,
        info: info.slice() as BufferSource,
      },
      ikm,
      lengthBytes * 8,
    );
    return new Uint8Array(bits);
  } catch (cause) {
    throw cryptoFailure("failed to derive stable key id", cause, "deriveStableKeyId");
  }
}
