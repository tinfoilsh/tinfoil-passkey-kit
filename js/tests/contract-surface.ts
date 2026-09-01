import {
  decodeWrappedKeyRecord,
  encodeWrappedKeyRecord,
  unwrapKey,
  wrapKey,
} from "../../src/index.js";
import type {
  CachedPRFResult,
  CreateAndWrapKeyInput,
  EvaluateCredentialInput,
  PasskeyKeyManager,
  PasskeyKeyManagerConfig,
  PasskeyKeyProfile,
  PasskeyKeyStorage,
  RecoverKeyInput,
  RewrapKeyInput,
  UnwrapKeyWithPRFResultInput,
  WrapKeyWithPRFResultInput,
  WrappedKey,
  WrappedKeyRecord,
} from "../../src/index.js";

type Equal<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends <
    Value,
  >() => Value extends Right ? 1 : 2
    ? true
    : false;
type Assert<Value extends true> = Value;

type ProfileFields = Assert<
  Equal<
    keyof PasskeyKeyProfile,
    "version" | "relyingPartyId" | "prfSalt" | "hkdfInfo"
  >
>;
type WrappedKeyFields = Assert<
  Equal<
    keyof WrappedKey,
    "profile" | "credentialId" | "kekIvHex" | "wrappedKeyHex"
  >
>;
type ManagerMethods = Assert<
  Equal<
    keyof PasskeyKeyManager,
    | "capability"
    | "createAndWrapKey"
    | "recoverKey"
    | "evaluateCredential"
    | "wrapKeyWithPRFResult"
    | "unwrapKeyWithPRFResult"
    | "recoverKeyFromCache"
    | "rewrapKeyFromCache"
    | "clearLocalState"
    | "cancelActiveCeremony"
  >
>;
type ManagerConfigFields = Assert<
  Equal<
    keyof PasskeyKeyManagerConfig,
    "profile" | "relyingPartyName" | "timeoutMs" | "storage"
  >
>;
type CreateInputFields = Assert<
  Equal<keyof CreateAndWrapKeyInput, "user" | "key" | "signal">
>;
type RecoverInputFields = Assert<
  Equal<
    keyof RecoverKeyInput,
    "wrappedKeys" | "preferredCredentialId" | "signal" | "interaction"
  >
>;
type RewrapInputFields = Assert<Equal<keyof RewrapKeyInput, "key">>;
type WrapWithPRFInputFields = Assert<
  Equal<
    keyof WrapKeyWithPRFResultInput,
    "keyMaterial" | "credentialId" | "prfResult"
  >
>;
type UnwrapWithPRFInputFields = Assert<
  Equal<keyof UnwrapKeyWithPRFResultInput, "wrappedKey" | "prfResult">
>;
type EvaluateInputFields = Assert<
  Equal<
    keyof EvaluateCredentialInput,
    "credentialIds" | "preferredCredentialId" | "signal" | "interaction"
  >
>;
type WrappedKeyRecordFields = Assert<
  Equal<
    keyof WrappedKeyRecord,
    "version" | "profile" | "credentialId" | "kekIvHex" | "wrappedKeyHex"
  >
>;
type WrappedKeyRecordProfileFields = Assert<
  Equal<
    keyof WrappedKeyRecord["profile"],
    "version" | "relyingPartyId" | "prfSalt" | "hkdfInfo"
  >
>;
const encodeSignature: (wrappedKey: WrappedKey) => string =
  encodeWrappedKeyRecord;
const decodeSignature: (json: string) => WrappedKey = decodeWrappedKeyRecord;
const wrapKeySignature: (
  profile: PasskeyKeyProfile,
  credentialId: string,
  prfOutput: Uint8Array,
  key: Uint8Array,
  operation?: string,
) => Promise<WrappedKey> = wrapKey;
const unwrapKeySignature: (
  profile: PasskeyKeyProfile,
  prfOutput: Uint8Array,
  wrapped: WrappedKey,
  operation?: string,
) => Promise<Uint8Array> = unwrapKey;
type StorageMethods = Assert<
  Equal<
    PasskeyKeyStorage,
    {
      loadCachedPRFResult(): CachedPRFResult | null;
      saveCachedPRFResult(result: CachedPRFResult): void;
      loadLocalCredentialId(): string | null;
      saveLocalCredentialId(credentialId: string): void;
      clear(): void;
    }
  >
>;

export type ContractSurface =
  | ProfileFields
  | WrappedKeyFields
  | ManagerMethods
  | ManagerConfigFields
  | CreateInputFields
  | RecoverInputFields
  | RewrapInputFields
  | WrapWithPRFInputFields
  | UnwrapWithPRFInputFields
  | EvaluateInputFields
  | WrappedKeyRecordFields
  | WrappedKeyRecordProfileFields
  | StorageMethods;

export const contractCodec = {
  encodeSignature,
  decodeSignature,
  wrapKeySignature,
  unwrapKeySignature,
};
