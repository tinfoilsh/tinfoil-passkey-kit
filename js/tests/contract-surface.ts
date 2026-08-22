import { decodeWrappedKey, encodeWrappedKey } from "../../src/index.js";
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
  WrappedKey,
  WrappedKeyRecord,
} from "../../src/index.js";

type Equal<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends
  (<Value>() => Value extends Right ? 1 : 2)
    ? true
    : false;
type Assert<Value extends true> = Value;

type ProfileFields = Assert<
  Equal<
    keyof PasskeyKeyProfile,
    | "version"
    | "relyingPartyId"
    | "prfSalt"
    | "hkdfInfo"
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
const encodeSignature: (wrappedKey: WrappedKey) => string = encodeWrappedKey;
const decodeSignature: (json: string) => WrappedKey = decodeWrappedKey;
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
  | EvaluateInputFields
  | WrappedKeyRecordFields
  | WrappedKeyRecordProfileFields
  | StorageMethods;

export const contractCodec = { encodeSignature, decodeSignature };
