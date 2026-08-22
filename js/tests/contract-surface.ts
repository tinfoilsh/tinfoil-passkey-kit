import type {
  CreateAndWrapKeyInput,
  PasskeyKeyManager,
  PasskeyKeyManagerConfig,
  PasskeyKeyProfile,
  RecoverKeyInput,
  RewrapKeyInput,
  WrappedKey,
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
    | "relyingPartyName"
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
    | "recoverKeyFromCache"
    | "rewrapKeyFromCache"
    | "clearLocalState"
    | "cancelActiveCeremony"
  >
>;
type ManagerConfigFields = Assert<
  Equal<keyof PasskeyKeyManagerConfig, "profile" | "timeoutMs" | "storage">
>;
type CreateInputFields = Assert<
  Equal<keyof CreateAndWrapKeyInput, "user" | "key" | "signal">
>;
type RecoverInputFields = Assert<
  Equal<
    keyof RecoverKeyInput,
    "wrappedKeys" | "preferredCredentialId" | "signal"
  >
>;
type RewrapInputFields = Assert<Equal<keyof RewrapKeyInput, "key">>;

export type ContractSurface =
  | ProfileFields
  | WrappedKeyFields
  | ManagerMethods
  | ManagerConfigFields
  | CreateInputFields
  | RecoverInputFields
  | RewrapInputFields;
