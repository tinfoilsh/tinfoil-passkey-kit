import type {
  PasskeyKeyManager,
  PasskeyKeyProfile,
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
    | "id"
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
    "profileId" | "version" | "credentialId" | "kekIvHex" | "wrappedKeyHex"
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

export type ContractSurface = ProfileFields | WrappedKeyFields | ManagerMethods;
