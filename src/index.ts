export { PasskeyKeyError } from "./errors.js";
export type { PasskeyKeyErrorCategory } from "./errors.js";
export { createPasskeyKeyManager } from "./kit.js";
export { unwrapKey, wrapKey } from "./crypto.js";
export {
  decodeWrappedKeyRecord,
  encodeWrappedKeyRecord,
} from "./wrapped-key-record-codec.js";
export {
  createInsecureBrowserLocalStoragePasskeyKeyStorage,
  createMemoryPasskeyKeyStorage,
} from "./storage.js";
export type { CachedPRFResult, PasskeyKeyStorage } from "./storage.js";
export type {
  CreateAndWrapKeyInput,
  CreatedWrappedKey,
  EvaluatedCredential,
  EvaluateCredentialInput,
  PasskeyCapability,
  PasskeyInteraction,
  PasskeyKeyManager,
  PasskeyKeyManagerConfig,
  PasskeyKeyProfile,
  PasskeyUser,
  PRFResult,
  RecoveredKey,
  RecoverKeyInput,
  RewrapKeyInput,
  UnwrapKeyWithPRFResultInput,
  WrapKeyWithPRFResultInput,
  WrappedKey,
  WrappedKeyRecord,
} from "./types.js";
