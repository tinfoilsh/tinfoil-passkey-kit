import type { CredentialStore, SecretStore } from "./storage.js";

export interface PasskeyKeyProfile {
  id: string;
  prfInput: Uint8Array;
  hkdfSalt: Uint8Array;
  hkdfInfo: Uint8Array;
  keyLengthBytes: number;
}

export interface WrappedKey {
  version: 1;
  profileId: string;
  credentialId: string;
  ivHex: string;
  ciphertextHex: string;
}

export interface PasskeyUser {
  id: Uint8Array;
  name: string;
  displayName?: string;
}

export interface PrfResult {
  credentialId: string;
  prfOutput: Uint8Array;
}

export interface EnrolledKey extends PrfResult {
  wrappedKey: WrappedKey;
}

export interface UnlockedKey {
  credentialId: string;
  keyMaterial: Uint8Array;
}

export interface CeremonyOptions {
  signal?: AbortSignal;
}

export interface UnlockOptions extends CeremonyOptions {
  preferredCredentialId?: string;
}

export interface PasskeyKeyManagerConfig {
  rpId: string;
  rpName: string;
  profile: PasskeyKeyProfile;
  timeoutMs?: number;
  secretStore?: SecretStore;
  credentialStore?: CredentialStore;
}

export interface PasskeyKeyManager {
  readonly profile: PasskeyKeyProfile;
  canEnrollPlatformPasskey(): Promise<boolean>;
  canAttemptPasskeyUnlock(): Promise<boolean>;
  createCredential(user: PasskeyUser, options?: CeremonyOptions): Promise<PrfResult>;
  evaluateCredential(
    credentialIds: string[],
    options?: UnlockOptions,
  ): Promise<PrfResult>;
  enrollKey(input: {
    user: PasskeyUser;
    keyMaterial?: Uint8Array;
    signal?: AbortSignal;
  }): Promise<EnrolledKey>;
  unlockKey(
    wrappedKeys: WrappedKey[],
    options?: UnlockOptions,
  ): Promise<UnlockedKey>;
  wrapWithPrfResult(result: PrfResult, keyMaterial: Uint8Array): Promise<WrappedKey>;
  unwrapWithPrfResult(result: PrfResult, wrappedKey: WrappedKey): Promise<Uint8Array>;
  unlockKeyFromCache(wrappedKeys: WrappedKey[]): Promise<UnlockedKey | null>;
  rewrapKeyFromCache(keyMaterial: Uint8Array): Promise<WrappedKey | null>;
  clearLocalState(): Promise<void>;
}
