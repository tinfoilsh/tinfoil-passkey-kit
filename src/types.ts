import type { PasskeyKeyStorage } from "./storage.js";

export interface PasskeyKeyProfile {
  version: number;
  relyingPartyId: string;
  relyingPartyName: string;
  prfSalt: Uint8Array;
  hkdfInfo: Uint8Array;
}

export interface WrappedKey {
  profile: PasskeyKeyProfile;
  credentialId: string;
  kekIvHex: string;
  wrappedKeyHex: string;
}

export interface PasskeyUser {
  id: Uint8Array;
  name: string;
  displayName?: string;
}

export type PasskeyCapability = "supported" | "unsupported" | "unknown";

export interface CreateAndWrapKeyInput {
  user: PasskeyUser;
  key: Uint8Array;
  signal?: AbortSignal;
}

export interface CreatedWrappedKey {
  credentialId: string;
  wrappedKey: WrappedKey;
}

export interface RecoverKeyInput {
  wrappedKeys: WrappedKey[];
  preferredCredentialId?: string;
  signal?: AbortSignal;
}

export interface RecoveredKey {
  credentialId: string;
  key: Uint8Array;
}

export interface RewrapKeyInput {
  key: Uint8Array;
}

export interface PasskeyKeyManagerConfig {
  profile: PasskeyKeyProfile;
  timeoutMs?: number;
  storage?: PasskeyKeyStorage;
}

export interface PasskeyKeyManager {
  capability(input: {
    operation: "enroll" | "recover";
  }): Promise<PasskeyCapability>;
  createAndWrapKey(input: CreateAndWrapKeyInput): Promise<CreatedWrappedKey>;
  recoverKey(input: RecoverKeyInput): Promise<RecoveredKey>;
  recoverKeyFromCache(input: RecoverKeyInput): Promise<RecoveredKey | null>;
  rewrapKeyFromCache(input: RewrapKeyInput): Promise<WrappedKey | null>;
  clearLocalState(): void;
  cancelActiveCeremony(): void;
}
