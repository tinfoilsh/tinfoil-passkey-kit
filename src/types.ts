import type { PasskeyKeyStorage } from "./storage.js";

export interface PasskeyKeyProfile {
  version: number;
  relyingPartyId: string;
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
export type PasskeyInteraction = "interactive" | "immediatelyAvailable";

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
  interaction?: PasskeyInteraction;
}

export interface EvaluateCredentialInput {
  credentialIds: string[];
  preferredCredentialId?: string;
  signal?: AbortSignal;
  interaction?: PasskeyInteraction;
}

export interface PRFResult {
  output: Uint8Array;
}

export interface EvaluatedCredential {
  credentialId: string;
  prfResult: PRFResult;
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
  relyingPartyName: string;
  timeoutMs?: number;
  storage?: PasskeyKeyStorage;
}

export interface PasskeyKeyManager {
  capability(input: {
    operation: "enroll" | "recover";
  }): Promise<PasskeyCapability>;
  createAndWrapKey(input: CreateAndWrapKeyInput): Promise<CreatedWrappedKey>;
  recoverKey(input: RecoverKeyInput): Promise<RecoveredKey>;
  evaluateCredential(input: EvaluateCredentialInput): Promise<EvaluatedCredential>;
  recoverKeyFromCache(input: RecoverKeyInput): Promise<RecoveredKey | null>;
  rewrapKeyFromCache(input: RewrapKeyInput): Promise<WrappedKey | null>;
  clearLocalState(): void;
  cancelActiveCeremony(): void;
}

export interface WrappedKeyRecord {
  version: 1;
  profile: {
    version: 1;
    relyingPartyId: string;
    prfSalt: string;
    hkdfInfo: string;
  };
  credentialId: string;
  kekIvHex: string;
  wrappedKeyHex: string;
}
