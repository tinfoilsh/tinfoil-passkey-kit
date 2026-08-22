import { bytesToBase64 } from "./codec.js";
import type { PasskeyKeyProfile } from "./types.js";

export interface CachedPRFResult {
  profile: PasskeyKeyProfile;
  credentialId: string;
  prfOutput: Uint8Array;
}

export interface PasskeyKeyStorage {
  loadCachedPRFResult(profile: PasskeyKeyProfile): CachedPRFResult | null;
  saveCachedPRFResult(result: CachedPRFResult): void;
  loadLocalCredentialId(profile: PasskeyKeyProfile): string | null;
  saveLocalCredentialId(profile: PasskeyKeyProfile, credentialId: string): void;
  clear(profile: PasskeyKeyProfile): void;
}

function profileKey(profile: PasskeyKeyProfile): string {
  return JSON.stringify([
    profile.version,
    profile.relyingPartyId,
    profile.relyingPartyName,
    bytesToBase64(profile.prfSalt),
    bytesToBase64(profile.hkdfInfo),
  ]);
}

function copyProfile(profile: PasskeyKeyProfile): PasskeyKeyProfile {
  return {
    ...profile,
    prfSalt: profile.prfSalt.slice(),
    hkdfInfo: profile.hkdfInfo.slice(),
  };
}

export function createMemoryPasskeyKeyStorage(): PasskeyKeyStorage {
  const cached = new Map<string, CachedPRFResult>();
  const localCredentialIds = new Map<string, string>();
  return {
    loadCachedPRFResult(profile) {
      const result = cached.get(profileKey(profile));
      return result
        ? {
            profile: copyProfile(result.profile),
            credentialId: result.credentialId,
            prfOutput: result.prfOutput.slice(),
          }
        : null;
    },
    saveCachedPRFResult(result) {
      cached.set(profileKey(result.profile), {
        profile: copyProfile(result.profile),
        credentialId: result.credentialId,
        prfOutput: result.prfOutput.slice(),
      });
    },
    loadLocalCredentialId(profile) {
      return localCredentialIds.get(profileKey(profile)) ?? null;
    },
    saveLocalCredentialId(profile, credentialId) {
      localCredentialIds.set(profileKey(profile), credentialId);
    },
    clear(profile) {
      const key = profileKey(profile);
      cached.delete(key);
      localCredentialIds.delete(key);
    },
  };
}
