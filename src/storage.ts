import { base64ToBytes, bytesToBase64 } from "./codec.js";
import type { PasskeyKeyProfile } from "./types.js";

export interface CachedPRFResult {
  profile: PasskeyKeyProfile;
  credentialId: string;
  prfOutput: Uint8Array;
}

export interface PasskeyKeyStorage {
  loadCachedPRFResult(): CachedPRFResult | null;
  saveCachedPRFResult(result: CachedPRFResult): void;
  loadLocalCredentialId(): string | null;
  saveLocalCredentialId(credentialId: string): void;
  clear(): void;
}

function copyProfile(profile: PasskeyKeyProfile): PasskeyKeyProfile {
  return {
    ...profile,
    prfSalt: profile.prfSalt.slice(),
    hkdfInfo: profile.hkdfInfo.slice(),
  };
}

function copyCachedResult(result: CachedPRFResult): CachedPRFResult {
  return {
    profile: copyProfile(result.profile),
    credentialId: result.credentialId,
    prfOutput: result.prfOutput.slice(),
  };
}

export function createMemoryPasskeyKeyStorage(): PasskeyKeyStorage {
  let cached: CachedPRFResult | null = null;
  let localCredentialId: string | null = null;
  return {
    loadCachedPRFResult() {
      return cached ? copyCachedResult(cached) : null;
    },
    saveCachedPRFResult(result) {
      cached = copyCachedResult(result);
    },
    loadLocalCredentialId() {
      return localCredentialId;
    },
    saveLocalCredentialId(credentialId) {
      localCredentialId = credentialId;
    },
    clear() {
      cached = null;
      localCredentialId = null;
    },
  };
}

interface SerializedCachedPRFResult {
  profile: Omit<PasskeyKeyProfile, "prfSalt" | "hkdfInfo"> & {
    prfSaltBase64: string;
    hkdfInfoBase64: string;
  };
  credentialId: string;
  prfOutputBase64: string;
}

/** Stores raw PRF output unencrypted in localStorage under an explicit namespace. */
export function createInsecureBrowserLocalStoragePasskeyKeyStorage(
  namespace: string,
): PasskeyKeyStorage {
  const prefix = `passkey-key/${encodeURIComponent(namespace)}`;
  const cachedKey = `${prefix}/cached-prf`;
  const localCredentialKey = `${prefix}/local-credential`;
  return {
    loadCachedPRFResult() {
      try {
        if (typeof localStorage === "undefined") return null;
        const value = localStorage.getItem(cachedKey);
        if (!value) return null;
        const stored = JSON.parse(value) as SerializedCachedPRFResult;
        return {
          profile: {
            version: stored.profile.version,
            relyingPartyId: stored.profile.relyingPartyId,
            prfSalt: base64ToBytes(stored.profile.prfSaltBase64),
            hkdfInfo: base64ToBytes(stored.profile.hkdfInfoBase64),
          },
          credentialId: stored.credentialId,
          prfOutput: base64ToBytes(stored.prfOutputBase64),
        };
      } catch {
        return null;
      }
    },
    saveCachedPRFResult(result) {
      if (typeof localStorage === "undefined") return;
      const serialized: SerializedCachedPRFResult = {
        profile: {
          version: result.profile.version,
          relyingPartyId: result.profile.relyingPartyId,
          prfSaltBase64: bytesToBase64(result.profile.prfSalt),
          hkdfInfoBase64: bytesToBase64(result.profile.hkdfInfo),
        },
        credentialId: result.credentialId,
        prfOutputBase64: bytesToBase64(result.prfOutput),
      };
      localStorage.setItem(cachedKey, JSON.stringify(serialized));
    },
    loadLocalCredentialId() {
      if (typeof localStorage === "undefined") return null;
      return localStorage.getItem(localCredentialKey);
    },
    saveLocalCredentialId(credentialId) {
      if (typeof localStorage === "undefined") return;
      localStorage.setItem(localCredentialKey, credentialId);
    },
    clear() {
      if (typeof localStorage === "undefined") return;
      localStorage.removeItem(cachedKey);
      localStorage.removeItem(localCredentialKey);
    },
  };
}
