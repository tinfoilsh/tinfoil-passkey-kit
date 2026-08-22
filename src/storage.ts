export interface CachedPRFResult {
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

export function createMemoryPasskeyKeyStorage(): PasskeyKeyStorage {
  let cached: CachedPRFResult | null = null;
  let localCredentialId: string | null = null;
  return {
    loadCachedPRFResult() {
      return cached
        ? { credentialId: cached.credentialId, prfOutput: cached.prfOutput.slice() }
        : null;
    },
    saveCachedPRFResult(result) {
      cached = { credentialId: result.credentialId, prfOutput: result.prfOutput.slice() };
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
