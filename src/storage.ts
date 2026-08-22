import { base64ToBytes, bytesToBase64 } from "./codec.js";

export interface StoreKey {
  rpId: string;
  profileId: string;
  credentialId: string;
}

export interface CredentialMetadata extends StoreKey {
  isPlatformAuthenticator: boolean;
}

export interface SecretStore {
  load(key: StoreKey): Promise<Uint8Array | null>;
  list(namespace: Pick<StoreKey, "rpId" | "profileId">): Promise<string[]>;
  save(key: StoreKey, secret: Uint8Array): Promise<void>;
  remove(key: StoreKey): Promise<void>;
  clear(namespace: Pick<StoreKey, "rpId" | "profileId">): Promise<void>;
}

export interface CredentialStore {
  load(key: StoreKey): Promise<CredentialMetadata | null>;
  save(metadata: CredentialMetadata): Promise<void>;
  remove(key: StoreKey): Promise<void>;
  clear(namespace: Pick<StoreKey, "rpId" | "profileId">): Promise<void>;
}

function storageKey(key: StoreKey): string {
  return [key.rpId, key.profileId, key.credentialId]
    .map((part) => encodeURIComponent(part))
    .join("/");
}

function namespacePrefix(namespace: Pick<StoreKey, "rpId" | "profileId">): string {
  return `${encodeURIComponent(namespace.rpId)}/${encodeURIComponent(namespace.profileId)}/`;
}

export function createMemorySecretStore(): SecretStore {
  const values = new Map<string, Uint8Array>();
  return {
    async load(key) {
      return values.get(storageKey(key))?.slice() ?? null;
    },
    async list(namespace) {
      const prefix = namespacePrefix(namespace);
      return [...values.keys()]
        .filter((key) => key.startsWith(prefix))
        .map((key) => decodeURIComponent(key.slice(prefix.length)));
    },
    async save(key, secret) {
      values.set(storageKey(key), secret.slice());
    },
    async remove(key) {
      values.delete(storageKey(key));
    },
    async clear(namespace) {
      const prefix = namespacePrefix(namespace);
      for (const key of values.keys()) if (key.startsWith(prefix)) values.delete(key);
    },
  };
}

export function createMemoryCredentialStore(): CredentialStore {
  const values = new Map<string, CredentialMetadata>();
  return {
    async load(key) {
      const value = values.get(storageKey(key));
      return value ? { ...value } : null;
    },
    async save(metadata) {
      values.set(storageKey(metadata), { ...metadata });
    },
    async remove(key) {
      values.delete(storageKey(key));
    },
    async clear(namespace) {
      const prefix = namespacePrefix(namespace);
      for (const key of values.keys()) if (key.startsWith(prefix)) values.delete(key);
    },
  };
}

/**
 * Stores raw PRF output in browser localStorage without encryption. This is
 * insecure against same-origin script access and must be explicitly enabled.
 */
export function createInsecureBrowserLocalStorageSecretStore(
  prefix = "passkey-key-secret/",
): SecretStore {
  const fullKey = (key: StoreKey) => `${prefix}${storageKey(key)}`;
  return {
    async load(key) {
      try {
        if (typeof localStorage === "undefined") return null;
        const value = localStorage.getItem(fullKey(key));
        return value === null ? null : base64ToBytes(value);
      } catch {
        return null;
      }
    },
    async list(namespace) {
      if (typeof localStorage === "undefined") return [];
      const scopedPrefix = `${prefix}${namespacePrefix(namespace)}`;
      const credentialIds: string[] = [];
      for (let index = 0; index < localStorage.length; index += 1) {
        const key = localStorage.key(index);
        if (key?.startsWith(scopedPrefix)) {
          credentialIds.push(decodeURIComponent(key.slice(scopedPrefix.length)));
        }
      }
      return credentialIds;
    },
    async save(key, secret) {
      if (typeof localStorage === "undefined") return;
      localStorage.setItem(fullKey(key), bytesToBase64(secret));
    },
    async remove(key) {
      if (typeof localStorage === "undefined") return;
      localStorage.removeItem(fullKey(key));
    },
    async clear(namespace) {
      if (typeof localStorage === "undefined") return;
      const scopedPrefix = `${prefix}${namespacePrefix(namespace)}`;
      const keys: string[] = [];
      for (let index = 0; index < localStorage.length; index += 1) {
        const key = localStorage.key(index);
        if (key?.startsWith(scopedPrefix)) keys.push(key);
      }
      for (const key of keys) localStorage.removeItem(key);
    },
  };
}
