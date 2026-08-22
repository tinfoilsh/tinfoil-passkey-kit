import {
  copyAndValidateProfile,
  copyProfile,
  deriveWrappingKey,
  generateKeyMaterial,
  unwrapKey,
  validateWrappedKey,
  wrapKey,
} from "./crypto.js";
import { invalidInput, PasskeyKeyError } from "./errors.js";
import { canAttemptPasskeyUnlock, canEnrollPlatformPasskey } from "./support.js";
import type { StoreKey } from "./storage.js";
import type {
  PasskeyKeyManager,
  PasskeyKeyManagerConfig,
  PasskeyUser,
  PrfResult,
  UnlockOptions,
  WrappedKey,
} from "./types.js";
import {
  createPrfCredential,
  evaluatePrfCredential,
  type CeremonyContext,
  type InternalPrfResult,
} from "./webauthn.js";

const DEFAULT_TIMEOUT_MS = 60_000;

function validateConfig(config: PasskeyKeyManagerConfig): void {
  if (!config || typeof config !== "object") throw invalidInput("manager config is required");
  if (typeof config.rpId !== "string" || config.rpId.length === 0) {
    throw invalidInput("rpId must be a non-empty string");
  }
  if (typeof config.rpName !== "string" || config.rpName.length === 0) {
    throw invalidInput("rpName must be a non-empty string");
  }
  if (
    config.timeoutMs !== undefined &&
    (!Number.isFinite(config.timeoutMs) || config.timeoutMs <= 0)
  ) {
    throw invalidInput("timeoutMs must be positive and finite");
  }
}

function publicResult(result: InternalPrfResult): PrfResult {
  return { credentialId: result.credentialId, prfOutput: result.prfOutput.slice() };
}

function mapCeremonyError(error: unknown, operation: string): PasskeyKeyError {
  if (error instanceof PasskeyKeyError) {
    if (error.operation) return error;
    return new PasskeyKeyError(error.code, error.message, { cause: error.cause, operation });
  }
  if (error instanceof DOMException && error.name === "NotAllowedError") {
    return new PasskeyKeyError(
      "cancelledOrUnavailable",
      "the passkey operation was cancelled or unavailable",
      { cause: error, operation },
    );
  }
  if (error instanceof DOMException && error.name === "AbortError") {
    return new PasskeyKeyError("cancelledOrUnavailable", "the passkey operation was aborted", {
      cause: error,
      operation,
    });
  }
  return new PasskeyKeyError("cryptoFailure", "the passkey operation failed", {
    cause: error,
    operation,
  });
}

export function createPasskeyKeyManager(
  config: PasskeyKeyManagerConfig,
): PasskeyKeyManager {
  validateConfig(config);
  const profile = copyAndValidateProfile(config.profile);
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const namespace = { rpId: config.rpId, profileId: profile.id };
  const ceremonyContext: CeremonyContext = {
    rpId: config.rpId,
    rpName: config.rpName,
    prfInput: profile.prfInput.slice(),
    timeoutMs,
  };
  let activeOperation: symbol | null = null;

  const storeKey = (credentialId: string): StoreKey => ({ ...namespace, credentialId });

  async function runCeremony(
    operation: string,
    callerSignal: AbortSignal | undefined,
    perform: (signal: AbortSignal) => Promise<InternalPrfResult>,
  ): Promise<InternalPrfResult> {
    if (activeOperation) {
      throw new PasskeyKeyError("operationInProgress", "another ceremony is in progress", {
        operation,
      });
    }
    if (callerSignal?.aborted) {
      throw new PasskeyKeyError(
        "cancelledOrUnavailable",
        "the passkey operation was aborted",
        { cause: callerSignal.reason, operation },
      );
    }

    const token = Symbol(operation);
    const controller = new AbortController();
    activeOperation = token;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    let rejectInterruption: ((error: PasskeyKeyError) => void) | undefined;
    const interrupted = new Promise<InternalPrfResult>((_, reject) => {
      rejectInterruption = reject;
    });
    const abortFromCaller = () => {
      rejectInterruption?.(
        new PasskeyKeyError("cancelledOrUnavailable", "the passkey operation was aborted", {
          cause: callerSignal?.reason,
          operation,
        }),
      );
      controller.abort(callerSignal?.reason);
    };
    callerSignal?.addEventListener("abort", abortFromCaller, { once: true });
    timeout = setTimeout(() => {
      rejectInterruption?.(
        new PasskeyKeyError("timeout", "the passkey operation timed out", { operation }),
      );
      controller.abort(new DOMException("Timed out", "TimeoutError"));
    }, timeoutMs);

    try {
      return await Promise.race([perform(controller.signal), interrupted]);
    } catch (error) {
      throw mapCeremonyError(error, operation);
    } finally {
      if (timeout !== undefined) clearTimeout(timeout);
      callerSignal?.removeEventListener("abort", abortFromCaller);
      if (activeOperation === token) activeOperation = null;
    }
  }

  async function record(result: InternalPrfResult): Promise<void> {
    const key = storeKey(result.credentialId);
    await Promise.allSettled([
      config.secretStore?.save(key, result.prfOutput.slice()),
      config.credentialStore?.save({
        ...key,
        isPlatformAuthenticator: result.isPlatformAuthenticator,
      }),
    ]);
  }

  async function createCredential(
    user: PasskeyUser,
    signal?: AbortSignal,
  ): Promise<PrfResult> {
    const result = await runCeremony("createCredential", signal, (internalSignal) =>
      createPrfCredential(ceremonyContext, user, internalSignal),
    );
    await record(result);
    return publicResult(result);
  }

  function orderedCredentialIds(
    credentialIds: string[],
    preferredCredentialId?: string,
  ): string[] {
    if (!Array.isArray(credentialIds) || credentialIds.length === 0) {
      throw invalidInput("at least one credentialId is required", "evaluateCredential");
    }
    const unique = [...new Set(credentialIds)];
    for (const credentialId of unique) {
      if (
        typeof credentialId !== "string" ||
        !/^[A-Za-z0-9_-]+$/.test(credentialId) ||
        credentialId.length % 4 === 1
      ) {
        throw invalidInput("credentialId must be unpadded base64url", "evaluateCredential");
      }
    }
    if (!preferredCredentialId || !unique.includes(preferredCredentialId)) return unique;
    return [preferredCredentialId, ...unique.filter((id) => id !== preferredCredentialId)];
  }

  async function evaluateCredential(
    credentialIds: string[],
    options: UnlockOptions = {},
  ): Promise<PrfResult> {
    const ordered = orderedCredentialIds(credentialIds, options.preferredCredentialId);
    const result = await runCeremony("evaluateCredential", options.signal, (internalSignal) =>
      evaluatePrfCredential(ceremonyContext, ordered, internalSignal),
    );
    await record(result);
    return publicResult(result);
  }

  async function wrapWithPrfResult(
    result: PrfResult,
    keyMaterial: Uint8Array,
  ): Promise<WrappedKey> {
    const wrappingKey = await deriveWrappingKey(result.prfOutput, profile);
    return wrapKey({
      profile,
      credentialId: result.credentialId,
      wrappingKey,
      keyMaterial,
    });
  }

  async function unwrapWithPrfResult(
    result: PrfResult,
    wrappedKey: WrappedKey,
  ): Promise<Uint8Array> {
    if (result.credentialId !== wrappedKey.credentialId) {
      throw invalidInput("PRF result credential does not match wrapped key");
    }
    const wrappingKey = await deriveWrappingKey(result.prfOutput, profile);
    return unwrapKey({ profile, wrappingKey, wrappedKey });
  }

  return {
    get profile() {
      return copyProfile(profile);
    },

    canEnrollPlatformPasskey,
    canAttemptPasskeyUnlock,

    createCredential(user, options = {}) {
      return createCredential(user, options.signal);
    },

    evaluateCredential,

    async enrollKey(input) {
      const keyMaterial = input.keyMaterial ?? generateKeyMaterial(profile);
      const result = await createCredential(input.user, input.signal);
      return { ...result, wrappedKey: await wrapWithPrfResult(result, keyMaterial) };
    },

    async unlockKey(wrappedKeys, options = {}) {
      if (!Array.isArray(wrappedKeys) || wrappedKeys.length === 0) {
        throw invalidInput("at least one wrapped key is required", "unlockKey");
      }
      for (const wrappedKey of wrappedKeys) validateWrappedKey(wrappedKey, profile);
      const result = await evaluateCredential(
        wrappedKeys.map((wrappedKey) => wrappedKey.credentialId),
        options,
      );
      const wrappedKey = wrappedKeys.find(
        (candidate) => candidate.credentialId === result.credentialId,
      );
      if (!wrappedKey) throw invalidInput("credential has no matching wrapped key", "unlockKey");
      return {
        credentialId: result.credentialId,
        keyMaterial: await unwrapWithPrfResult(result, wrappedKey),
      };
    },

    wrapWithPrfResult,
    unwrapWithPrfResult,

    async unlockKeyFromCache(wrappedKeys) {
      if (!config.secretStore) return null;
      for (const wrappedKey of wrappedKeys) {
        validateWrappedKey(wrappedKey, profile);
        const secret = await config.secretStore
          .load(storeKey(wrappedKey.credentialId))
          .catch(() => null);
        if (!secret) continue;
        try {
          return {
            credentialId: wrappedKey.credentialId,
            keyMaterial: await unwrapWithPrfResult(
              { credentialId: wrappedKey.credentialId, prfOutput: secret },
              wrappedKey,
            ),
          };
        } catch {
          continue;
        }
      }
      return null;
    },

    async rewrapKeyFromCache(keyMaterial) {
      if (!config.secretStore) return null;
      const [credentialId] = await config.secretStore.list(namespace).catch(() => []);
      if (!credentialId) return null;
      const secret = await config.secretStore.load(storeKey(credentialId)).catch(() => null);
      if (!secret) return null;
      return wrapWithPrfResult({ credentialId, prfOutput: secret }, keyMaterial);
    },

    async clearLocalState() {
      await Promise.allSettled([
        config.secretStore?.clear(namespace),
        config.credentialStore?.clear(namespace),
      ]);
    },
  };
}
