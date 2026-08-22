import {
  copyAndValidateProfile,
  profilesEqual,
  unwrapKey,
  validateKey,
  validateWrappedKey,
  wrapKey,
} from "./crypto.js";
import { invalidInput, PasskeyKeyError } from "./errors.js";
import { capability as detectCapability } from "./support.js";
import type { CachedPRFResult } from "./storage.js";
import type {
  CreateAndWrapKeyInput,
  PasskeyKeyManager,
  PasskeyKeyManagerConfig,
  PasskeyUser,
  RecoverKeyInput,
  WrappedKey,
} from "./types.js";
import {
  createPrfCredential,
  evaluatePrfCredential,
  type CeremonyContext,
  type InternalPrfResult,
} from "./webauthn.js";

const DEFAULT_TIMEOUT_MS = 60_000;

interface ActiveCeremony {
  token: symbol;
  operation: string;
  cancel(error: PasskeyKeyError): void;
}

function mapCeremonyError(error: unknown, operation: string): PasskeyKeyError {
  if (error instanceof PasskeyKeyError) {
    if (error.operation) return error;
    return new PasskeyKeyError(error.category, error.message, {
      cause: error.cause,
      operation,
    });
  }
  if (error instanceof DOMException && error.name === "NotAllowedError") {
    return new PasskeyKeyError(
      "cancelled",
      "the prompt was dismissed or no eligible credential was available",
      { cause: error, operation },
    );
  }
  if (error instanceof DOMException && error.name === "AbortError") {
    return new PasskeyKeyError("cancelled", "the passkey operation was cancelled", {
      cause: error,
      operation,
    });
  }
  return new PasskeyKeyError("operation_failed", "the passkey operation failed", {
    cause: error,
    operation,
  });
}

function context(profile: PasskeyKeyProfileSnapshot, timeoutMs: number): CeremonyContext {
  return {
    rpId: profile.relyingPartyId,
    rpName: profile.relyingPartyName,
    prfInput: profile.prfSalt,
    timeoutMs,
  };
}

type PasskeyKeyProfileSnapshot = ReturnType<typeof copyAndValidateProfile>;

function copyUser(user: PasskeyUser): PasskeyUser {
  if (!user || typeof user !== "object") throw invalidInput("user is required");
  return {
    id: user.id instanceof Uint8Array ? user.id.slice() : user.id,
    name: user.name,
    displayName: user.displayName,
  };
}

function copyWrappedKeys(wrappedKeys: WrappedKey[]): WrappedKey[] {
  if (!Array.isArray(wrappedKeys) || wrappedKeys.length === 0) {
    throw invalidInput("at least one wrapped key is required");
  }
  return wrappedKeys.map((wrapped) => ({
    ...wrapped,
    profile: copyAndValidateProfile(wrapped.profile),
  }));
}

export function createPasskeyKeyManager(
  config: PasskeyKeyManagerConfig,
): PasskeyKeyManager {
  if (!config || typeof config !== "object") throw invalidInput("manager config is required");
  const profile = copyAndValidateProfile(config.profile);
  if (
    config.timeoutMs !== undefined &&
    (!Number.isFinite(config.timeoutMs) || config.timeoutMs <= 0)
  ) {
    throw invalidInput("timeoutMs must be positive and finite");
  }
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  let activeCeremony: ActiveCeremony | null = null;

  async function runCeremony(
    operation: string,
    callerSignal: AbortSignal | undefined,
    perform: (signal: AbortSignal) => Promise<InternalPrfResult>,
  ): Promise<InternalPrfResult> {
    if (activeCeremony) {
      throw new PasskeyKeyError(
        "operation_in_progress",
        "another passkey ceremony is in progress",
        { operation },
      );
    }
    if (callerSignal?.aborted) {
      throw new PasskeyKeyError("cancelled", "the passkey operation was cancelled", {
        cause: callerSignal.reason,
        operation,
      });
    }

    const token = Symbol(operation);
    const controller = new AbortController();
    let rejectInterruption: ((error: PasskeyKeyError) => void) | undefined;
    const interrupted = new Promise<InternalPrfResult>((_, reject) => {
      rejectInterruption = reject;
    });
    const cancel = (error: PasskeyKeyError) => {
      rejectInterruption?.(error);
      controller.abort(error);
    };
    activeCeremony = { token, operation, cancel };
    const cancelFromCaller = () =>
      cancel(
        new PasskeyKeyError("cancelled", "the passkey operation was cancelled", {
          cause: callerSignal?.reason,
          operation,
        }),
      );
    callerSignal?.addEventListener("abort", cancelFromCaller, { once: true });
    const timeout = setTimeout(
      () =>
        cancel(
          new PasskeyKeyError("timeout", "the passkey operation timed out", {
            operation,
          }),
        ),
      timeoutMs,
    );

    try {
      return await Promise.race([perform(controller.signal), interrupted]);
    } catch (error) {
      throw mapCeremonyError(error, operation);
    } finally {
      clearTimeout(timeout);
      callerSignal?.removeEventListener("abort", cancelFromCaller);
      if (activeCeremony?.token === token) activeCeremony = null;
    }
  }

  function recordSuccessfulCredential(result: InternalPrfResult): void {
    try {
      config.storage?.saveCachedPRFResult({
        profile: copyAndValidateProfile(profile),
        credentialId: result.credentialId,
        prfOutput: result.prfOutput.slice(),
      });
    } catch {
      // Storage is best-effort and cannot invalidate a successful ceremony.
    }
    if (result.isPlatformAuthenticator) {
      try {
        config.storage?.saveLocalCredentialId(
          copyAndValidateProfile(profile),
          result.credentialId,
        );
      } catch {
        // Storage is best-effort and cannot invalidate a successful ceremony.
      }
    }
  }

  function loadCachedResult(): CachedPRFResult | null {
    let result: CachedPRFResult | null;
    try {
      result =
        config.storage?.loadCachedPRFResult(copyAndValidateProfile(profile)) ?? null;
    } catch {
      return null;
    }
    if (!result) return null;
    let cachedProfile: PasskeyKeyProfileSnapshot;
    try {
      cachedProfile = copyAndValidateProfile(result.profile);
    } catch {
      return null;
    }
    if (
      !profilesEqual(cachedProfile, profile) ||
      typeof result.credentialId !== "string" ||
      !/^[A-Za-z0-9_-]+$/.test(result.credentialId) ||
      result.credentialId.length % 4 === 1 ||
      !(result.prfOutput instanceof Uint8Array) ||
      result.prfOutput.length !== 32
    ) return null;
    return {
      profile: cachedProfile,
      credentialId: result.credentialId,
      prfOutput: result.prfOutput.slice(),
    };
  }

  function loadPreferredCredentialId(): string | null {
    try {
      return (
        config.storage?.loadLocalCredentialId(copyAndValidateProfile(profile)) ?? null
      );
    } catch {
      return null;
    }
  }

  function orderedCredentialIds(
    wrappedKeys: WrappedKey[],
    preferredCredentialId?: string,
  ): string[] {
    const unique = [...new Set(wrappedKeys.map((wrapped) => wrapped.credentialId))];
    const preferred = preferredCredentialId ?? loadPreferredCredentialId();
    if (!preferred || !unique.includes(preferred)) return unique;
    return [preferred, ...unique.filter((credentialId) => credentialId !== preferred)];
  }

  async function createAndWrapKey(input: CreateAndWrapKeyInput) {
    if (!input || typeof input !== "object") throw invalidInput("input is required");
    validateKey(input.key, "createAndWrapKey");
    const key = input.key.slice();
    const user = copyUser(input.user);
    const result = await runCeremony("createAndWrapKey", input.signal, (signal) =>
      createPrfCredential(context(profile, timeoutMs), user, signal),
    );
    recordSuccessfulCredential(result);
    const wrappedKey = await wrapKey(
      profile,
      result.credentialId,
      result.prfOutput,
      key,
    );
    return { credentialId: result.credentialId, wrappedKey };
  }

  function prepareRecovery(input: RecoverKeyInput) {
    if (!input || typeof input !== "object") throw invalidInput("input is required");
    const wrappedKeys = copyWrappedKeys(input.wrappedKeys);
    for (const wrapped of wrappedKeys) validateWrappedKey(wrapped, profile);
    return wrappedKeys;
  }

  return {
    async capability(input) {
      if (
        !input ||
        typeof input !== "object" ||
        (input.operation !== "enroll" && input.operation !== "recover")
      ) {
        throw invalidInput("operation must be enroll or recover", "capability");
      }
      return detectCapability(input.operation);
    },

    createAndWrapKey,

    async recoverKey(input) {
      const wrappedKeys = prepareRecovery(input);
      const credentialIds = orderedCredentialIds(
        wrappedKeys,
        input.preferredCredentialId,
      );
      const result = await runCeremony("recoverKey", input.signal, (signal) =>
        evaluatePrfCredential(context(profile, timeoutMs), credentialIds, signal),
      );
      recordSuccessfulCredential(result);
      const wrapped = wrappedKeys.find(
        (candidate) => candidate.credentialId === result.credentialId,
      );
      if (!wrapped) throw invalidInput("credential has no matching wrapped key", "recoverKey");
      return {
        credentialId: result.credentialId,
        key: await unwrapKey(profile, result.prfOutput, wrapped),
      };
    },

    async recoverKeyFromCache(input) {
      const wrappedKeys = prepareRecovery(input);
      const cached = loadCachedResult();
      if (!cached) return null;
      const wrapped = wrappedKeys.find(
        (candidate) => candidate.credentialId === cached.credentialId,
      );
      if (!wrapped) return null;
      try {
        return {
          credentialId: cached.credentialId,
          key: await unwrapKey(profile, cached.prfOutput, wrapped),
        };
      } catch {
        return null;
      }
    },

    async rewrapKeyFromCache(input) {
      if (!input || typeof input !== "object") throw invalidInput("input is required");
      validateKey(input.key, "rewrapKeyFromCache");
      const cached = loadCachedResult();
      if (!cached) return null;
      return wrapKey(profile, cached.credentialId, cached.prfOutput, input.key.slice());
    },

    clearLocalState() {
      try {
        config.storage?.clear(copyAndValidateProfile(profile));
      } catch {
        // Storage is best-effort.
      }
    },

    cancelActiveCeremony() {
      const operation = activeCeremony?.operation;
      activeCeremony?.cancel(
        new PasskeyKeyError("cancelled", "the passkey operation was cancelled", {
          operation,
        }),
      );
    },
  };
}
