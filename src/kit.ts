import {
  copyAndValidateProfile,
  profilesEqual,
  unwrapKey,
  validateCredentialId,
  validateKey,
  validateWrappedKey,
  wrapKey,
} from "./crypto.js";
import { invalidInput, PasskeyKeyError } from "./errors.js";
import { capability as detectCapability } from "./support.js";
import type { CachedPRFResult } from "./storage.js";
import type {
  CreateAndWrapKeyInput,
  EvaluateCredentialInput,
  PasskeyKeyManager,
  PasskeyKeyManagerConfig,
  PasskeyUser,
  RecoverKeyInput,
  UnwrapKeyWithPRFResultInput,
  WrapKeyWithPRFResultInput,
  WrappedKey,
} from "./types.js";
import {
  createPrfCredential,
  evaluatePrfCredential,
  type CeremonyContext,
  type InternalPrfResult,
} from "./webauthn.js";

const DEFAULT_TIMEOUT_MS = 60_000;
const MAX_TIMEOUT_MS = 2_147_483_647;

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

function context(
  profile: PasskeyKeyProfileSnapshot,
  relyingPartyName: string,
  timeoutMs: number,
): CeremonyContext {
  return {
    rpId: profile.relyingPartyId,
    rpName: relyingPartyName,
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
  return wrappedKeys.map((wrapped) => {
    if (!wrapped || typeof wrapped !== "object") {
      throw invalidInput("wrapped key is required");
    }
    return {
      ...wrapped,
      profile: copyAndValidateProfile(wrapped.profile),
    };
  });
}

export function createPasskeyKeyManager(
  config: PasskeyKeyManagerConfig,
): PasskeyKeyManager {
  if (!config || typeof config !== "object") throw invalidInput("manager config is required");
  const profile = copyAndValidateProfile(config.profile);
  if (
    typeof config.relyingPartyName !== "string" ||
    config.relyingPartyName.length === 0
  ) {
    throw invalidInput("relyingPartyName must be a non-empty string");
  }
  const relyingPartyName = config.relyingPartyName;
  if (
    config.timeoutMs !== undefined &&
    (!Number.isFinite(config.timeoutMs) ||
      config.timeoutMs <= 0 ||
      config.timeoutMs > MAX_TIMEOUT_MS)
  ) {
    throw invalidInput(`timeoutMs must be between 1 and ${MAX_TIMEOUT_MS}`);
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
        config.storage?.saveLocalCredentialId(result.credentialId);
      } catch {
        // Storage is best-effort and cannot invalidate a successful ceremony.
      }
    }
  }

  function loadCachedResult(): CachedPRFResult | null {
    let result: CachedPRFResult | null;
    try {
      result = config.storage?.loadCachedPRFResult() ?? null;
    } catch {
      return null;
    }
    if (!result) return null;
    let cachedProfile: PasskeyKeyProfileSnapshot;
    try {
      cachedProfile = copyAndValidateProfile(result.profile);
      validateCredentialId(result.credentialId);
    } catch {
      return null;
    }
    if (
      !profilesEqual(cachedProfile, profile) ||
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
      return config.storage?.loadLocalCredentialId() ?? null;
    } catch {
      return null;
    }
  }

  function orderedCredentialIds(
    credentialIds: string[],
    preferredCredentialId?: string,
  ): string[] {
    if (!Array.isArray(credentialIds) || credentialIds.length === 0) {
      throw invalidInput("at least one credentialId is required");
    }
    const unique = [...new Set(credentialIds)];
    for (const credentialId of unique) {
      validateCredentialId(credentialId);
    }
    const preferred = preferredCredentialId ?? loadPreferredCredentialId();
    if (!preferred || !unique.includes(preferred)) return unique;
    return [preferred, ...unique.filter((credentialId) => credentialId !== preferred)];
  }

  function copyPRFOutput(
    prfResult: { output: Uint8Array },
    operation: string,
  ): Uint8Array {
    if (
      !prfResult ||
      typeof prfResult !== "object" ||
      !(prfResult.output instanceof Uint8Array) ||
      prfResult.output.length !== 32
    ) {
      throw invalidInput("prfResult.output must be exactly 32 bytes", operation);
    }
    return prfResult.output.slice();
  }

  async function wrapKeyWithPRFResult(
    input: WrapKeyWithPRFResultInput,
    operation = "wrapKeyWithPRFResult",
  ): Promise<WrappedKey> {
    if (!input || typeof input !== "object") throw invalidInput("input is required", operation);
    validateKey(input.keyMaterial, operation);
    validateCredentialId(input.credentialId);
    const keyMaterial = input.keyMaterial.slice();
    const prfOutput = copyPRFOutput(input.prfResult, operation);
    return wrapKey(
      profile,
      input.credentialId,
      prfOutput,
      keyMaterial,
      operation,
    );
  }

  async function unwrapKeyWithPRFResult(
    input: UnwrapKeyWithPRFResultInput,
    operation = "unwrapKeyWithPRFResult",
  ): Promise<Uint8Array> {
    if (!input || typeof input !== "object") throw invalidInput("input is required", operation);
    const wrappedKey = {
      ...input.wrappedKey,
      profile: copyAndValidateProfile(input.wrappedKey?.profile),
    };
    validateWrappedKey(wrappedKey, profile);
    const prfOutput = copyPRFOutput(input.prfResult, operation);
    return unwrapKey(profile, prfOutput, wrappedKey, operation);
  }

  async function createAndWrapKey(input: CreateAndWrapKeyInput) {
    if (!input || typeof input !== "object") throw invalidInput("input is required");
    validateKey(input.key, "createAndWrapKey");
    const key = input.key.slice();
    const user = copyUser(input.user);
    const result = await runCeremony("createAndWrapKey", input.signal, (signal) =>
      createPrfCredential(context(profile, relyingPartyName, timeoutMs), user, signal),
    );
    recordSuccessfulCredential(result);
    const wrappedKey = await wrapKeyWithPRFResult(
      {
        keyMaterial: key,
        credentialId: result.credentialId,
        prfResult: { output: result.prfOutput },
      },
      "createAndWrapKey",
    );
    return { credentialId: result.credentialId, wrappedKey };
  }

  function prepareRecovery(input: RecoverKeyInput) {
    if (!input || typeof input !== "object") throw invalidInput("input is required");
    const wrappedKeys = copyWrappedKeys(input.wrappedKeys);
    for (const wrapped of wrappedKeys) validateWrappedKey(wrapped, profile);
    return wrappedKeys;
  }

  async function evaluateCredential(
    input: EvaluateCredentialInput,
    operation = "evaluateCredential",
  ) {
    if (!input || typeof input !== "object") throw invalidInput("input is required");
    const interaction = input.interaction ?? "interactive";
    if (interaction !== "interactive" && interaction !== "immediatelyAvailable") {
      throw invalidInput("interaction must be interactive or immediatelyAvailable", operation);
    }
    if (interaction === "immediatelyAvailable") {
      throw new PasskeyKeyError(
        "unsupported",
        "immediatelyAvailable credential evaluation is not supported in browsers",
        { operation },
      );
    }
    const credentialIds = orderedCredentialIds(
      input.credentialIds,
      input.preferredCredentialId,
    );
    const result = await runCeremony(operation, input.signal, (signal) =>
      evaluatePrfCredential(
        context(profile, relyingPartyName, timeoutMs),
        credentialIds,
        signal,
      ),
    );
    recordSuccessfulCredential(result);
    return {
      credentialId: result.credentialId,
      prfResult: { output: result.prfOutput.slice() },
    };
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

    evaluateCredential(input) {
      return evaluateCredential(input);
    },

    wrapKeyWithPRFResult(input) {
      return wrapKeyWithPRFResult(input);
    },

    unwrapKeyWithPRFResult(input) {
      return unwrapKeyWithPRFResult(input);
    },

    async recoverKey(input) {
      const wrappedKeys = prepareRecovery(input);
      const result = await evaluateCredential(
        {
          credentialIds: wrappedKeys.map((wrapped) => wrapped.credentialId),
          preferredCredentialId: input.preferredCredentialId,
          signal: input.signal,
          interaction: input.interaction,
        },
        "recoverKey",
      );
      const wrapped = wrappedKeys.find(
        (candidate) => candidate.credentialId === result.credentialId,
      );
      if (!wrapped) throw invalidInput("credential has no matching wrapped key", "recoverKey");
      return {
        credentialId: result.credentialId,
        key: await unwrapKeyWithPRFResult(
          { wrappedKey: wrapped, prfResult: result.prfResult },
          "recoverKey",
        ),
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
          key: await unwrapKeyWithPRFResult(
            {
              wrappedKey: wrapped,
              prfResult: { output: cached.prfOutput },
            },
            "recoverKeyFromCache",
          ),
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
      return wrapKeyWithPRFResult(
        {
          keyMaterial: input.key,
          credentialId: cached.credentialId,
          prfResult: { output: cached.prfOutput },
        },
        "rewrapKeyFromCache",
      );
    },

    clearLocalState() {
      try {
        config.storage?.clear();
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
