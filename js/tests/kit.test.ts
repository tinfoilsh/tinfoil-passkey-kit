import { afterEach, describe, expect, it, vi } from "vitest";
import { bufferSourceToArrayBuffer, bytesToBase64Url } from "../../src/codec.js";
import { createPasskeyKeyManager } from "../../src/kit.js";
import { createMemorySecretStore } from "../../src/storage.js";
import type { PasskeyKeyProfile } from "../../src/types.js";

const originalCredentials = navigator.credentials;
const encoder = new TextEncoder();
const profile: PasskeyKeyProfile = {
  id: "test-v1",
  prfInput: encoder.encode("test-prf"),
  hkdfSalt: new Uint8Array(),
  hkdfInfo: encoder.encode("test-kek"),
  keyLengthBytes: 32,
};

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  Object.defineProperty(navigator, "credentials", {
    value: originalCredentials,
    configurable: true,
  });
});

function installCredentials(credentials: Partial<CredentialsContainer>): void {
  Object.defineProperty(navigator, "credentials", {
    value: credentials,
    configurable: true,
  });
}

function credential(options: {
  rawId?: Uint8Array;
  prf?: Uint8Array;
  enabled?: boolean;
  attachment?: AuthenticatorAttachment;
} = {}): PublicKeyCredential {
  const rawId = options.rawId ?? new Uint8Array([1, 2, 3]);
  return {
    rawId: rawId.buffer,
    authenticatorAttachment: options.attachment ?? "platform",
    getClientExtensionResults: () => ({
      prf: {
        enabled: options.enabled ?? true,
        results: options.prf ? { first: options.prf.buffer } : undefined,
      },
    }),
  } as unknown as PublicKeyCredential;
}

function manager(options: { timeoutMs?: number; secretStore?: ReturnType<typeof createMemorySecretStore> } = {}) {
  return createPasskeyKeyManager({
    rpId: "example.com",
    rpName: "Example",
    profile,
    ...options,
  });
}

const user = { id: new Uint8Array([9, 8, 7]), name: "person@example.com" };

describe("profile and storage", () => {
  it("defensively copies profile and user handle inputs", async () => {
    const mutableProfile = { ...profile, prfInput: profile.prfInput.slice() };
    const keyManager = createPasskeyKeyManager({
      rpId: "example.com",
      rpName: "Example",
      profile: mutableProfile,
    });
    mutableProfile.prfInput[0] = 0;
    const exposed = keyManager.profile;
    exposed.hkdfInfo[0] = 0;
    expect(keyManager.profile.prfInput).toEqual(profile.prfInput);
    expect(keyManager.profile.hkdfInfo).toEqual(profile.hkdfInfo);

    const create = vi.fn(async (options: CredentialCreationOptions) => {
      const request = options.publicKey!;
      expect(new Uint8Array(bufferSourceToArrayBuffer(request.user.id))).toEqual(
        new Uint8Array([9, 8, 7]),
      );
      return credential({ prf: new Uint8Array(32) });
    });
    installCredentials({ create } as Partial<CredentialsContainer>);
    const handle = user.id.slice();
    const pending = keyManager.createCredential({ ...user, id: handle });
    handle[0] = 0;
    await pending;
  });

  it("stores nothing by default and enables cache only with an explicit secret store", async () => {
    const prf = new Uint8Array(32).fill(3);
    installCredentials({ create: vi.fn(async () => credential({ prf })) });
    const withoutStore = manager();
    const enrolled = await withoutStore.enrollKey({ user });
    await expect(withoutStore.unlockKeyFromCache([enrolled.wrappedKey])).resolves.toBeNull();

    const secretStore = createMemorySecretStore();
    const withStore = manager({ secretStore });
    const cachedEnrollment = await withStore.enrollKey({ user });
    await expect(withStore.unlockKeyFromCache([cachedEnrollment.wrappedKey])).resolves.toMatchObject({
      credentialId: cachedEnrollment.credentialId,
    });
    await expect(withStore.rewrapKeyFromCache(new Uint8Array(32))).resolves.not.toBeNull();
  });
});

describe("ceremony lifecycle", () => {
  it("rejects an already-aborted signal without starting a ceremony", async () => {
    const create = vi.fn();
    installCredentials({ create } as Partial<CredentialsContainer>);
    const controller = new AbortController();
    controller.abort("stop");
    await expect(manager().createCredential(user, { signal: controller.signal })).rejects.toMatchObject({
      code: "cancelledOrUnavailable",
      operation: "createCredential",
    });
    expect(create).not.toHaveBeenCalled();
  });

  it("aborts an active ceremony and releases the operation slot", async () => {
    const create = vi.fn((options: CredentialCreationOptions) =>
      new Promise((_, reject) => {
        options.signal?.addEventListener("abort", () => reject(new DOMException("", "AbortError")));
      }),
    );
    installCredentials({ create } as Partial<CredentialsContainer>);
    const keyManager = manager();
    const controller = new AbortController();
    const first = keyManager.createCredential(user, { signal: controller.signal });
    await expect(keyManager.createCredential(user)).rejects.toMatchObject({
      code: "operationInProgress",
    });
    controller.abort();
    await expect(first).rejects.toMatchObject({ code: "cancelledOrUnavailable" });

    create.mockResolvedValueOnce(credential({ prf: new Uint8Array(32) }));
    await expect(keyManager.createCredential(user)).resolves.toBeDefined();
  });

  it("aborts on timeout, ignores late completion, and permits the next operation", async () => {
    vi.useFakeTimers();
    let resolveLate!: (value: PublicKeyCredential) => void;
    let ceremonySignal: AbortSignal | undefined;
    const create = vi
      .fn()
      .mockImplementationOnce(
        (options: CredentialCreationOptions) =>
          new Promise((resolve) => {
            ceremonySignal = options.signal;
            resolveLate = resolve;
          }),
      )
      .mockResolvedValueOnce(credential({ prf: new Uint8Array(32) }));
    installCredentials({ create } as Partial<CredentialsContainer>);
    const secretStore = createMemorySecretStore();
    const keyManager = manager({ timeoutMs: 25, secretStore });
    const first = keyManager.createCredential(user);
    first.catch(() => {});
    await vi.advanceTimersByTimeAsync(25);
    await expect(first).rejects.toMatchObject({ code: "timeout" });
    expect(ceremonySignal?.aborted).toBe(true);
    resolveLate(credential({ prf: new Uint8Array(32).fill(9) }));
    await Promise.resolve();
    await expect(
      secretStore.list({ rpId: "example.com", profileId: profile.id }),
    ).resolves.toEqual([]);
    await expect(keyManager.createCredential(user)).resolves.toBeDefined();
  });

  it("reports NotAllowedError honestly", async () => {
    installCredentials({
      create: vi.fn(async () => {
        throw new DOMException("", "NotAllowedError");
      }),
    });
    await expect(manager().createCredential(user)).rejects.toMatchObject({
      code: "cancelledOrUnavailable",
    });
  });
});

describe("unlock behavior", () => {
  it("orders the preferred credential first", async () => {
    const get = vi.fn(async (options: CredentialRequestOptions) => {
      const ids = options.publicKey!.allowCredentials!.map((item) =>
        bytesToBase64Url(new Uint8Array(bufferSourceToArrayBuffer(item.id))),
      );
      expect(ids).toEqual(["Ag", "AQ"]);
      return credential({ rawId: new Uint8Array([2]), prf: new Uint8Array(32) });
    });
    installCredentials({ get } as Partial<CredentialsContainer>);
    await manager().evaluateCredential(["AQ", "Ag"], { preferredCredentialId: "Ag" });
  });

  it("allows unlock attempts when platform enrollment is unavailable", async () => {
    installCredentials({ get: vi.fn() } as Partial<CredentialsContainer>);
    vi.stubGlobal("PublicKeyCredential", {
      isUserVerifyingPlatformAuthenticatorAvailable: vi.fn(async () => false),
    });
    const keyManager = manager();
    await expect(keyManager.canEnrollPlatformPasskey()).resolves.toBe(false);
    await expect(keyManager.canAttemptPasskeyUnlock()).resolves.toBe(true);
  });
});
