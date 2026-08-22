import { afterEach, describe, expect, it, vi } from "vitest";
import { bufferSourceToArrayBuffer, bytesToBase64Url } from "../../src/codec.js";
import { createPasskeyKeyManager } from "../../src/kit.js";
import {
  createInsecureBrowserLocalStoragePasskeyKeyStorage,
  createMemoryPasskeyKeyStorage,
} from "../../src/storage.js";
import type { PasskeyKeyProfile, WrappedKey } from "../../src/types.js";

const originalCredentials = navigator.credentials;
const encoder = new TextEncoder();
const profile: PasskeyKeyProfile = {
  version: 1,
  relyingPartyId: "example.com",
  prfSalt: encoder.encode("test-prf"),
  hkdfInfo: encoder.encode("test-kek"),
};
const user = { id: new Uint8Array([9, 8, 7]), name: "person@example.com" };

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

function createManager(
  options: Partial<Parameters<typeof createPasskeyKeyManager>[0]> = {},
) {
  return createPasskeyKeyManager({
    profile,
    relyingPartyName: "Example",
    ...options,
  });
}

async function createFixture(storage = createMemoryPasskeyKeyStorage()) {
  const prf = new Uint8Array(32).fill(3);
  const rawId = new Uint8Array([1, 2, 3]);
  installCredentials({
    create: vi.fn(async () => credential({ rawId, prf, attachment: "platform" })),
    get: vi.fn(async () => credential({ rawId, prf, attachment: "cross-platform" })),
  });
  const manager = createManager({ storage });
  const key = new Uint8Array(32).map((_, index) => index);
  const created = await manager.createAndWrapKey({ user, key });
  return { created, key, manager, storage };
}

describe("contract flows", () => {
  it("creates and recovers a wrapped key", async () => {
    const { created, key, manager } = await createFixture();
    const recovered = await manager.recoverKey({
      wrappedKeys: [created.wrappedKey],
    });
    expect(recovered).toEqual({ credentialId: created.credentialId, key });
  });

  it("uses profile RP fields and snapshots profile and user bytes", async () => {
    const mutableProfile = {
      ...profile,
      prfSalt: profile.prfSalt.slice(),
      hkdfInfo: profile.hkdfInfo.slice(),
    };
    const mutableUser = { ...user, id: user.id.slice() };
    const create = vi.fn(async (options: CredentialCreationOptions) => {
      expect(options.publicKey?.rp).toEqual({ id: "example.com", name: "Example" });
      expect(
        new Uint8Array(bufferSourceToArrayBuffer(options.publicKey!.user.id)),
      ).toEqual(user.id);
      const first = (
        options.publicKey!.extensions as unknown as {
          prf: { eval: { first: Uint8Array } };
        }
      ).prf.eval.first;
      expect(first).toEqual(profile.prfSalt);
      return credential({ prf: new Uint8Array(32) });
    });
    installCredentials({ create } as Partial<CredentialsContainer>);
    const pending = createManager({ profile: mutableProfile }).createAndWrapKey({
      user: mutableUser,
      key: new Uint8Array(32),
    });
    mutableProfile.prfSalt[0] = 0;
    mutableProfile.hkdfInfo[0] = 0;
    mutableUser.id[0] = 0;
    await pending;
  });

  it("has no storage by default and cache methods match credential IDs", async () => {
    const prf = new Uint8Array(32).fill(4);
    installCredentials({ create: vi.fn(async () => credential({ prf })) });
    const noStorage = createManager();
    const created = await noStorage.createAndWrapKey({
      user,
      key: new Uint8Array(32),
    });
    await expect(
      noStorage.recoverKeyFromCache({ wrappedKeys: [created.wrappedKey] }),
    ).resolves.toBeNull();

    const { manager, storage, created: cached } = await createFixture();
    expect(storage.loadCachedPRFResult()?.credentialId).toBe(cached.credentialId);
    const stranger: WrappedKey = { ...cached.wrappedKey, credentialId: "BAUG" };
    await expect(
      manager.recoverKeyFromCache({ wrappedKeys: [stranger] }),
    ).resolves.toBeNull();
    await expect(
      manager.recoverKeyFromCache({ wrappedKeys: [cached.wrappedKey] }),
    ).resolves.toMatchObject({ credentialId: cached.credentialId });
  });

  it("rewraps only with the latest successful cached credential", async () => {
    const storage = createMemoryPasskeyKeyStorage();
    const firstPrf = new Uint8Array(32).fill(1);
    const secondPrf = new Uint8Array(32).fill(2);
    const create = vi
      .fn()
      .mockResolvedValueOnce(
        credential({ rawId: new Uint8Array([1]), prf: firstPrf }),
      )
      .mockResolvedValueOnce(
        credential({ rawId: new Uint8Array([2]), prf: secondPrf }),
      );
    installCredentials({ create } as Partial<CredentialsContainer>);
    const manager = createManager({ storage });
    await manager.createAndWrapKey({ user, key: new Uint8Array(32) });
    await manager.createAndWrapKey({ user, key: new Uint8Array(32) });
    const rewrapped = await manager.rewrapKeyFromCache({
      key: new Uint8Array(32),
    });
    expect(rewrapped?.credentialId).toBe("Ag");
  });

  it("rejects the latest cached credential from another profile", async () => {
    const otherProfile: PasskeyKeyProfile = {
      ...profile,
      hkdfInfo: encoder.encode("other-kek"),
    };
    const storage = createMemoryPasskeyKeyStorage();
    const create = vi
      .fn()
      .mockResolvedValueOnce(
        credential({ rawId: new Uint8Array([1]), prf: new Uint8Array(32).fill(1) }),
      )
      .mockResolvedValueOnce(
        credential({ rawId: new Uint8Array([2]), prf: new Uint8Array(32).fill(2) }),
      );
    const get = vi.fn();
    installCredentials({ create, get } as Partial<CredentialsContainer>);
    const firstManager = createManager({ profile, storage });
    const secondManager = createManager({ profile: otherProfile, storage });
    const first = await firstManager.createAndWrapKey({
      user,
      key: new Uint8Array(32),
    });
    await secondManager.createAndWrapKey({ user, key: new Uint8Array(32) });

    expect(storage.loadCachedPRFResult()?.credentialId).toBe("Ag");
    await expect(
      firstManager.rewrapKeyFromCache({ key: new Uint8Array(32) }),
    ).resolves.toBeNull();
    await expect(
      secondManager.rewrapKeyFromCache({ key: new Uint8Array(32) }),
    ).resolves.toMatchObject({ credentialId: "Ag" });
    await expect(
      secondManager.recoverKey({ wrappedKeys: [first.wrappedKey] }),
    ).rejects.toMatchObject({ category: "invalid_input" });
    expect(get).not.toHaveBeenCalled();
  });

  it("rejects a cached record carrying a different profile", async () => {
    const otherProfile: PasskeyKeyProfile = {
      ...profile,
      prfSalt: encoder.encode("other-prf"),
    };
    const manager = createManager({
      storage: {
        loadCachedPRFResult: () => ({
          profile: otherProfile,
          credentialId: "AQ",
          prfOutput: new Uint8Array(32),
        }),
        saveCachedPRFResult: () => {},
        loadLocalCredentialId: () => null,
        saveLocalCredentialId: () => {},
        clear: () => {},
      },
    });
    await expect(
      manager.rewrapKeyFromCache({ key: new Uint8Array(32) }),
    ).resolves.toBeNull();
  });

  it("namespaces browser storage without changing the storage interface", () => {
    const first = createInsecureBrowserLocalStoragePasskeyKeyStorage("first");
    const second = createInsecureBrowserLocalStoragePasskeyKeyStorage("second");
    const cached = {
      profile: {
        ...profile,
        prfSalt: profile.prfSalt.slice(),
        hkdfInfo: profile.hkdfInfo.slice(),
      },
      credentialId: "AQ",
      prfOutput: new Uint8Array(32).fill(7),
    };
    first.saveCachedPRFResult(cached);
    first.saveLocalCredentialId("AQ");
    cached.profile.prfSalt[0] = 0;
    cached.prfOutput[0] = 0;

    expect(first.loadCachedPRFResult()).toMatchObject({ credentialId: "AQ" });
    expect(first.loadCachedPRFResult()?.prfOutput[0]).toBe(7);
    expect(first.loadLocalCredentialId()).toBe("AQ");
    expect(second.loadCachedPRFResult()).toBeNull();
    expect(second.loadLocalCredentialId()).toBeNull();
    first.clear();
    second.clear();
  });

  it("catches every host storage operation independently", async () => {
    installCredentials({
      create: vi.fn(async () => credential({ prf: new Uint8Array(32) })),
    });
    const manager = createManager({
      storage: {
        loadCachedPRFResult: () => {
          throw new Error("load cache");
        },
        saveCachedPRFResult: () => {
          throw new Error("save cache");
        },
        loadLocalCredentialId: () => {
          throw new Error("load local");
        },
        saveLocalCredentialId: () => {
          throw new Error("save local");
        },
        clear: () => {
          throw new Error("clear");
        },
      },
    });
    const created = await manager.createAndWrapKey({
      user,
      key: new Uint8Array(32),
    });
    await expect(
      manager.recoverKeyFromCache({ wrappedKeys: [created.wrappedKey] }),
    ).resolves.toBeNull();
    await expect(
      manager.rewrapKeyFromCache({ key: new Uint8Array(32) }),
    ).resolves.toBeNull();
    expect(() => manager.clearLocalState()).not.toThrow();
  });

  it("orders an explicit or stored preferred credential first", async () => {
    const get = vi.fn(async (options: CredentialRequestOptions) => {
      const ids = options.publicKey!.allowCredentials!.map((item) =>
        bytesToBase64Url(
          new Uint8Array(bufferSourceToArrayBuffer(item.id)),
        ),
      );
      expect(ids).toEqual(["Ag", "AQ"]);
      return credential({ rawId: new Uint8Array([2]), prf: new Uint8Array(32) });
    });
    installCredentials({ get } as Partial<CredentialsContainer>);
    const wrappedKeys = ["AQ", "Ag"].map(
      (credentialId): WrappedKey => ({
        profile,
        credentialId,
        kekIvHex: "00".repeat(12),
        wrappedKeyHex: "00".repeat(48),
      }),
    );
    await expect(
      createManager().recoverKey({
        wrappedKeys,
        preferredCredentialId: "Ag",
      }),
    ).rejects.toMatchObject({ category: "operation_failed" });
    expect(get).toHaveBeenCalledOnce();
  });
});

describe("capability", () => {
  it("separates platform enrollment from general recovery", async () => {
    installCredentials({ create: vi.fn(), get: vi.fn() });
    vi.stubGlobal("PublicKeyCredential", {
      isUserVerifyingPlatformAuthenticatorAvailable: vi.fn(async () => false),
      getClientCapabilities: vi.fn(async () => ({ "extension:prf": true })),
    });
    const manager = createManager();
    await expect(manager.capability({ operation: "enroll" })).resolves.toBe(
      "unsupported",
    );
    await expect(manager.capability({ operation: "recover" })).resolves.toBe(
      "supported",
    );
  });

  it("returns unknown when PRF capability cannot be determined", async () => {
    installCredentials({ create: vi.fn(), get: vi.fn() });
    vi.stubGlobal("PublicKeyCredential", {
      isUserVerifyingPlatformAuthenticatorAvailable: vi.fn(async () => true),
    });
    await expect(
      createManager().capability({ operation: "enroll" }),
    ).resolves.toBe("unknown");
  });

  it("uses the standardized extension:prf capability", async () => {
    installCredentials({ create: vi.fn(), get: vi.fn() });
    vi.stubGlobal("PublicKeyCredential", {
      isUserVerifyingPlatformAuthenticatorAvailable: vi.fn(async () => true),
      getClientCapabilities: vi.fn(async () => ({ "extension:prf": true })),
    });
    await expect(
      createManager().capability({ operation: "enroll" }),
    ).resolves.toBe("supported");

    vi.stubGlobal("PublicKeyCredential", {
      isUserVerifyingPlatformAuthenticatorAvailable: vi.fn(async () => true),
      getClientCapabilities: vi.fn(async () => ({ "extension-prf": true })),
    });
    await expect(
      createManager().capability({ operation: "enroll" }),
    ).resolves.toBe("unknown");
  });
});

describe("credential evaluation", () => {
  it("returns a defensive raw PRF result and caches only with configured storage", async () => {
    const rawPrf = new Uint8Array(32).map((_, index) => index);
    const get = vi.fn(async () =>
      credential({ rawId: new Uint8Array([1]), prf: rawPrf }),
    );
    installCredentials({ get } as Partial<CredentialsContainer>);
    localStorage.clear();
    const withoutStorage = createManager();
    const uncached = await withoutStorage.evaluateCredential({ credentialIds: ["AQ"] });
    expect(uncached).toEqual({
      credentialId: "AQ",
      prfResult: { output: new Uint8Array(32).map((_, index) => index) },
    });
    expect(localStorage.length).toBe(0);

    const storage = createMemoryPasskeyKeyStorage();
    const withStorage = createManager({ storage });
    const evaluated = await withStorage.evaluateCredential({ credentialIds: ["AQ"] });
    rawPrf[0] = 99;
    evaluated.prfResult.output[1] = 99;
    const cached = storage.loadCachedPRFResult();
    expect(cached?.prfOutput[0]).toBe(0);
    expect(cached?.prfOutput[1]).toBe(1);
    expect(cached?.prfOutput).not.toBe(evaluated.prfResult.output);
  });

  it("supports interactive evaluation and rejects immediatelyAvailable before a ceremony", async () => {
    const get = vi.fn(async () =>
      credential({ rawId: new Uint8Array([1]), prf: new Uint8Array(32) }),
    );
    installCredentials({ get } as Partial<CredentialsContainer>);
    const manager = createManager();
    await expect(
      manager.evaluateCredential({
        credentialIds: ["AQ"],
        interaction: "immediatelyAvailable",
      }),
    ).rejects.toMatchObject({ category: "unsupported" });
    await expect(
      manager.recoverKey({
        wrappedKeys: [
          {
            profile,
            credentialId: "AQ",
            kekIvHex: "00".repeat(12),
            wrappedKeyHex: "00".repeat(48),
          },
        ],
        interaction: "immediatelyAvailable",
      }),
    ).rejects.toMatchObject({ category: "unsupported" });
    expect(get).not.toHaveBeenCalled();
    await expect(
      manager.evaluateCredential({
        credentialIds: ["AQ"],
        interaction: "interactive",
      }),
    ).resolves.toMatchObject({ credentialId: "AQ" });
    expect(get).toHaveBeenCalledOnce();
  });

  it("orders the preferred credential for direct evaluation", async () => {
    const get = vi.fn(async (options: CredentialRequestOptions) => {
      const ids = options.publicKey!.allowCredentials!.map((item) =>
        bytesToBase64Url(new Uint8Array(bufferSourceToArrayBuffer(item.id))),
      );
      expect(ids).toEqual(["Ag", "AQ"]);
      return credential({ rawId: new Uint8Array([2]), prf: new Uint8Array(32) });
    });
    installCredentials({ get } as Partial<CredentialsContainer>);
    await createManager().evaluateCredential({
      credentialIds: ["AQ", "Ag"],
      preferredCredentialId: "Ag",
    });
  });
});

describe("ceremony lifecycle", () => {
  it("maps NotAllowed to cancelled with its documented ambiguity", async () => {
    installCredentials({
      create: vi.fn(async () => {
        throw new DOMException("", "NotAllowedError");
      }),
    });
    await expect(
      createManager().createAndWrapKey({
        user,
        key: new Uint8Array(32),
      }),
    ).rejects.toMatchObject({
      category: "cancelled",
      message: expect.stringContaining("no eligible credential"),
    });
  });

  it("rejects concurrent ceremonies and releases after caller cancellation", async () => {
    const create = vi.fn((options: CredentialCreationOptions) =>
      new Promise((_, reject) => {
        options.signal?.addEventListener("abort", () =>
          reject(new DOMException("", "AbortError")),
        );
      }),
    );
    installCredentials({ create } as Partial<CredentialsContainer>);
    const manager = createManager();
    const controller = new AbortController();
    const first = manager.createAndWrapKey({
      user,
      key: new Uint8Array(32),
      signal: controller.signal,
    });
    await expect(
      manager.createAndWrapKey({ user, key: new Uint8Array(32) }),
    ).rejects.toMatchObject({ category: "operation_in_progress" });
    controller.abort();
    await expect(first).rejects.toMatchObject({ category: "cancelled" });
    create.mockResolvedValueOnce(credential({ prf: new Uint8Array(32) }));
    await expect(
      manager.createAndWrapKey({ user, key: new Uint8Array(32) }),
    ).resolves.toBeDefined();
  });

  it("supports explicit cancellation", async () => {
    let ceremonySignal: AbortSignal | undefined;
    installCredentials({
      create: vi.fn(
        (options: CredentialCreationOptions) =>
          new Promise(() => {
            ceremonySignal = options.signal;
          }),
      ),
    } as Partial<CredentialsContainer>);
    const manager = createManager();
    const pending = manager.createAndWrapKey({
      user,
      key: new Uint8Array(32),
    });
    manager.cancelActiveCeremony();
    await expect(pending).rejects.toMatchObject({ category: "cancelled" });
    expect(ceremonySignal?.aborted).toBe(true);
  });

  it("aborts on timeout, ignores late completion, and permits the next ceremony", async () => {
    vi.useFakeTimers();
    let resolveLate!: (value: PublicKeyCredential) => void;
    let ceremonySignal: AbortSignal | undefined;
    const storage = createMemoryPasskeyKeyStorage();
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
    const manager = createManager({ timeoutMs: 25, storage });
    const first = manager.createAndWrapKey({
      user,
      key: new Uint8Array(32),
    });
    first.catch(() => {});
    await vi.advanceTimersByTimeAsync(25);
    await expect(first).rejects.toMatchObject({ category: "timeout" });
    expect(ceremonySignal?.aborted).toBe(true);
    resolveLate(credential({ prf: new Uint8Array(32).fill(9) }));
    await Promise.resolve();
    expect(storage.loadCachedPRFResult()).toBeNull();
    await expect(
      manager.createAndWrapKey({ user, key: new Uint8Array(32) }),
    ).resolves.toBeDefined();
  });
});
