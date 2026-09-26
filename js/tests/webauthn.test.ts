import { afterEach, describe, expect, it, vi } from "vitest";
import { createPasskeyKeyManager } from "../../src/kit.js";
import { createMemoryPasskeyKeyStorage } from "../../src/storage.js";
import type { PasskeyKeyProfile } from "../../src/types.js";

const PRF_OUTPUT_BYTES = 32;
const MAX_BYTE_VALUE = 255;
const VIEW_OFFSET_BYTES = 4;
const CREDENTIAL_ID = "AQID";
const originalCredentials = navigator.credentials;
const encoder = new TextEncoder();
const profile: PasskeyKeyProfile = {
  version: 1,
  relyingPartyId: "example.com",
  prfSalt: encoder.encode("test-prf"),
  hkdfInfo: encoder.encode("test-kek"),
};
const user = { id: new Uint8Array([9, 8, 7]), name: "person@example.com" };
const prf = Uint8Array.from({ length: PRF_OUTPUT_BYTES }, (_, index) =>
  index === PRF_OUTPUT_BYTES - 1 ? MAX_BYTE_VALUE : index,
);
const key = prf.slice().reverse();

afterEach(() => {
  vi.restoreAllMocks();
  Object.defineProperty(navigator, "credentials", {
    value: originalCredentials,
    configurable: true,
  });
});

function credential(first: unknown): PublicKeyCredential {
  return {
    rawId: new Uint8Array([1, 2, 3]).buffer,
    authenticatorAttachment: "platform",
    getClientExtensionResults: () => ({
      prf: { enabled: true, results: { first } },
    }),
  } as unknown as PublicKeyCredential;
}

function installPrf(first: unknown, followUp = false): void {
  Object.defineProperty(navigator, "credentials", {
    value: {
      create: vi.fn(async () => credential(followUp ? undefined : first)),
      get: vi.fn(async () => credential(first)),
    },
    configurable: true,
  });
}

function createManager() {
  const storage = createMemoryPasskeyKeyStorage();
  const manager = createPasskeyKeyManager({
    profile,
    relyingPartyName: "Example",
    storage,
  });
  return { manager, storage };
}

describe("WebAuthn PRF output", () => {
  it("recovers an existing buffer-backed key with a plain byte array", async () => {
    const { manager, storage } = createManager();
    installPrf(prf.slice().buffer);
    const { wrappedKey } = await manager.createAndWrapKey({ user, key });
    manager.clearLocalState();

    installPrf(Array.from(prf));
    await expect(manager.recoverKey({ wrappedKeys: [wrappedKey] })).resolves.toEqual({
      credentialId: CREDENTIAL_ID,
      key,
    });
    expect(storage.loadCachedPRFResult()?.prfOutput).toEqual(prf);
    await expect(
      manager.recoverKeyFromCache({ wrappedKeys: [wrappedKey] }),
    ).resolves.toEqual({ credentialId: CREDENTIAL_ID, key });
  });

  it.each([
    { label: "during creation", followUp: false },
    { label: "during follow-up authentication", followUp: true },
  ])("enrolls with a plain byte array $label", async ({ followUp }) => {
    const { manager } = createManager();
    installPrf(Object.freeze(Array.from(prf)), followUp);
    const { wrappedKey } = await manager.createAndWrapKey({ user, key });

    await expect(
      manager.unwrapKeyWithPRFResult({ wrappedKey, prfResult: { output: prf } }),
    ).resolves.toEqual(key);
    installPrf(prf.slice().buffer);
    await expect(manager.recoverKey({ wrappedKeys: [wrappedKey] })).resolves.toEqual({
      credentialId: CREDENTIAL_ID,
      key,
    });
  });

  it.each([
    { label: "ArrayBuffer", output: (bytes: Uint8Array) => bytes.slice().buffer },
    { label: "Uint8Array", output: (bytes: Uint8Array) => bytes.slice() },
    { label: "offset Uint8Array", output: (bytes: Uint8Array) => bytes },
    {
      label: "offset DataView",
      output: (bytes: Uint8Array) =>
        new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength),
    },
    {
      label: "offset Uint16Array",
      output: (bytes: Uint8Array) =>
        new Uint16Array(bytes.buffer, bytes.byteOffset, bytes.byteLength / Uint16Array.BYTES_PER_ELEMENT),
    },
    { label: "plain byte array", output: (bytes: Uint8Array) => Array.from(bytes) },
  ])("copies the exact bytes from $label", async ({ output }) => {
    const padded = new Uint8Array(PRF_OUTPUT_BYTES + VIEW_OFFSET_BYTES * 2).fill(MAX_BYTE_VALUE);
    padded.set(prf, VIEW_OFFSET_BYTES);
    const first = output(padded.subarray(VIEW_OFFSET_BYTES, VIEW_OFFSET_BYTES + PRF_OUTPUT_BYTES));
    installPrf(first);
    const { manager, storage } = createManager();
    const evaluated = await manager.evaluateCredential({ credentialIds: [CREDENTIAL_ID] });
    expect(evaluated.prfResult.output).toEqual(prf);

    if (Array.isArray(first)) first.fill(MAX_BYTE_VALUE);
    else if (first instanceof ArrayBuffer) new Uint8Array(first).fill(MAX_BYTE_VALUE);
    else new Uint8Array(first.buffer).fill(MAX_BYTE_VALUE);
    expect(evaluated.prfResult.output).toEqual(prf);
    evaluated.prfResult.output.fill(MAX_BYTE_VALUE);
    expect(storage.loadCachedPRFResult()?.prfOutput).toEqual(prf);
  });

  it.each([0, PRF_OUTPUT_BYTES - 1, PRF_OUTPUT_BYTES + 1])(
    "rejects %i-byte outputs without caching them",
    async (length) => {
      const { manager, storage } = createManager();
      const bytes = new Uint8Array(length);
      for (const first of [Array.from(bytes), bytes.buffer, bytes, new DataView(bytes.buffer)]) {
        installPrf(first);
        await expect(
          manager.evaluateCredential({ credentialIds: [CREDENTIAL_ID] }),
        ).rejects.toMatchObject({ category: "invalid_input" });
        expect(storage.loadCachedPRFResult()).toBeNull();
        expect(storage.loadLocalCredentialId()).toBeNull();
      }
    },
  );

  it.each([
    -1, MAX_BYTE_VALUE + 1, 1.5, NaN, Infinity, -Infinity,
    "1", true, null, undefined, 1n, {}, [1],
  ].map((value) => ({ value })))(
    "rejects a non-byte array element ($value) without coercion",
    async ({ value }) => {
      const first: unknown[] = Array.from(prf);
      first[PRF_OUTPUT_BYTES - 1] = value;
      installPrf(first);
      const { manager, storage } = createManager();
      await expect(
        manager.evaluateCredential({ credentialIds: [CREDENTIAL_ID] }),
      ).rejects.toMatchObject({ category: "invalid_input" });
      expect(storage.loadCachedPRFResult()).toBeNull();
      expect(storage.loadLocalCredentialId()).toBeNull();
    },
  );

  it("validates the copied buffer length even if its metadata is shadowed", async () => {
    const first = new ArrayBuffer(PRF_OUTPUT_BYTES + 1);
    Object.defineProperty(first, "byteLength", { value: PRF_OUTPUT_BYTES });
    installPrf(first);
    const { manager, storage } = createManager();
    await expect(
      manager.evaluateCredential({ credentialIds: [CREDENTIAL_ID] }),
    ).rejects.toMatchObject({ category: "invalid_input" });
    expect(storage.loadCachedPRFResult()).toBeNull();
  });

  it("validates and copies each array element once without using its iterator", async () => {
    const first = Array.from(prf);
    let reads = 0;
    Object.defineProperty(first, "0", {
      get: () => reads++ === 0 ? prf[0] : MAX_BYTE_VALUE + 1,
    });
    first[Symbol.iterator] = () => {
      throw new Error("PRF byte arrays must be read by index");
    };
    installPrf(first);
    const { manager } = createManager();
    const evaluated = await manager.evaluateCredential({ credentialIds: [CREDENTIAL_ID] });
    expect(evaluated.prfResult.output).toEqual(prf);
    expect(reads).toBe(1);
  });

  it("keeps missing PRF results classified as unsupported", async () => {
    const { manager, storage } = createManager();
    for (const first of [undefined, null]) {
      installPrf(first);
      await expect(
        manager.evaluateCredential({ credentialIds: [CREDENTIAL_ID] }),
      ).rejects.toMatchObject({ category: "unsupported" });
      expect(storage.loadCachedPRFResult()).toBeNull();
    }
  });

  it("rejects sparse arrays, including holes filled by inherited values", async () => {
    const sparse = Array.from(prf);
    delete sparse[PRF_OUTPUT_BYTES - 1];
    const inherited = Array.from(prf);
    delete inherited[PRF_OUTPUT_BYTES - 1];
    Object.setPrototypeOf(inherited, Object.assign(Object.create(Array.prototype), {
      [PRF_OUTPUT_BYTES - 1]: MAX_BYTE_VALUE,
    }));
    const { manager } = createManager();
    for (const first of [new Array(PRF_OUTPUT_BYTES), sparse, inherited]) {
      installPrf(first);
      await expect(
        manager.evaluateCredential({ credentialIds: [CREDENTIAL_ID] }),
      ).rejects.toMatchObject({ category: "invalid_input" });
    }
  });

  it("rejects non-buffer objects instead of treating them as byte sources", async () => {
    const { manager } = createManager();
    for (const first of [
      "0".repeat(PRF_OUTPUT_BYTES),
      { ...Array.from(prf), length: PRF_OUTPUT_BYTES },
      { buffer: prf.buffer, byteOffset: 0, byteLength: PRF_OUTPUT_BYTES },
    ]) {
      installPrf(first);
      await expect(
        manager.evaluateCredential({ credentialIds: [CREDENTIAL_ID] }),
      ).rejects.toMatchObject({ category: "invalid_input" });
    }
  });

  it.each([false, true])(
    "preserves cached results and releases failed enrollment (follow-up: %s)",
    async (followUp) => {
      const { manager, storage } = createManager();
      installPrf(prf.slice().buffer);
      await manager.evaluateCredential({ credentialIds: [CREDENTIAL_ID] });
      const cached = storage.loadCachedPRFResult();
      const invalid = Array.from(prf);
      invalid[0] = MAX_BYTE_VALUE + 1;
      installPrf(invalid, followUp);
      await expect(manager.createAndWrapKey({ user, key })).rejects.toMatchObject({
        category: "invalid_input",
      });
      expect(storage.loadCachedPRFResult()).toEqual(cached);

      installPrf(Array.from(prf), followUp);
      const { wrappedKey } = await manager.createAndWrapKey({ user, key });
      await expect(
        manager.unwrapKeyWithPRFResult({ wrappedKey, prfResult: { output: prf } }),
      ).resolves.toEqual(key);
    },
  );
});
