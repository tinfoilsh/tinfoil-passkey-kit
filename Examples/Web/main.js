import { createPasskeyKeyManager } from "../../dist/index.js";

const encoder = new TextEncoder();
const profile = {
  version: 1,
  relyingPartyId: "example.com",
  relyingPartyName: "Passkey Key Example",
  prfSalt: encoder.encode("example-key-wrapping"),
  hkdfInfo: encoder.encode("example-wrapping-key-v1"),
};

/** @typedef {import("../../dist/index.js").WrappedKey} WrappedKey */

/**
 * @interface WrappedKeyRepository
 * @property {(wrappedKey: WrappedKey) => Promise<void>} save
 * @property {() => Promise<WrappedKey[]>} list
 */

/** @implements {WrappedKeyRepository} */
class InMemoryWrappedKeyRepository {
  /** @type {WrappedKey[]} */
  #records = [];

  async save(wrappedKey) {
    this.#records = [wrappedKey];
  }

  async list() {
    return [...this.#records];
  }
}

const manager = createPasskeyKeyManager({ profile });
const repository = new InMemoryWrappedKeyRepository();
const status = document.querySelector("#status");

document.querySelector("#enroll").addEventListener("click", async () => {
  try {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const created = await manager.createAndWrapKey({
      user: {
        id: crypto.getRandomValues(new Uint8Array(32)),
        name: "person@example.com",
        displayName: "Example Person",
      },
      key,
    });
    await repository.save(created.wrappedKey);
    status.textContent = `Stored wrapped key for ${created.credentialId}.`;
  } catch (error) {
    status.textContent = `Enrollment failed: ${error}`;
  }
});

document.querySelector("#recover").addEventListener("click", async () => {
  try {
    const recovered = await manager.recoverKey({
      wrappedKeys: await repository.list(),
    });
    status.textContent = `Recovered ${recovered.key.byteLength} key bytes.`;
  } catch (error) {
    status.textContent = `Recovery failed: ${error}`;
  }
});
