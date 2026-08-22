import {
  createPasskeyKeyManager,
  decodeWrappedKeyRecord,
  encodeWrappedKeyRecord,
} from "../../dist/index.js";

const encoder = new TextEncoder();
const profile = {
  version: 1,
  relyingPartyId: "example.com",
  prfSalt: encoder.encode("example-key-wrapping"),
  hkdfInfo: encoder.encode("example-wrapping-key-v1"),
};

/**
 * @interface WrappedKeyRepository
 * @property {(record: string) => Promise<void>} save
 * @property {() => Promise<string[]>} list
 */

/** @implements {WrappedKeyRepository} */
class InMemoryWrappedKeyRepository {
  /** @type {string[]} */
  #records = [];

  async save(record) {
    this.#records = [...this.#records, record];
  }

  async list() {
    return [...this.#records];
  }
}

const manager = createPasskeyKeyManager({
  profile,
  relyingPartyName: "Passkey Key Example",
});
const repository = new InMemoryWrappedKeyRepository();
const status = document.querySelector("#status");

async function loadWrappedKeys() {
  return (await repository.list()).map(decodeWrappedKeyRecord);
}

document.querySelector("#enroll").addEventListener("click", async () => {
  let key;
  try {
    key = crypto.getRandomValues(new Uint8Array(32));
    const created = await manager.createAndWrapKey({
      user: {
        id: crypto.getRandomValues(new Uint8Array(32)),
        name: "person@example.com",
        displayName: "Example Person",
      },
      key,
    });
    await repository.save(encodeWrappedKeyRecord(created.wrappedKey));
    status.textContent = `Stored wrapped key for ${created.credentialId}.`;
  } catch (error) {
    status.textContent = `Enrollment failed: ${error}`;
  } finally {
    key?.fill(0);
  }
});

document.querySelector("#recover").addEventListener("click", async () => {
  let recovered;
  try {
    recovered = await manager.recoverKey({
      wrappedKeys: await loadWrappedKeys(),
    });
    status.textContent = `Recovered ${recovered.key.byteLength} key bytes.`;
  } catch (error) {
    status.textContent = `Recovery failed: ${error}`;
  } finally {
    recovered?.key.fill(0);
  }
});

document.querySelector("#evaluate").addEventListener("click", async () => {
  try {
    const wrappedKeys = await loadWrappedKeys();
    const evaluated = await manager.evaluateCredential({
      credentialIds: wrappedKeys.map(({ credentialId }) => credentialId),
    });
    status.textContent = `Evaluated ${evaluated.prfResult.output.byteLength} PRF bytes.`;
    evaluated.prfResult.output.fill(0);
  } catch (error) {
    status.textContent = `Evaluation failed: ${error}`;
  }
});
