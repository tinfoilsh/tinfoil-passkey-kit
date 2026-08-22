# Tinfoil Passkey Kit

Cross-platform SDKs for protecting key material with passkeys and
the WebAuthn PRF extension. The JavaScript and Swift implementations share the
same profile-driven wire format, so either client can recover a CEK wrapped by
the other.

- Passkey creation and authentication with PRF
- HKDF-SHA-256 key-encryption-key derivation
- AES-256-GCM CEK wrapping and unwrapping
- Optional device-local PRF and credential persistence

## JavaScript

Install the browser package:

```sh
npm install @tinfoilsh/passkey-kit
```

```ts
import {
  createPasskeyKeyManager,
  decodeWrappedKeyRecord,
  encodeWrappedKeyRecord,
} from "@tinfoilsh/passkey-kit";

const profile = {
  version: 1,
  relyingPartyId: "example.com",
  prfSalt: new TextEncoder().encode("example-key-wrapping"),
  hkdfInfo: new TextEncoder().encode("example-wrapping-key-v1"),
};
const manager = createPasskeyKeyManager({
  profile,
  relyingPartyName: "Example App",
});

const created = await manager.createAndWrapKey({
  user: { id: opaqueUserHandle, name: email, displayName },
  key,
});
await api.saveWrappedKey(created.wrappedKey);
const canonicalRecord = encodeWrappedKeyRecord(created.wrappedKey);
const wrappedKey = decodeWrappedKeyRecord(canonicalRecord);

const recovered = await manager.recoverKey({
  wrappedKeys: [wrappedKey],
});
useKey(recovered.key);
```

Ceremony failures throw `PasskeyKeyError`. Branch on its stable `category`, not
its message.

Persistence is disabled by default. Cached recovery and rewrap require an
explicit synchronous `PasskeyKeyStorage`. Cached PRF output is raw secret key
material and requires host-appropriate protection.

The memory adapter is suitable for tests. The explicitly named
`createInsecureBrowserLocalStoragePasskeyKeyStorage(namespace)` adapter stores
raw PRF output unencrypted, isolates records by its required namespace, and is
insecure because same-origin scripts can read the cached secret material.

`evaluateCredential` exposes raw PRF output for advanced migrations. Treat
`prfResult.output` as secret key material and prefer `recoverKey` for normal
recovery. `wrapKeyWithPRFResult` and `unwrapKeyWithPRFResult` perform explicit
crypto-only operations without starting a ceremony or accessing storage.

## Swift

Add this repository as a Swift Package Manager dependency and link the
`TinfoilPasskeyKit` product. The package requires iOS 18 or macOS 15.

```swift
import TinfoilPasskeyKit

@MainActor
func configurePasskeyKit() async throws {
    let store = KeychainPasskeyStateStore(
        service: "example.com",
        account: "com.example.passkey-prf",
        localCredentialIdKey: "com.example.local-passkey-id"
    )
    let kit = PasskeyKit(
        configuration: PasskeyKitConfiguration(
            rpId: "example.com",
            rpName: "Example App",
            stateStore: store
        )
    )

    let cek = try PasskeyCrypto.generateCEK()
    let enrollment = try await kit.enroll(
        user: PasskeyUser(id: userId, name: email, displayName: displayName),
        cek: cek
    )
    await saveToServer(enrollment.wrappedCEK)

    let unlocked = try await kit.unlock(wrappedCEKsFromServer)
    useCEK(unlocked.cek)
}
```

The optional `KeychainPasskeyStateStore` stores cached PRF output with
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. No state store is selected by
default. The host app must provide the `webcredentials` associated-domain
entitlement for its relying-party domain.

## Protocol

Both implementations use the PRF salt and HKDF info supplied by the profile.
These values must remain identical across clients that wrap the same key.

The existing Tinfoil server adapter persists only:

- The unpadded base64url credential ID
- The 12-byte AES-GCM IV as lowercase hexadecimal
- The wrapped CEK ciphertext and 16-byte authentication tag as lowercase
  hexadecimal

The adapter reconstructs the known profile when reading these legacy records.

User identity, server persistence, associated-domain configuration, and
recovery UI remain the host application's responsibility.

## Documentation

- [Scope](docs/scope.md)
- [API contract](docs/api-contract.md)
- [Security boundary](docs/security-boundary.md)
- [Tinfoil integration boundary](docs/tinfoil-integration-boundary.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Development

```sh
npm install
npm test
npm run typecheck
npm run build
swift test
```
