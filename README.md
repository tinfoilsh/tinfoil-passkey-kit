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
import Foundation
import TinfoilPasskeyKit

@MainActor
func protectKey(
    _ key: Data,
    presentationAnchorProvider: any PasskeyPresentationAnchorProviding
) async throws {
    let profile = try PasskeyKeyProfile(
        version: 1,
        relyingPartyId: "example.com",
        prfSalt: Data("example-key-wrapping".utf8),
        hkdfInfo: Data("example-wrapping-key-v1".utf8)
    )
    let storage = KeychainPasskeyKeyStorage(
        service: "example.com",
        account: "com.example.passkey-prf",
        localCredentialIdKey: "com.example.local-passkey-id"
    )
    let manager = try PasskeyKeyManager(
        profile: profile,
        relyingPartyName: "Example App",
        storage: storage,
        presentationAnchorProvider: presentationAnchorProvider
    )

    let created = try await manager.createAndWrapKey(
        user: PasskeyUser(id: opaqueUserHandle, name: email, displayName: displayName),
        key: key
    )
    let record = try encodeWrappedKeyRecord(created.wrappedKey)
    await saveToServer(record)

    let wrappedKey = try decodeWrappedKeyRecord(recordFromServer)
    let recovered = try await manager.recoverKey(wrappedKeys: [wrappedKey])
    useKey(recovered.key)
}
```

`evaluateCredential` supports advanced and legacy flows that need direct PRF
evaluation. Its `prfResult.output` is raw secret key material. Do not log,
transmit, or retain it longer than necessary. Pass `.immediatelyAvailable` as
the interaction to restrict evaluation to credentials Apple can offer without
the full interactive flow.

Apple hosts must pass a `PasskeyPresentationAnchorProviding` implementation to
the manager as `presentationAnchorProvider`. The provider returns the iOS or
macOS window AuthenticationServices uses for interactive presentation. Making
it required prevents constructing a manager that cannot present a ceremony.
AuthenticationServices does not accept the configured `relyingPartyName`; Apple
derives relying-party presentation from system and associated-domain metadata.

Persistence is disabled by default. `KeychainPasskeyKeyStorage` is an optional
generic Apple adapter that stores cached PRF output with
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Its records are device-bound and
unavailable while the device is locked, but any process context that can read
the item can recover keys without another passkey prompt. Choose storage based
on the host app's threat model. The host app must also provide the
`webcredentials` associated-domain entitlement for its relying-party domain.
Keychain operations are synchronous and can block the manager's main actor.

On iOS 18 and macOS 15, recovery supports platform and synced passkeys,
including Apple's cross-device passkey flow. Explicit security-key PRF is not
currently enabled in the Apple target because the baseline toolchain does not
provide that API. Browsers may support security-key or hybrid recovery.
Capability remains `unknown` when Apple cannot preflight PRF support; callers
should allow an attempt.

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
