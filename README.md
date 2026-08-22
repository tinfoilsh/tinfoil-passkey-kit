# Tinfoil Passkey Kit

Cross-platform SDKs for protecting content-encryption keys with passkeys and
the WebAuthn PRF extension. The JavaScript and Swift implementations share the
same protocol constants and wire formats, so either client can recover a CEK
wrapped by the other.

- Passkey creation and authentication with PRF
- HKDF-SHA-256 key-encryption-key derivation
- AES-256-GCM CEK wrapping and unwrapping
- Stable CEK key-ID derivation
- Device-local PRF and credential persistence

## JavaScript

Install the browser package:

```sh
npm install @tinfoilsh/passkey-kit
```

```ts
import { createPasskeyKit, generateCek } from "@tinfoilsh/passkey-kit";

const kit = createPasskeyKit({
  rpId: "example.com",
  rpName: "Example App",
});

const cek = generateCek();
const enrolled = await kit.enroll({
  user: { id: userId, name: email, displayName },
  cek,
});

if (enrolled) {
  await api.saveBundle(enrolled.wrappedCek);
}

const unlocked = await kit.unlock(bundlesFromServer);
if (unlocked) {
  useCek(unlocked.cek);
}
```

High-level ceremony methods return `null` when the user cancels. They throw
`PrfNotSupportedError` when the authenticator lacks PRF support and
`PasskeyTimeoutError` when the provider hangs. Classify these errors with
`instanceof`, not message strings.

The kit also provides cached unlock and rewrap flows. Lower-level exports
include `detectPrfSupport`, `deriveKeyEncryptionKey`, `generateCek`,
`isValidCek`, `wrapCek`, `unwrapCek`, and `deriveKeyId`.

The default storage adapter uses `localStorage` on a best-effort basis. Pass
`storage: null` to disable persistence or provide a custom `StorageAdapter`.
Cached PRF output is raw secret key material and must be protected accordingly.

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

`KeychainPasskeyStateStore` stores cached PRF output with
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Pass `stateStore: nil` to
disable local persistence. The host app must provide the `webcredentials`
associated-domain entitlement for its relying-party domain.

## Protocol

Both implementations default to the Tinfoil v1 PRF salt and HKDF info. These
values must remain identical across clients that wrap the same CEK. Override
both values together to establish a separate protocol domain.

The server-persisted wrapped bundle contains only:

- The unpadded base64url credential ID
- The 12-byte AES-GCM IV as lowercase hexadecimal
- The wrapped CEK ciphertext and 16-byte authentication tag as lowercase
  hexadecimal

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
