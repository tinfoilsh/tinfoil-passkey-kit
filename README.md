# Tinfoil Passkey Kit

JavaScript and Swift libraries for wrapping 32-byte keys with passkeys and the
WebAuthn PRF extension. Both implementations use the same profile-driven wire
format and can recover records produced by the other.

This kit performs local key wrapping. It does not log users in, authenticate a
session to a server, or provide hosted storage.

## JavaScript quickstart

```sh
npm install @tinfoilsh/passkey-kit
```

```ts
import {
  createPasskeyKeyManager,
  decodeWrappedKeyRecord,
  encodeWrappedKeyRecord,
} from "@tinfoilsh/passkey-kit";

const encoder = new TextEncoder();
// Keep every profile field stable for existing records.
const manager = createPasskeyKeyManager({
  profile: {
    version: 1,
    relyingPartyId: "example.com",
    prfSalt: encoder.encode("example-key-wrapping"),
    hkdfInfo: encoder.encode("example-wrapping-key-v1"),
  },
  relyingPartyName: "Example App",
});

const created = await manager.createAndWrapKey({
  user: { id: crypto.getRandomValues(new Uint8Array(32)), name: "person@example.com" },
  key: crypto.getRandomValues(new Uint8Array(32)),
});
await wrappedKeyRepository.save(encodeWrappedKeyRecord(created.wrappedKey));

const wrappedKeys = (await wrappedKeyRepository.list()).map(decodeWrappedKeyRecord);
const recovered = await manager.recoverKey({ wrappedKeys });
```

`wrappedKeyRepository` is application-owned; see the
[repository interface](https://github.com/tinfoilsh/tinfoil-passkey-kit/blob/main/docs/wrapped-key-repository.md)
and the runnable [web example](https://github.com/tinfoilsh/tinfoil-passkey-kit/blob/main/Examples/Web/README.md).
Failures throw `PasskeyKeyError`; branch on its `category`, not its message.
PRF caching is off unless you pass a `PasskeyKeyStorage`. Cached PRF output is
raw secret key material, and `createInsecureBrowserLocalStoragePasskeyKeyStorage`
stores it where same-origin scripts can read it.

## Swift quickstart

Add this repository as a Swift Package Manager dependency and link the
`TinfoilPasskeyKit` product. The package requires iOS 18 or macOS 15, and the
app needs the `webcredentials` associated-domain entitlement for its
relying-party domain.

```swift
import TinfoilPasskeyKit

// On the main actor. The provider returns the window that presents passkey UI.
let manager = try PasskeyKeyManager(
    profile: PasskeyKeyProfile(
        version: 1,
        relyingPartyId: "example.com",
        prfSalt: Data("example-key-wrapping".utf8),
        hkdfInfo: Data("example-wrapping-key-v1".utf8)
    ),
    relyingPartyName: "Example App",
    presentationAnchorProvider: presentationAnchorProvider
)

let created = try await manager.createAndWrapKey(
    user: PasskeyUser(id: opaqueUserHandle, name: "person@example.com"),
    key: key
)
await wrappedKeyRepository.save(try encodeWrappedKeyRecord(created.wrappedKey))

let records: [Data] = await wrappedKeyRepository.list()
let recovered = try await manager.recoverKey(wrappedKeys: records.map(decodeWrappedKeyRecord))
```

`KeychainPasskeyKeyStorage` is an optional device-bound PRF cache; choose
storage based on your threat model. See the compilable
[Apple example](https://github.com/tinfoilsh/tinfoil-passkey-kit/blob/main/Examples/Apple/README.md).

## Documentation

- [API contract](https://github.com/tinfoilsh/tinfoil-passkey-kit/blob/main/docs/api-contract.md)
- [Support matrix](https://github.com/tinfoilsh/tinfoil-passkey-kit/blob/main/docs/support-matrix.md)
- [Security boundary](https://github.com/tinfoilsh/tinfoil-passkey-kit/blob/main/docs/security-boundary.md)
- [Scope](https://github.com/tinfoilsh/tinfoil-passkey-kit/blob/main/docs/scope.md)
- [Contributing](https://github.com/tinfoilsh/tinfoil-passkey-kit/blob/main/CONTRIBUTING.md)
- [Security policy](https://github.com/tinfoilsh/tinfoil-passkey-kit/blob/main/SECURITY.md)

## Development

```sh
npm ci
npm test
npm run typecheck
npm run build
swift test
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
