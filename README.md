# Tinfoil Passkey Kit

JavaScript and Swift libraries for wrapping 32-byte keys with passkeys and the
WebAuthn PRF extension. Both implementations use the same profile-driven wire
format and can recover records produced by the other.

This kit performs local key wrapping. It does not log users in, authenticate a
session to a server, or provide hosted storage.

## JavaScript quickstart

Install the browser package:

```sh
npm install @tinfoilsh/passkey-kit
```

Create one explicit version 1 profile and keep every field stable for existing
records. The display name belongs to manager configuration, not the profile.

```ts
import {
  createPasskeyKeyManager,
  decodeWrappedKeyRecord,
  encodeWrappedKeyRecord,
} from "@tinfoilsh/passkey-kit";

const encoder = new TextEncoder();
const profile = {
  version: 1,
  relyingPartyId: "example.com",
  prfSalt: encoder.encode("example-key-wrapping"),
  hkdfInfo: encoder.encode("example-wrapping-key-v1"),
};
const manager = createPasskeyKeyManager({
  profile,
  relyingPartyName: "Example App",
});
const key = crypto.getRandomValues(new Uint8Array(32));

const created = await manager.createAndWrapKey({
  user: {
    id: crypto.getRandomValues(new Uint8Array(32)),
    name: "person@example.com",
    displayName: "Example Person",
  },
  key,
});
await wrappedKeyRepository.save(encodeWrappedKeyRecord(created.wrappedKey));

const records: string[] = await wrappedKeyRepository.list();
const wrappedKeys = records.map(decodeWrappedKeyRecord);
const recovered = await manager.recoverKey({ wrappedKeys });
useKey(recovered.key);
```

`evaluateCredential` is available for advanced migrations that need direct PRF
evaluation:

```ts
const evaluated = await manager.evaluateCredential({
  credentialIds: wrappedKeys.map(({ credentialId }) => credentialId),
});
usePRFOutput(evaluated.prfResult.output);
evaluated.prfResult.output.fill(0);
```

Treat PRF output as secret key material and prefer `recoverKey` for normal
recovery. `wrappedKeyRepository` is application-owned. See the minimal
[repository interface](https://github.com/tinfoilsh/tinfoil-passkey-kit/blob/main/docs/wrapped-key-repository.md)
and runnable [web example](https://github.com/tinfoilsh/tinfoil-passkey-kit/blob/main/Examples/Web/README.md).

Ceremony failures throw `PasskeyKeyError`. Branch on its stable `category`, not
its message. Local PRF caching is disabled unless the application supplies a
`PasskeyKeyStorage`; cached PRF output is secret key material.

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

The standalone `wrapKey(profile, credentialId, prfOutput, key)` and
`unwrapKey(profile, prfOutput, wrappedKey)` functions expose the same
crypto-only operations without constructing a manager, for migration and
interoperability tooling that already holds raw PRF output. They apply the
same validation as the manager methods and treat the PRF output as secret
key material.

## Swift quickstart

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
    let manager = try PasskeyKeyManager(
        profile: profile,
        relyingPartyName: "Example App",
        presentationAnchorProvider: presentationAnchorProvider
    )

    let created = try await manager.createAndWrapKey(
        user: PasskeyUser(
            id: opaqueUserHandle,
            name: "person@example.com",
            displayName: "Example Person"
        ),
        key: key
    )
    await wrappedKeyRepository.save(try encodeWrappedKeyRecord(created.wrappedKey))

    let records: [Data] = await wrappedKeyRepository.list()
    let wrappedKeys = try records.map(decodeWrappedKeyRecord)
    let recovered = try await manager.recoverKey(wrappedKeys: wrappedKeys)
    useKey(recovered.key)
}
```

Advanced flows can call `evaluateCredential(credentialIds:interaction:)`.
Its `prfResult.output` is raw secret key material. Do not log, transmit, or
retain it longer than necessary.

The standalone `wrapKey(profile:credentialId:prfOutput:key:)` and
`unwrapKey(profile:prfOutput:wrapped:)` functions expose the same crypto-only
operations without constructing a manager or providing a presentation anchor,
for migration and interoperability tooling that already holds raw PRF output.

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
on the host app's threat model. Hosts migrating from a pre-kit cache format can
pass the optional `decodeCachedRecord` hook to decode non-canonical stored
payloads instead of forking the adapter. The host app must also provide the
`webcredentials` associated-domain entitlement for its relying-party domain.
Keychain operations are synchronous and can block the manager's main actor.

On iOS 18 and macOS 15, recovery supports platform and synced passkeys,
including Apple's cross-device passkey flow. Explicit security-key PRF is not
currently enabled in the Apple target because the baseline toolchain does not
provide that API. Browsers may support security-key or hybrid recovery.
Capability remains `unknown` when Apple cannot preflight PRF support; callers
should allow an attempt.

See the compilable [Apple example](https://github.com/tinfoilsh/tinfoil-passkey-kit/blob/main/Examples/Apple/README.md).

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
