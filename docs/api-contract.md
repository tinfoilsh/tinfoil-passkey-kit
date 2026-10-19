# API Contract

JavaScript and Swift expose the same concepts with platform conventions:
`Uint8Array` in JavaScript and `Data` in Swift, `prf` in JavaScript and `PRF`
in Swift. Exact signatures are in [`src/types.ts`](../src/types.ts) and
[`Sources/TinfoilPasskeyKit`](../Sources/TinfoilPasskeyKit).

## Profile

`PasskeyKeyProfile` has exactly `version`, `relyingPartyId`, `prfSalt`, and
`hkdfInfo`. Its values select the cryptographic domain and are not secret. Only
version `1` is supported; any other version is `invalid_input`. Keys are
exactly 32 bytes.

## Wrapped key record

`WrappedKey` is the runtime model: the profile plus `credentialId`, `kekIvHex`,
and `wrappedKeyHex`. Its canonical JSON form is:

```ts
interface WrappedKeyRecord {
  version: 1;
  profile: {
    version: 1;
    relyingPartyId: string;
    prfSalt: string;
    hkdfInfo: string;
  };
  credentialId: string;
  kekIvHex: string;
  wrappedKeyHex: string;
}
```

- The record has exactly these fields, and record and profile versions must
  both be `1`.
- `prfSalt`, `hkdfInfo`, and `credentialId` are unpadded base64url. The two hex
  fields are lowercase.
- `encodeWrappedKeyRecord` emits UTF-8 JSON in the shown key order with no
  insignificant whitespace (Swift returns `Data`). `decodeWrappedKeyRecord`
  accepts any key order and insignificant whitespace, but rejects missing or
  additional fields, invalid encodings, and unsupported versions.

## Manager

A manager is bound to exactly one profile: `createPasskeyKeyManager({ profile,
relyingPartyName, storage?, timeoutMs? })` in JavaScript and
`PasskeyKeyManager(profile:relyingPartyName:storage:presentationAnchorProvider:timeout:)`
in Swift. No operation accepts a per-call profile. The relying-party name is
presentation configuration, not profile identity; AuthenticationServices does
not accept it. Swift requires a presentation anchor provider. The timeout
defaults to 60 seconds.

- `createAndWrapKey` creates a passkey for the user and wraps a 32-byte key,
  embedding the manager profile in the `WrappedKey`. The user `id` is a stable
  opaque handle, `name` is the account identifier, and `displayName` defaults
  to `name`. Creation is always interactive.
- `recoverKey` rejects any wrapped key whose profile differs from the manager's
  with `invalid_input`, authenticates only against the listed credential IDs,
  and returns the matched credential ID and key.
- `recoverKeyFromCache` and `rewrapKeyFromCache` never start a ceremony and
  return `null` when no usable matching-profile cache exists. Storage failures
  do not discard a successful ceremony.
- `evaluateCredential` authenticates against the given credential IDs and
  returns the matched ID with raw PRF output, for migrations and
  interoperability. `wrapKeyWithPRFResult` and `unwrapKeyWithPRFResult` then
  wrap or unwrap with that output. The standalone `wrapKey` and `unwrapKey`
  functions do the same with an explicit profile and no manager. None of these
  start a ceremony, occupy the ceremony slot, or access storage. Applications
  should prefer `createAndWrapKey` and `recoverKey`.

For every wrap and unwrap operation, a profile mismatch or malformed input
(key or PRF output not 32 bytes, invalid credential ID, malformed wrapped key)
is `invalid_input`, and authenticated-decryption failure is `operation_failed`.
Raw PRF output is secret key material: do not log, transmit, or retain it
longer than necessary.

`recoverKey` and `evaluateCredential` accept `interaction`, which defaults to
`interactive`:

| Platform | `interactive` | `immediatelyAvailable` |
| --- | --- | --- |
| Apple | Supported | Supported |
| Browser | Supported | Fails with `unsupported` |

## Capability

`capability({ operation })` returns `supported`, `unsupported`, or `unknown`.
It is advisory, not proof that an authenticator will return PRF output.
`supported` permits an attempt, `unsupported` means the platform definitively
rejects the operation, and `unknown` means it cannot tell without a ceremony,
so callers should attempt and handle the result. `enroll` requires a
PRF-capable platform authenticator; `recover` does not require platform
attachment. See the [support matrix](support-matrix.md) for platform behavior.

## Errors and lifecycle

Every failure maps to exactly one category, exposed as `category` on
`PasskeyKeyError` in JavaScript and as `PasskeyKeyError` cases in Swift.
Messages and underlying platform errors are diagnostic only; branch on the
category.

- `unsupported`: a definitive check shows a required platform or PRF feature is unavailable.
- `cancelled`: user, caller, or task cancellation, including WebAuthn `NotAllowed`.
- `timeout`: the platform request or the kit's hard deadline expired.
- `operation_in_progress`: the manager already has an active ceremony.
- `invalid_input`: the profile, credential metadata, wrapped fields, or key is invalid.
- `operation_failed`: authorization, random generation, derivation, or authenticated decryption failed.

WebAuthn `NotAllowed` maps to `cancelled` because it can mean either a
dismissed prompt or no eligible credential.

A manager permits one active create or assertion ceremony. A concurrent request
fails with `operation_in_progress` and does not replace the first. JavaScript
cancels with `AbortSignal`, Swift with task cancellation, and both with
`cancelActiveCeremony`. Cancellation and timeout settle the operation once,
release the active slot, and never return a partial wrapped or recovered key.

## Storage

Persistence is disabled unless the host passes a storage implementation. The
interface is synchronous and stores only the cached PRF result and the local
credential ID:

```ts
interface CachedPRFResult {
  profile: PasskeyKeyProfile;
  credentialId: string;
  prfOutput: Uint8Array;
}

interface PasskeyKeyStorage {
  loadCachedPRFResult(): CachedPRFResult | null;
  saveCachedPRFResult(result: CachedPRFResult): void;
  loadLocalCredentialId(): string | null;
  saveLocalCredentialId(credentialId: string): void;
  clear(): void;
}
```

No method takes a profile. Each cached result carries a full profile snapshot,
and the manager rejects it unless the snapshot exactly matches its profile.
Swift storage calls run synchronously on the manager's main actor, so Keychain
access can block it.

The kit ships these adapters; none is enabled by default:

- `createMemoryPasskeyKeyStorage()`, for tests.
- `createInsecureBrowserLocalStoragePasskeyKeyStorage(namespace)`, which stores
  raw PRF output unencrypted where same-origin scripts can read it.
- Swift `KeychainPasskeyKeyStorage`, which uses
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`: device-bound and unavailable
  while locked, but readable without another passkey prompt once unlocked. Its
  optional `decodeCachedRecord` hook decodes a pre-kit cache payload that is not
  a canonical `CachedPRFResult` and must throw for payloads it cannot decode.
  Writes always use the canonical encoding, and the manager still rejects a
  decoded result whose profile does not match.
