# API Contract

The public contract uses the same concepts on web and Apple. Language casing
follows platform conventions, but names and behavior remain recognizable.

## Models

`PasskeyKeyProfile` defines one interoperable key-wrapping domain:

```ts
interface PasskeyKeyProfile {
  version: number;
  relyingPartyId: string;
  prfSalt: Uint8Array;
  hkdfInfo: Uint8Array;
}

interface WrappedKey {
  profile: PasskeyKeyProfile;
  credentialId: string;
  kekIvHex: string;
  wrappedKeyHex: string;
}
```

Swift uses `Data` for byte values and otherwise exposes the same properties.
The profile contains exactly `version`, relying-party ID, PRF salt, and HKDF
info. Its values select the cryptographic domain and are not secret. v0.2
supports exactly profile version `1` and rejects any other version with
`invalid_input`. The first public scope accepts exactly 32 key bytes. The
initial Tinfoil profile retains the current PRF salt, HKDF info, AES-GCM, and
hexadecimal field layout.

`WrappedKey` is the runtime model. Its profile byte fields remain `Uint8Array`
in JavaScript and `Data` in Swift. The canonical public JSON model is:

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

The record has exactly the top-level fields `version`, `profile`,
`credentialId`, `kekIvHex`, and `wrappedKeyHex`. `prfSalt` and `hkdfInfo` use
unpadded base64url. `credentialId` remains unpadded base64url; the two hex fields
remain lowercase. JavaScript and Swift encoders emit this shape and decoders
apply the same validation. `encodeWrappedKeyRecord` emits UTF-8 JSON with the
shown key order and no insignificant whitespace. `decodeWrappedKeyRecord`
accepts insignificant whitespace and any key order, but rejects missing or
additional fields, invalid encodings, and unsupported versions. Record and
profile versions must both be `1`. Swift exposes methods with the same names.
Swift encodes to and decodes from `Data` containing the canonical UTF-8 JSON.

## Manager

JavaScript constructs a manager with exactly one required profile. Swift uses
`PasskeyKeyManager(profile:relyingPartyName:storage:presentationAnchorProvider:timeout:)`
with the same requirement. The relying-party name is required for API parity
but is not part of the cryptographic profile. AuthenticationServices does not
expose a relying-party display-name field, so Apple derives its presentation
from system and associated-domain metadata. Storage remains optional, the Apple
presentation anchor provider is required, and timeout defaults to 60 seconds.
Omitting it is a compile-time error rather than a ceremony-time failure.

```ts
declare function createPasskeyKeyManager(input: {
  profile: PasskeyKeyProfile;
  relyingPartyName: string;
  storage?: PasskeyKeyStorage;
  timeoutMs?: number;
}): PasskeyKeyManager;
```

Every manager operation uses that profile. No operation accepts a profile or
profile override per call. The conceptual surface is:

```ts
type PasskeyInteraction = "interactive" | "immediatelyAvailable";
type PasskeyCapability = "supported" | "unsupported" | "unknown";

interface PasskeyUser {
  id: string;
  name: string;
  displayName?: string;
}

interface PRFResult {
  output: Uint8Array;
}

interface CreateAndWrapKeyInput {
  user: PasskeyUser;
  keyMaterial: Uint8Array;
}

interface CreatedWrappedKey {
  credentialId: string;
  wrappedKey: WrappedKey;
  prfResult: PRFResult;
}

interface RecoverKeyInput {
  wrappedKeys: WrappedKey[];
  interaction?: PasskeyInteraction;
}

interface RecoveredKey {
  credentialId: string;
  keyMaterial: Uint8Array;
}

interface RewrapKeyInput {
  keyMaterial: Uint8Array;
}

interface EvaluateCredentialInput {
  credentialIds: string[];
  interaction?: PasskeyInteraction;
}

interface EvaluatedCredential {
  credentialId: string;
  prfResult: PRFResult;
}

interface WrapKeyWithPRFResultInput {
  keyMaterial: Uint8Array;
  credentialId: string;
  prfResult: PRFResult;
}

interface UnwrapKeyWithPRFResultInput {
  wrappedKey: WrappedKey;
  prfResult: PRFResult;
}

interface PasskeyKeyManager {
  capability(input: {
    operation: "enroll" | "recover";
  }): Promise<PasskeyCapability>;
  createAndWrapKey(input: CreateAndWrapKeyInput): Promise<CreatedWrappedKey>;
  recoverKey(input: RecoverKeyInput): Promise<RecoveredKey>;
  evaluateCredential(
    input: EvaluateCredentialInput,
  ): Promise<EvaluatedCredential>;
  wrapKeyWithPRFResult(
    input: WrapKeyWithPRFResultInput,
  ): Promise<WrappedKey>;
  unwrapKeyWithPRFResult(
    input: UnwrapKeyWithPRFResultInput,
  ): Promise<Uint8Array>;
  recoverKeyFromCache(input: RecoverKeyInput): Promise<RecoveredKey | null>;
  rewrapKeyFromCache(input: RewrapKeyInput): Promise<WrappedKey | null>;
  clearLocalState(): void;
  cancelActiveCeremony(): void;
}
```

`PasskeyUser` matches the existing JavaScript identity model: `id` is the
stable opaque user handle, `name` is the account identifier shown by the
passkey provider, and optional `displayName` falls back to `name`. Swift exposes
equivalent input and result types, using `Data` wherever JavaScript uses
`Uint8Array`.

Creation accepts passkey user metadata and a 32-byte key, then embeds the
manager's full profile in the `WrappedKey`. Recovery accepts one or more wrapped
keys, rejects any profile that does not exactly match the manager profile with
`invalid_input`, authenticates only against the listed credential IDs, and
returns the matched credential ID and recovered key. Cache-only methods never
start a ceremony and return `null` when no usable matching-profile cache exists.
Storage failures do not discard a successful ceremony.

`recoverKey` and `evaluateCredential` accept `interaction`, either `interactive`
or `immediatelyAvailable`; the default is `interactive`. Apple supports both.
Browsers support only `interactive` and fail an `immediatelyAvailable` request
with `unsupported`. Passkey creation is always interactive.

`evaluateCredential` is an advanced ceremony API for migrations and custom
interoperability. It authenticates against supplied credential IDs using the
manager profile and returns the matched `credentialId` plus a `PRFResult`. Its
raw `output` is secret key material: callers must avoid logging, transmitting,
or retaining it longer than necessary. Swift uses `Data` for this output.
High-level applications should use `recoverKey` instead.

`wrapKeyWithPRFResult({ keyMaterial, credentialId, prfResult })` and
`unwrapKeyWithPRFResult({ wrappedKey, prfResult })` are advanced primitives for
use immediately after `evaluateCredential`, primarily during migration or
custom interoperability. They validate the manager profile and version, the
32-byte key material, the 32-byte PRF output, the credential ID, and wrapped-key
shape as applicable. A profile mismatch or malformed input is `invalid_input`;
authenticated-decryption failure is `operation_failed`.

These methods only derive, wrap, or unwrap. They never start a passkey ceremony,
occupy the active ceremony slot, or read or write storage. The supplied PRF
result remains raw secret key material and must not be logged, transmitted, or
retained unnecessarily. High-level applications should prefer
`createAndWrapKey` and `recoverKey`.

JavaScript uses the names shown above. Swift uses `PasskeyKeyManager`,
`PasskeyKeyProfile`, and `WrappedKey`, with methods `capability(operation:)`,
`createAndWrapKey`, `recoverKey`, `evaluateCredential`, `recoverKeyFromCache`,
`rewrapKeyFromCache`, `clearLocalState`, and `cancelActiveCeremony`. Swift also
exposes `wrapKeyWithPRFResult(keyMaterial:credentialId:prfResult:)` and
`unwrapKeyWithPRFResult(wrappedKey:prfResult:)` with the same validation and
side-effect-free behavior.
Initialisms follow language style (`prf` in JavaScript and `PRF` where exposed
in Swift), without changing the underlying concept.

## Capability semantics

`PasskeyCapability` is `supported`, `unsupported`, or `unknown`. It is an
advisory preflight result, not proof that a specific authenticator will produce
PRF output. `supported` permits attempting a ceremony, `unsupported` means the
platform can definitively reject the operation, and `unknown` means the platform
cannot answer without a ceremony. Applications should permit an attempt for
`unknown` and handle the ceremony result.

The single `capability({ operation })` API distinguishes the requirements.
`enroll` checks whether a PRF-capable platform authenticator can create a
credential. `recover` checks whether a PRF assertion can be attempted and does
not require platform attachment. Browsers may use synced, security-key, or
hybrid credentials when their WebAuthn implementation and authenticator support
PRF. The manager profile is implicit and cannot be supplied to the capability
call.

On iOS 18 and macOS 15, Apple recovery supports platform and synced passkeys,
including cross-device passkey flows. Explicit security-key PRF is not currently
enabled in the Apple target because the baseline toolchain does not provide that
API. Apple also does not provide a reliable PRF preflight for the supported
flows, so Swift reports `unknown` rather than falsely reporting `unsupported`.

Assertion interaction support is:

| Platform | `interactive` | `immediatelyAvailable` |
| --- | --- | --- |
| Apple | Supported | Supported |
| Browser | Supported | Unsupported |

## Errors and lifecycle

Every public failure maps to exactly one stable category:

- `unsupported`: a definitive check shows a required platform or PRF feature is unavailable.
- `cancelled`: user, caller, or task cancellation, including WebAuthn `NotAllowed`.
- `timeout`: the platform request or the kit's hard deadline expired.
- `operation_in_progress`: the manager already has an active ceremony.
- `invalid_input`: the profile, credential metadata, wrapped fields, or key is invalid.
- `operation_failed`: authorization, random generation, derivation, or authenticated decryption failed.

JavaScript exposes these values as an error `category`; Swift exposes matching
`PasskeyKeyError` cases. Messages and underlying platform errors are diagnostic
only. Callers branch on the category, never the message.

WebAuthn `NotAllowed` is intentionally `cancelled` because it may mean either
that the prompt was dismissed or that no eligible credential was available.
Only a definitive capability result or observed missing PRF support maps to
`unsupported`.

A manager permits one active create or assertion ceremony. A concurrent request
fails with `operation_in_progress` and does not replace the first. JavaScript
supports caller cancellation with `AbortSignal`; Swift observes task
cancellation. `cancelActiveCeremony` provides explicit UI-driven cancellation.
Cancellation and timeout settle the operation once, release the active slot,
and never return a partial wrapped key or recovered key.

## Storage

Local persistence is an explicit opt-in: it is disabled unless the host supplies
a storage implementation. In v0.2 the interface is synchronous for simplicity
and stores only the cached PRF result and local credential metadata:

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

These are the five storage methods. None accepts a profile argument. A cached
PRF result includes the full profile snapshot, and the manager rejects it unless
that snapshot exactly matches its profile. Swift provides equivalent
`PasskeyKeyStorage` requirements. These interfaces and examples do not
prescribe hosted or account storage. v0.2 provides optional browser and
Keychain implementations. The browser local-storage adapter is explicitly
insecure because same-origin script can read its cached PRF output; the Keychain
adapter uses device-local protected storage. Neither is selected by default:
the host must opt in by passing an adapter.

Swift storage calls run synchronously on the manager's main-actor methods.
Keychain access may block that actor. Hosts whose persistence must run off the
main actor should avoid the v0.2 adapter and use a future asynchronous storage
API rather than treating this synchronous contract as background I/O.

The generic public contract does not expose `deriveStableKeyId`.

Swift also provides the opt-in `KeychainPasskeyKeyStorage` adapter. It uses
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, so cached PRF output is
device-bound and unavailable while locked. The cache still permits recovery
without another passkey prompt once readable; hosts must decide whether that
tradeoff fits their threat model. No storage adapter is enabled by default.

`KeychainPasskeyKeyStorage` accepts an optional `decodeCachedRecord` hook for
hosts migrating from a pre-kit cache format. When the stored payload is not a
canonical `CachedPRFResult`, the adapter invokes the hook to decode it instead
of failing the load; the hook must throw for payloads it cannot decode. Writes
always use the canonical encoding, so migrated entries converge on the current
format after the next successful ceremony. The hook only translates bytes into
a `CachedPRFResult`: the manager still rejects any decoded result whose profile
snapshot does not exactly match its own.
