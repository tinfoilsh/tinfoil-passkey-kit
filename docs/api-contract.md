# API Contract

The public contract uses the same concepts on web and Apple. Language casing
follows platform conventions, but names and behavior remain recognizable.

## Models

`PasskeyKeyProfile` defines one interoperable key-wrapping domain:

```ts
interface PasskeyKeyProfile {
  version: number;
  relyingPartyId: string;
  relyingPartyName: string;
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
The profile contains exactly `version`, relying-party ID and name, PRF salt,
and HKDF info. Its values select the derivation contract and are not secret.
The first public scope accepts exactly 32 key bytes. The initial Tinfoil profile
retains the current PRF salt, HKDF info, AES-GCM, and hexadecimal field layout.

## Manager

The conceptual surface is:

```ts
interface PasskeyKeyManager {
  capability(input: {
    operation: "enroll" | "recover";
  }): Promise<PasskeyCapability>;
  createAndWrapKey(input: CreateAndWrapKeyInput): Promise<CreatedWrappedKey>;
  recoverKey(input: RecoverKeyInput): Promise<RecoveredKey>;
  recoverKeyFromCache(input: RecoverKeyInput): Promise<RecoveredKey | null>;
  rewrapKeyFromCache(input: RewrapKeyInput): Promise<WrappedKey | null>;
  clearLocalState(): void;
  cancelActiveCeremony(): void;
}
```

Creation accepts a profile, passkey user metadata, and a 32-byte key. Recovery
accepts a profile and one or more wrapped keys, authenticates only against the
listed credential IDs, and returns the matched credential ID and recovered
key. Cache-only methods never start a ceremony and return `null` when no usable
cached result exists. Storage failures do not discard a successful ceremony.

JavaScript uses the names shown above. Swift uses `PasskeyKeyManager`,
`PasskeyKeyProfile`, and `WrappedKey`, with methods `capability(operation:)`,
`createAndWrapKey`, `recoverKey`, `recoverKeyFromCache`,
`rewrapKeyFromCache`, `clearLocalState`, and `cancelActiveCeremony`.
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
not require platform attachment; a synced, cross-device, or security-key
credential may recover a key.

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
interface PasskeyKeyStorage {
  loadCachedPRFResult(): CachedPRFResult | null;
  saveCachedPRFResult(result: CachedPRFResult): void;
  loadLocalCredentialId(): string | null;
  saveLocalCredentialId(credentialId: string): void;
  clear(): void;
}
```

Swift provides equivalent `PasskeyKeyStorage` requirements. These interfaces
and examples do not prescribe browser, Keychain, hosted, or account storage.
The generic public contract does not expose `deriveStableKeyId`.
