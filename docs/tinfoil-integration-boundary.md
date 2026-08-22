# Tinfoil Integration Boundary

Tinfoil Passkey Kit owns the web and Apple passkey ceremonies, PRF evaluation,
HKDF derivation, AES-GCM key wrapping and recovery, capability reporting,
ceremony lifecycle, stable errors, and explicit opt-in synchronous local-state
interface. Capability reporting distinguishes enrollment, which requires a
platform authenticator, from recovery, which does not require platform
attachment. Each manager receives one required profile at initialization, and
all operations, including capability checks, use it implicitly. The
relying-party name is separate manager presentation configuration.

Tinfoil applications continue to own:

- Clerk authentication, sessions, and user identity mapping.
- Enclave requests, authorization, and content-encryption-key use.
- Credential and wrapped-key inventory fetched from application services.
- Stable key identifiers and their inventory semantics.
- Enrollment, recovery, retry, and error UI.
- Recovery routing, account policy, and device-management decisions.
- Hosted persistence and synchronization of wrapped records.

Applications translate their records at the kit boundary. Existing production
fields `credentialId`, `kekIvHex`, and `wrappedKeyHex` remain byte-for-byte
compatible. An adapter may add the known initial Tinfoil `PasskeyKeyProfile`
when constructing `WrappedKey`, then omit that generic profile when writing the
existing record shape. The profile contains exactly its version, relying-party
ID, PRF salt, and HKDF info. v0.2 accepts only version 1. Applications create the
manager with that same profile; mismatched wrapped records are rejected rather
than routed with a per-call override.

Applications may adopt the canonical `WrappedKeyRecord` codec when they need a
public JSON representation. Its exact top-level fields are `version`, `profile`,
`credentialId`, `kekIvHex`, and `wrappedKeyHex`; profile bytes are unpadded
base64url. JavaScript and Swift encode and decode the same record. Legacy
production fields remain compatible through adapters, without server migration.

An opt-in host store implements exactly the five synchronous storage methods in
the API contract and receives no profile arguments. Cached PRF results carry a
profile snapshot for manager-side validation; the store does not select or
partition profiles on the kit's behalf.

The browser and Keychain stores are supported opt-in implementations, not
defaults. Applications choose them according to their security requirements.
The advanced `evaluateCredential` API is available for migrations and custom
interoperability, but application recovery flows should use `recoverKey` and
avoid handling raw PRF output.

Adapters must not reinterpret ciphertext, change encoding, or trigger migration.
No feature flag, server schema change, cryptographic wire change, or recovery
policy change is part of this effort. The generic public contract does not add
`deriveStableKeyId`.
