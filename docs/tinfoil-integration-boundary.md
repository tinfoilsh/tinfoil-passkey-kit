# Tinfoil Integration Boundary

Tinfoil Passkey Kit owns the web and Apple passkey ceremonies, PRF evaluation,
HKDF derivation, AES-GCM key wrapping and recovery, capability reporting,
ceremony lifecycle, stable errors, and explicit opt-in synchronous local-state
interface. Capability reporting distinguishes enrollment, which requires a
platform authenticator, from recovery, which does not require platform
attachment.

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
ID and name, PRF salt, and HKDF info.

Adapters must not reinterpret ciphertext, change encoding, or trigger migration.
No feature flag, server schema change, cryptographic wire change, or recovery
policy change is part of this effort. The generic public contract does not add
`deriveStableKeyId`.
