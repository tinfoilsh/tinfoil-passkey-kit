# Tinfoil Integration Boundary

Tinfoil Passkey Kit owns the web and Apple passkey ceremonies, PRF evaluation,
HKDF derivation, AES-GCM key wrapping and recovery, capability reporting,
ceremony lifecycle, stable errors, and optional local-state interface.

Tinfoil applications continue to own:

- Clerk authentication, sessions, and user identity mapping.
- Enclave requests, authorization, and content-encryption-key use.
- Credential and wrapped-key inventory fetched from application services.
- Enrollment, recovery, retry, and error UI.
- Recovery routing, account policy, and device-management decisions.
- Hosted persistence and synchronization of wrapped records.

Applications translate their records at the kit boundary. Existing production
fields `credentialId`, `kekIvHex`, and `wrappedKeyHex` remain byte-for-byte
compatible. An adapter may add the known initial Tinfoil `profileId` and
`version` when constructing `WrappedKey`, then omit those generic fields when
writing the existing record shape.

Adapters must not reinterpret ciphertext, change encoding, or trigger migration.
No feature flag, server schema change, cryptographic wire change, or recovery
policy change is part of this effort.
