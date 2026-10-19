# Scope

Tinfoil Passkey Kit owns the web and Apple passkey ceremonies, PRF evaluation,
HKDF derivation, AES-GCM wrapping and recovery of a 32-byte key, capability
reporting, ceremony lifecycle, stable errors, and the opt-in local storage
interface described in the [API contract](api-contract.md).

## Out of scope

- Server authentication. The kit does not issue or verify login sessions,
  validate WebAuthn assertions on a server, or replace an identity provider.
- Hosted storage, accounts, synchronization, backup, retention, or cloud policy.
- Android, server, or non-browser JavaScript support.
- New cryptographic wire formats, server data migration, and stable key
  identifiers (there is no `deriveStableKeyId`).

## Application responsibilities

Applications, including Tinfoil's, own:

- Authentication, sessions, and user identity mapping.
- Use of the recovered key, and any enclave requests or authorization around it.
- Credential and wrapped-key inventory, stable key identifiers, and hosted
  persistence and synchronization of wrapped records.
- Enrollment, recovery, retry, and error UI, recovery routing, account policy,
  and device management.

## Existing Tinfoil records

Existing production fields `credentialId`, `kekIvHex`, and `wrappedKeyHex`
remain byte-for-byte compatible. An adapter may add the known Tinfoil
`PasskeyKeyProfile` when constructing a `WrappedKey` and omit it when writing
the existing record shape. Adapters must not reinterpret ciphertext, change
encoding, or trigger migration.
