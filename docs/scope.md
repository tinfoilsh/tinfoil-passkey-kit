# Scope

Tinfoil Passkey Kit is a web and Apple client library for wrapping and
recovering a 32-byte content-encryption key with the WebAuthn PRF extension.
It owns the passkey ceremony, PRF evaluation, key-encryption-key derivation,
and AES-GCM wrapping needed for that flow.

## In scope

- JavaScript browser and Swift Apple APIs with equivalent models and behavior.
- Operation-specific capability reporting for enrollment and recovery.
- Passkey creation and assertion ceremonies; recovery permits non-platform
  credentials.
- Wrapping, recovering, and optionally rewrapping keys with a cached PRF result.
- Exactly 32-byte keys for the first public scope.
- Host-supplied, opt-in synchronous storage for PRF cache and credential
  metadata.
- Adapters between generic kit models and existing Tinfoil application records.

## Out of scope

- Server authentication. The kit does not issue or verify login sessions,
  validate WebAuthn assertions on a server, or replace an identity provider.
- Hosted storage, accounts, synchronization, backup, retention, or cloud policy.
- Clerk, enclave, inventory, UI, and application recovery-routing behavior.
- Android, server, or non-browser JavaScript support.
- Feature flags, a new cryptographic wire format, or server data migration.
- Generic stable-key-ID derivation, including a `deriveStableKeyId` API.
- Production storage implementations. Storage types and examples define only
  the integration interface.

The package keeps Tinfoil branding. Its key profile and wrapped-key models are
vendor-neutral so applications can use the cryptographic contract without
depending on Tinfoil application services.
