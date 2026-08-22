# Security Boundary

## Assets and trust boundaries

The protected assets are the raw 32-byte content-encryption key, WebAuthn PRF
output, and the derived key-encryption key. The credential ID, profile metadata,
IV, and wrapped ciphertext are non-secret metadata, although applications may
still treat them as sensitive account data.

The authenticator evaluates PRF after user verification. The kit receives the
PRF output, derives a non-extractable AES-256-GCM key where the platform allows,
and briefly handles plaintext key bytes during wrap or recovery. Host code owns
those bytes before wrapping and after recovery. Host-provided storage forms a
separate trust boundary because a cached PRF result can derive the wrapping key.
Storage is explicit opt-in and synchronous in v0.2; synchronous access does not
make the stored secret safer. Each cached result carries a full profile snapshot
so the manager can reject state from another derivation domain.

The advanced `evaluateCredential` API returns raw PRF output to host code. That
output can rederive the KEK and recover matching wrapped keys. It must not be
logged, sent to a server, or retained without protections equivalent to key
material. High-level applications should prefer `recoverKey`.

The advanced explicit-PRF wrap and unwrap methods extend that exposure without
starting another ceremony. They do not cache the PRF result, but host code still
holds raw secret material while calling them. Inputs are validated against the
manager profile, credential encoding, fixed key and PRF lengths, and wrapped-key
shape; validation does not make an exposed PRF result safe to retain.

## Challenge limitation

The kit generates a fresh random challenge locally. This prevents accidental
challenge reuse within the local ceremony, but no server issued or tracks that
challenge. The ceremony therefore authorizes local PRF use only. It does not
authenticate the user to a server, prove freshness to a server, or provide a
server-verifiable WebAuthn login assertion.

## Threat boundaries

- PRF caching removes the user-verification prompt from cache-only recovery.
  Anyone who reads the cache and wrapped record can attempt offline recovery.
  Storage is opt-in and should use platform protection appropriate to the app.
- The optional browser local-storage adapter stores PRF output where same-origin
  JavaScript can read it and is explicitly insecure. The optional Keychain
  adapter uses device-local protection, but a compromised application or device
  remains in the trust boundary. Neither adapter is enabled by default.
- JavaScript cannot protect keys from script executing in the same origin. XSS
  can read cached material, invoke ceremonies, or exfiltrate recovered keys.
- A compromised device or authenticator can expose keys while they are in use.
  Hardware-backed passkeys do not make host memory or application code trusted.
- Recovery may use synced, cross-device, or security-key credentials. Platform
  attachment is an enrollment capability requirement, not a recovery boundary.
- A malicious server can withhold, replace, replay, or delete wrapped records.
  AES-GCM detects ciphertext modification but does not provide availability,
  account authorization, record ordering, or rollback protection.
- The kit does not trust Clerk sessions, enclave responses, or application
  inventory. Applications must establish those trust relationships separately.

## Metadata and wire assumptions

The current interoperable profile uses WebAuthn PRF output as HKDF-SHA-256 input
with an empty HKDF salt and the profile's `hkdfInfo`, producing a 256-bit KEK.
It wraps exactly 32 key bytes with AES-256-GCM, a fresh 12-byte IV, a 16-byte
tag appended to the ciphertext, and no additional authenticated data.

Credential IDs are unpadded base64url. `kekIvHex` and `wrappedKeyHex` are
lowercase, even-length hexadecimal. The wire record does not carry assertions,
challenges, PRF output, plaintext keys, or KEKs. A `PasskeyKeyProfile` contains
exactly the version, relying-party ID, PRF salt, and HKDF info. The
relying-party name configures ceremony presentation and is not profile identity.
v0.2 accepts only profile version 1. An adapter may reconstruct that profile for
a legacy record only when the application already knows its derivation contract.
A manager is bound to one profile and rejects wrapped keys or cached PRF results
whose full profile does not match; callers cannot override the profile for an
individual operation.

The public `WrappedKeyRecord` JSON has exactly `version`, `profile`,
`credentialId`, `kekIvHex`, and `wrappedKeyHex`. Profile bytes use unpadded
base64url, while runtime models retain byte arrays. JavaScript and Swift apply
identical encoding and validation; record and profile versions must both be 1.

This effort retains that layout. It introduces no new cryptographic format,
server migration, downgrade protocol, compatibility negotiation, or generic
stable-key-ID derivation.
