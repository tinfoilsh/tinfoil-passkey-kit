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
make the stored secret safer.

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
exactly the version, relying-party ID and name, PRF salt, and HKDF info. An
adapter may reconstruct that profile for a legacy record only when the
application already knows its derivation contract.

This effort retains that layout. It introduces no new cryptographic format,
server migration, downgrade protocol, compatibility negotiation, or generic
stable-key-ID derivation.
