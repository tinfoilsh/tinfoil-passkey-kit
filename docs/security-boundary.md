# Security Boundary

## Assets and trust boundaries

The protected assets are the raw 32-byte content-encryption key, WebAuthn PRF
output, and the derived key-encryption key (KEK). The credential ID, profile
metadata, IV, and wrapped ciphertext are non-secret metadata, although
applications may still treat them as sensitive account data.

The authenticator evaluates PRF after user verification. The kit receives the
PRF output, derives a non-extractable AES-256-GCM key where the platform allows,
and briefly handles plaintext key bytes during wrap or recovery. Host code owns
those bytes before wrapping and after recovery.

Host-provided storage is a separate trust boundary because a cached PRF result
can derive the KEK. Raw PRF output returned by `evaluateCredential`, or passed
to the explicit-PRF wrap and unwrap functions, can likewise recover matching
wrapped keys and must be protected like key material.

## Challenge limitation

The kit generates a fresh random challenge locally. No server issues or tracks
it, so the ceremony authorizes local PRF use only. It does not authenticate the
user to a server, prove freshness to a server, or provide a server-verifiable
WebAuthn login assertion.

## Threat boundaries

- PRF caching removes the user-verification prompt from cache-only recovery.
  Anyone who reads the cache and wrapped record can attempt offline recovery.
- The browser local-storage adapter stores PRF output where same-origin
  JavaScript can read it. The Keychain adapter prevents syncing and access
  while locked, but does not restore a passkey prompt after unlock.
- JavaScript cannot protect keys from script executing in the same origin. XSS
  can read cached material, invoke ceremonies, or exfiltrate recovered keys.
- A compromised application, device, or authenticator can expose keys while
  they are in use. Hardware-backed passkeys do not make host memory or
  application code trusted.
- A malicious server can withhold, replace, replay, or delete wrapped records.
  AES-GCM detects ciphertext modification but does not provide availability,
  account authorization, record ordering, or rollback protection.
- The kit does not trust authentication sessions, enclave responses, or
  application inventory. Applications must establish those trust relationships
  separately.

## Wire format

The profile uses WebAuthn PRF output as HKDF-SHA-256 input with an empty HKDF
salt and the profile's `hkdfInfo`, producing a 256-bit KEK. It wraps exactly 32
key bytes with AES-256-GCM, a fresh 12-byte IV, a 16-byte tag appended to the
ciphertext, and no additional authenticated data.

The wire record does not carry assertions, challenges, PRF output, plaintext
keys, or KEKs. Its encoding is defined in the [API contract](api-contract.md).
A manager rejects wrapped keys and cached PRF results whose full profile does
not match its own. An adapter may reconstruct the profile for a legacy record
only when the application already knows its derivation contract.
