# Web example

This static example generates a 32-byte key, enrolls a PRF-capable passkey,
stores its canonical record in memory, recovers the key, and exposes advanced
PRF evaluation. It demonstrates key wrapping, not login or server
authentication.

First replace the profile's `example.com` relying-party ID in `main.js` with
`localhost`. Then build the root package and serve the repository:

```sh
npm run build
npx serve .
```

Open only the localhost URL printed by `serve`. Browsers treat localhost as a
secure context for WebAuthn, and the relying-party ID must match localhost. Do
not use the network or LAN URL unless the profile relying-party ID and a secure
origin are deliberately configured for that host. Reloading clears the
in-memory repository.
