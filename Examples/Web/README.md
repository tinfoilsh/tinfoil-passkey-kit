# Web example

This static example generates a 32-byte key, enrolls a PRF-capable passkey,
stores the wrapped record in memory, and recovers the key. It demonstrates key
wrapping, not login or server authentication.

First replace the profile's `example.com` relying-party ID in `main.js` with
`localhost`. Then build the root package and serve the repository:

```sh
npm run build
npx serve .
```

Open `http://localhost:3000/Examples/Web/` (or the URL printed by `serve`).
Browsers treat localhost as a secure context for WebAuthn, and the relying-party
ID must match localhost. Replace the example profile and user values for your
application. Reloading clears the in-memory repository.
