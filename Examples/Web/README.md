# Web example

This static example generates a 32-byte key, enrolls a PRF-capable passkey,
stores the wrapped record in memory, and recovers the key. It demonstrates key
wrapping, not login or server authentication.

Build the root package, then serve the repository from a secure context:

```sh
npm run build
npx serve .
```

Open `/Examples/Web/` on an HTTPS origin whose registrable domain matches the
profile's `example.com` relying-party ID. Replace the example profile and user
values for your application. Reloading clears the in-memory repository.
