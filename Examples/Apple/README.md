# Apple example

`PasskeyKeyExample` is app-style source that generates a 32-byte key, enrolls a
passkey, stores the canonical record through `WrappedKeyRepository`, recovers
the key, and exposes advanced PRF evaluation. It demonstrates key wrapping, not
login or server authentication.

Add `webcredentials:example.com` to the app target's Associated Domains
entitlement and host a valid `apple-app-site-association` file for that domain.
Replace the complete example profile consistently in web and Apple clients.
Construct `WindowPresentationAnchorProvider` with the app's active `UIWindow` or
`NSWindow`, then pass it to `PasskeyKeyExample`. The host owns that window and
must keep it suitable for presenting AuthenticationServices UI.

Compile the package from the repository root:

```sh
swift build --package-path Examples/Apple
```

Run ceremonies from app UI on a real iOS 18+ or macOS 15+ device. The simulator
and command-line package build do not establish real authenticator PRF support.
