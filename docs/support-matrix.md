# Support Matrix

## Web

The JavaScript package targets current secure-context WebAuthn implementations.
Maintainers manually verify PRF ceremonies on real authenticators before a
release; CI cannot exercise authenticator PRF support.

| Browser | Maintainer test matrix | Notes |
| --- | --- | --- |
| Chrome | Current and previous stable on macOS and Windows | Platform passkey and one hybrid recovery flow |
| Edge | Current stable on Windows | Platform passkey and one hybrid recovery flow |
| Safari | Current stable on macOS and iOS | Platform or synced passkey |
| Firefox | Not currently claimed | PRF availability depends on browser and authenticator support |

WebAuthn requires HTTPS, except the browser's special `localhost` development
context. The relying-party ID must match the page's registrable domain. An
iframe also requires an appropriate Permissions Policy.

`capability()` is advisory. A browser may expose WebAuthn without the selected
authenticator returning PRF output. Hybrid, synced, and security-key recovery
depend on the browser, operating system, account state, and authenticator.

## Apple

| Platform | Package floor | PRF behavior |
| --- | --- | --- |
| iOS | 18.0 | Platform, synced, and cross-device passkey recovery |
| macOS | 15.0 | Platform, synced, and cross-device passkey recovery |

Apple apps need the `webcredentials` associated-domain entitlement and a valid
`apple-app-site-association` file. The host must provide an active `UIWindow`
or `NSWindow` through `PasskeyPresentationAnchorProviding`.

Apple has no reliable PRF preflight, so capability may be `unknown`; allow the
ceremony and handle its result. Explicit security-key PRF is not enabled
because the baseline toolchain does not provide that API.

Simulator and unit tests do not establish real PRF support. Manually test at
least enrollment, same-device recovery, synced or hybrid recovery, cancellation,
and an unsupported authenticator on real devices used by the release matrix.
