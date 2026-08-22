# Contributing

## Setup

Install Node.js 20 or 22, npm, Xcode with the Swift 5.10 toolchain, and the
macOS 15 SDK. Then install JavaScript dependencies:

```sh
npm ci
```

## Tests

Run the JavaScript checks:

```sh
npm test
npm run typecheck
npm run build
```

Run the Swift checks:

```sh
swift test
swift build -c release -Xswiftc -strict-concurrency=complete
```

Compile the standalone Apple example with:

```sh
swift build --package-path Examples/Apple
```

## Interoperability changes

Changes to profiles, key derivation, codecs, or wrapped records must update
`Fixtures/interop.json`. JavaScript and Swift tests must consume the same
fixture values and continue to open records produced by the other language.
Keep deterministic IV control internal to tests; do not add it to a public API.

Real WebAuthn PRF behavior requires manual testing with real authenticators.
Record results against the matrix in [docs/support-matrix.md](docs/support-matrix.md).

## Versions and tags

The npm package and Swift package use the same repository version. Before 1.0,
minor versions may contain breaking changes. A release tag must exactly match
`v<package.json version>`, including prerelease suffixes. For example, package
version `0.2.0-beta.1` uses tag `v0.2.0-beta.1`. This repository does not infer
versions from branch names.
