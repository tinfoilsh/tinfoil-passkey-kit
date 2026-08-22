# Wrapped Key Repository Example

Applications own wrapped-record persistence. A repository can be as small as:

```ts
import type { WrappedKey } from "@tinfoilsh/passkey-kit";

interface WrappedKeyRepository {
  save(wrappedKey: WrappedKey): Promise<void>;
  list(): Promise<WrappedKey[]>;
}
```

The [web example](../Examples/Web/main.js) and
[Apple example](../Examples/Apple/Sources/PasskeyKeyAppleExample/PasskeyKeyExample.swift)
provide in-memory implementations. Production repositories must scope records
to the application's account model and preserve the full profile. This
interface is an application example, not part of the core package API.
