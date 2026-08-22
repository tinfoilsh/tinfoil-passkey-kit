# Wrapped Key Repository Example

Applications own wrapped-record persistence. Store the canonical record emitted
by the package rather than serializing `Uint8Array` values directly:

```ts
interface WrappedKeyRepository {
  save(record: string): Promise<void>;
  list(): Promise<string[]>;
}
```

Use `encodeWrappedKeyRecord` before saving and `decodeWrappedKeyRecord` after
loading. The [web example](../Examples/Web/main.js) and
[Apple example](../Examples/Apple/Sources/PasskeyKeyAppleExample/PasskeyKeyExample.swift)
provide in-memory implementations. Production repositories must scope records
to the application's account model. This interface is an application example,
not part of the core package API.
