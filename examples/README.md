# Examples

Configuration files that illustrate how to shape AegisAPI for different
situations. They contain settings only - never credentials.

| File | Purpose |
| --- | --- |
| `strict-scope.toml` | A tightly scoped, authorised engagement against named hosts. |
| `verbose-local.toml` | Debug-level development against a local mock API. |
| `petstore-openapi.yaml` | A small OpenAPI 3.0 document for trying discovery. |

Try one without touching your workspace:

```powershell
aegisapi --config examples\strict-scope.toml info
```

`aegisapi init` writes a fully commented starting point to
`%APPDATA%\AegisAPI\config.toml`; these files are variations on it.

These files configure the **tool-wide** allow-list. Per-target scope lives in
`targets.json`, which the CLI manages for you - there is no example file for it
because hand-editing it is not the supported path:

```powershell
aegisapi target add acme https://api.acme.test/v1 --exclude-path /v1/admin
aegisapi target scope acme https://api.acme.test/v1/orders
```

Credentials never appear in either file. An authentication profile stores the
*name* of an environment variable, which you set in your own shell per run.

## Trying discovery

```powershell
aegisapi target add demo https://api.example.test/v1 --exclude-path /v1/internal
aegisapi discover spec demo --file examples\petstore-openapi.yaml
```

The document is parsed locally and nothing is contacted. `/internal/metrics`
is declared in the specification but excluded from the target's scope, so it
appears as **out of scope** rather than being hidden - seeing what a document
declares beyond your engagement is the point.

Every example keeps `scope.enforce = true`. Only assess APIs you own or have
explicit written authorisation to test.
