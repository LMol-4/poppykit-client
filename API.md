# API reference

Every export has an accompanying `dist/*.d.ts` declaration; use editor completion
for complete option/result types. This map describes the supported integration seams.

| Entry point | Main exports | Guide |
| --- | --- | --- |
| `@poppykit/client` | `createMetadataResolver`, `createNodeTransport` | [README](README.md), [delivery](DELIVERY.md) |
| `@poppykit/client` | `createClientAuth`, `AuthFailure`, authentication/identity/input types | [authentication](AUTH.md) |
| `@poppykit/client` | `createConversationClient`, `ConversationError`, `parseEventStream` | [delivery](DELIVERY.md) |
| `@poppykit/client` | `ApiTarget`, `AgentBrowserController`, `FeedbackReport` types | [integrations](INTEGRATIONS.md) |
| `@poppykit/client/sqlite` | `SqliteAuthStore`, `SqliteConversationStore` | [storage](STORAGE.md) |
| `@poppykit/client/memory` | `MemoryConversationStore` (non-durable) | [storage](STORAGE.md) |
| `@poppykit/client/provider` | `createProvider`, `createProviderClient`, `createResultCipher`, `createBrowserEnrollmentClient` | [provider](PROVIDER.md) |
| `@poppykit/client/provider/sqlite` | `SqliteProviderStore` | [provider](PROVIDER.md) |

ClientAuth methods include `start/get/list/target`, `authorization`,
`beginSignIn/continueSignIn/completeSignIn/cancelSignIn/operation`, `renew`,
`signOut/retryCleanup/recover`, `authorizedFetch`, `apiTarget/apiFetch`,
`joinBrowser` and `feedback`. Conversation operations bind one connection, issuer
and endpoint; never substitute profile names or model-provided URLs for that binding.

The [quickstart](examples/quickstart.mjs) is executed by CI. Integration examples
describe adapters your application supplies; they are not built-in browser drivers
or general API executors.

The optional Postgres entry point ships its adapters, `createPostgresPool`,
`postgresMigration`, `migratePostgres` and schema-version export; see [storage](STORAGE.md).
TypeScript Postgres consumers also install `@types/pg@8.23.1` as a development dependency.
