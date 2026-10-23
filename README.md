# PoppyKit client

TypeScript SDK for personal-agent providers integrating [Personal Agent Protocol
draft 0.2](https://personalagentprotocol.org/docs/0.2/spec). Discover companies,
start sessions, use Direct/Device/Mediated sign-in, exchange JSON/SSE conversations,
authorize API requests, join an agent browser and send feedback. Your application
supplies the agent and trusted infrastructure.

## Installation

Requires Node **24.12.0 or later**, ESM and HTTPS. CI certifies Node 24.12.0;
later majors are not separately certified. Optional SQLite uses experimental
`node:sqlite` and local filesystem locking.

Version **0.1.0** is an initial development release candidate under the [MIT license](LICENSE).
It has not been published. Install a verified tarball:

```sh
npm install ./poppykit-client-0.1.0.tgz
```

The only production dependency is `jose@6.2.12`. No server SDK or CLI is required.
Registry installation instructions will accompany the first public release.

## Quickstart

Discovery needs no signing key, account token or database:

```js
import { createMetadataResolver, createNodeTransport } from '@poppykit/client';

const transport = createNodeTransport();
try {
  const company = await createMetadataResolver(transport).resolveCompany('company.example');
  console.log(company.document.organization);
} finally {
  transport.close?.();
}
```

Replace `company.example` with a company publishing draft 0.2 discovery.
Run the complete [quickstart](examples/quickstart.mjs) with a real domain, or
`node examples/quickstart.mjs --self-check` for a deterministic offline example.

## Configuration and authentication

`createClientAuth(options)` owns sessions, all three sign-in methods, renewal,
scope replacement, sign-out and recovery. Supply `namespace`, `localUserId`,
`clientId`, registered `redirectUris`, an `AuthStore`, `SecretStore`, safe transport
and metadata resolver. Run `recover()` at startup. Publish HTTPS client metadata
and public JWKS; private signing keys stay in your signer or provider.

Choose an `IdentitySigner`, or authenticated `AssertionProvider` and
`ProviderIdentity` adapters. The optional `/provider` reference is documented in
[PROVIDER.md](PROVIDER.md). Operators supply HTTPS hosting, enrollment authentication,
company policy and signing/KMS. Anonymous sessions require a separate local signer
with a published key; provider-only custody reports `anonymous_unavailable`.

Call `start(domain)`, then `authorization(connectionId, scopes)` to inspect grants,
missing scopes and advertised methods. `beginSignIn(connectionId, { method, scopes })`
selects `direct`, `device` or `mediated`. Direct requires an authenticated browser
binding and HTTPS callback. Device displays a verified human link/code and resumes
with `continueSignIn`. Mediated invokes your `TrustedInput.collect` UI. Keep that UI,
passwords, codes and credential adapters outside model tools. See [AUTH.md](AUTH.md)
for partial consent, scope upgrades, cancellation and revocation.

## Examples and common operations

Configure conversations using the verified target and the same auth lifecycle:

```js
import { createConversationClient } from '@poppykit/client';
const target = await auth.target(connectionId);
const conversations = createConversationClient({
  ...target, connectionId, store: conversationStore, clock: { now: Date.now },
  authorizedRequest: request => auth.authorizedFetch(connectionId, request, target),
  authorization: (id, scopes) => auth.authorization(id, scopes),
});
```

`auth`, `connectionId` and `conversationStore` are your configured instances.
`start`, `send`, `read`, `watch`, `ack`, `handoff` and `close` manage the lifecycle.
Retain message IDs for retries; acknowledge durable deliveries after processing.
[DELIVERY.md](DELIVERY.md) explains cursors, streaming, pagination and retention.

Use `apiTarget`/`apiFetch` with an existing OpenAPI or MCP client. The final URL
must be independently authorized; an OpenAPI `servers` entry grants no authority.
`joinBrowser` accepts a trusted agent-controlled controller separate from human
consent. `feedback` sends a single `missing` report expecting empty HTTP 202.
[INTEGRATIONS.md](INTEGRATIONS.md) documents the adapter contracts and examples.

## Errors, cancellation, retries and limits

Handle `AuthFailure.code` and `ConversationError.code`; do not parse messages or
log credential headers/private adapter errors. Pending operations are resumable;
an uncertain remote exchange requires reconciliation and is never silently replayed.
Declined upgrades preserve old access; sign-out never automatically reconnects.

Conversation operations accept `AbortSignal`. Cancellation cannot undo bytes sent.
Conversation retries retain message IDs/payloads with bounded backoff and Retry-After.
Auth deadlines persist across restarts. Feedback has no automatic POST retry or
deduplication promise. Pools, bodies, event/page sizes and reconnects are bounded;
see [DELIVERY.md](DELIVERY.md). External effects need application idempotency.

## Storage and production responsibilities

Optional `/sqlite` exports `SqliteAuthStore` and `SqliteConversationStore`;
`/memory` exports non-durable `MemoryConversationStore`. Consumers can implement
the targeted contracts using their own databases. Store Account Tokens, DPoP keys
and PKCE in a secure `SecretStore`; Session Tokens stay in memory. SQLite stores
secret references and private message data, not vault encryption. Database, vault
and remote exchange are separate boundaries; implement orphan-secret reconciliation
and deployment ownership checks. [STORAGE.md](STORAGE.md) defines atomicity,
recovery and explicit development reset.

## Reference and support

[API.md](API.md) maps public exports and TypeScript declarations to deeper guides.
This independent draft implementation has deterministic and packaged tests;
production vaults, browsers, external issuers and hosting need operator validation.
Individual protocol extensions and application business logic are outside the SDK.
See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md),
[CHANGELOG.md](CHANGELOG.md) and [RELEASING.md](RELEASING.md). No public license grant
has been selected; publication remains blocked pending the owner's license decision.
