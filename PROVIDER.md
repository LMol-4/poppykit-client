# Optional identity provider

`createBrowserEnrollmentClient` from this subpath is an optional hosting-service
client. It is independent of company consent and leaves all secret custody with
the caller. Configure an HTTPS enrollment URL on the provider origin; call
`start(SHA256(verifier))`, show only its public `browserUrl`, then call
`status(requestId, verifier)` from trusted code. A ready response contains the
credential for immediate secure staging, never for model output. `cancel` revokes
failed/uncertain delivery; hosts must consume results once, retain replay
tombstones and revoke on failed/lost retrieval. The CLI implements that workflow.
This optional service uses version1 JSON requests and is not a Poppy extension.

Import `createProvider`, `createProviderClient`, and `createResultCipher` from
`@poppykit/client/provider`; durable `SqliteProviderStore` is separately exported
from `@poppykit/client/provider/sqlite`. Neither is loaded by the core import.
The wire protocol remains PoppyKit provider **v1**; the 0.2 TypeScript API uses async storage, not a Personal Agent Protocol extension.
Node 24.x (at least 24.21.0) is required for the SQLite reference adapter.

An operator supplies HTTPS hosting, a provider client metadata URL, JWKS URL,
HTTPS callback URL on that same domain, an ES256 signer/KMS, a verified company
metadata resolver, authenticated enrollment and encrypted callback-result storage.
The provider has no company account-token vault, token-exchange proxy, login UI,
deployment dependency or cloud dependency.

HTTP JSON is limited to 16 KiB of UTF-8 bytes. Chunk boundaries preserve Unicode;
invalid/truncated UTF-8 fails before enrollment, signing or operation creation.
Callbacks accept optional OAuth error details and unknown response fields while
checking state/issuer, destination and duplicate recognized fields. An identical
callback after consumption acknowledges `consumed` without recreating ciphertext;
a changed callback conflicts. `takeResult` remains one-time, including after restart.

`ProviderError` codes `unauthorized`, `expired` and `canceled` are definite
rejections. `consumed` means retrieval already happened and does not prove the
caller staged its result. Network failure, `unavailable` and `invalid_response`
are ambiguous; preserve uncertainty rather than repeating one-time retrieval.
`rate_limited` carries a retry deadline. Never expose raw errors, credentials,
assertions or callback URLs through model tools.

Postgres hosts can explicitly enlist the store in their existing transaction:

```js
await companyDatabase.withTransaction(async connection => {
  await providerStore.withTransaction(connection, async () => {
    const callback = await issuer.completeAuthorization(id, browserBinding, decision);
    await provider.callback(callback.href);
    await saveHostReceipt(connection); // host-owned bounded SQL
  });
});
```

The handle must come from `PostgresCompanyDatabase.withTransaction` (or an
equivalent host guard that rejects expired/escaped handles), on the same database
with the required provider schema privileges. Normal operations still use the
configured provider pool; enlisted operations never fall back to it. The host
owns commit/rollback and must propagate failures to abort the whole transaction.
Only bounded SQL and synchronous cryptography belong in the scope; no HTTP,
model, signing service or other remote work. Persist the authenticated human
decision first, then issue the code, provider-ready callback and host receipt in
one atomic transaction. A rolled-back attempt can retry that decision; an
uncertain one-time code/token redemption must never be retried. Escaped participant
work fails closed. Code/consent lifetimes are unchanged.

```js
import { createProvider, createResultCipher } from '@poppykit/client/provider';
import { SqliteProviderStore } from '@poppykit/client/provider/sqlite';
const provider = createProvider({
  clientId: 'https://identity.example/client.json',
  jwksUri: 'https://identity.example/jwks',
  callbackUrl: 'https://identity.example/callback', clientName: 'Operator agent',
  store: new SqliteProviderStore('/private/provider.sqlite'),
  cipher: createResultCipher(await operatorKeys.readResultEncryptionKey()),
  signer: operatorKeys.signer, metadata: verifiedCompanyResolver,
  authenticateEnrollment: async request => {
    // Authenticate the human using the operator's existing login; validate CSRF.
    const human = await operatorLogin.authenticateEnrollment(request);
    return human ? { subject: human.stableSubject, allowedCompanies: human.companyDomains } : null;
  },
  verifySession: binding => operatorSessionVerifier.owns(binding),
});
// Route Fetch Requests under /v1/{operation}, plus the exact public URLs above:
// await provider.handle(request)
```

`operatorKeys`, `operatorLogin`, `operatorSessionVerifier` and
`verifiedCompanyResolver` are operator-owned adapters, not globals supplied by
the package. A session verifier must independently verify both the provider client
and derived UserID; an opaque session ID alone does not prove ownership. Browser
signing fails closed without that verifier. Starting a session signs a derived
UserID assertion; the company checks session/client/UserID association on renewals.

POST JSON operations use `version: 1` and `installationId`. Enroll additionally
takes a fresh `idempotencyKey`; private operations carry `Authorization: Bearer
<enrollmentId.secret>`. The secret is generated once and delivered only in that
authenticated enrollment response. A repeated enrollment key returns `consumed`;
lost credential delivery requires fresh human authentication and enrollment.
Installations have independent credentials and callback operations. Re-enrollment
can recover a visitor identity through the same authenticated operator subject,
but cannot recover another installation's result. Enrollment never accepts caller
subjects, arbitrary audiences, lifetimes, key IDs, raw bytes or signing claims.

`identity` takes domain and exact issuer; `begin` registers immutable operation,
issuer/domain, purpose (`session`, `client-authentication`, `browser`, `direct`),
optional session and browser return destination. Company metadata is independently
resolved and enrollment company policy checked. `assert` takes operation/purpose
only and constructs a 60-second assertion with fresh 256-bit jti. Browser assertions
are audience-bound to the verified browser endpoint. `createProviderClient` binds
enrollment credentials and automatically registers SDK assertion operations.

Direct sign-in uses SDK-generated 256-bit state. Trusted CLI code privately
registers it with `beginDirect` after SDK preparation and before displaying the
authorization URL. Only its hash is indexed. The callback accepts state, exact
issuer, and exactly one code/error; result ciphertext is sealed atomically with
the immutable binding. Identical pending callbacks are harmless; conflicting,
canceled, expired and consumed callbacks fail. `takeResult` requires enrollment,
installation, operation, issuer and exact `sessionKey` thumbprint from the SDK's
authorization URL `dpop_jkt`; the local `Connection.sessionId` cannot identify a
company Session. Old Direct operations without the key binding must restart.
Retrieval consumes within the same
storage transaction before returning private callback data. Lost retrieval delivery
is uncertain, never a reason to exchange or retrieve again. SDK code owns PKCE and
the exchange. Never log request URLs or responses on this route.

SQLite serializes writers across processes. Provider transactions must be
synchronous, targeted and atomic; custom stores implement `ProviderStore` with
the same guarantees. The AES-GCM result key comes from an independent secure
backend and must never be stored beside the database. Cipher failures roll back
consumption. KMS failures fail closed; a revoke/cancel racing signing is rechecked
before delivery. External stores/KMS are separate failure boundaries.

Defaults bound enrollments globally to 10,000, pending operations to ten per
enrollment, assertions to 60/minute, operation lifetime to ten minutes and request
bodies to 16 KiB. A hard cap of 1,000 retained operations per enrollment keeps
quota/cleanup/revocation scans complete even under tombstone flooding. Expired
operations are cleaned in bounded batches on begin;
tombstones survive expiry plus 30 seconds. Hosts must additionally enforce
per-human enrollment rate limits, ingress rate/connection/time limits, total
database retention, and authenticated account recovery. Rate-limit responses
include a retry timestamp. Errors contain fixed codes only.

Rotate signer configuration only after publishing the new key. Supply
`publishedKeys` during rotation and retain old public keys until every assertion
expires plus 30-second skew; never publish private JWK fields. The operator owns
the publication grace period and KMS key lifecycle.

Enrollment revocation stops new signing/retrieval and cancels pending results.
It cannot invalidate delivered assertions, existing company Session Tokens,
Account Tokens or DPoP keys. Revoke company authorization **before** disabling
provider signing, or use authenticated company account controls afterward.
This is scoped authority, redaction and provider key custody; it does not isolate
authority from unrestricted programs running as the same OS user.

## Migrating provider code to 0.2

Await every provider operation, including `callback`, `takeResult`, `cancel` and
`revokeEnrollment`; HTTP callback success is returned only after storage commits.
Use rejected-Promise assertions for failures. Signer, enrollment authentication,
metadata and session verification stay outside storage transactions; ResultCipher
remains synchronous local cryptography.

`ProviderSelection` declares enroll, identity, operation, begin, callback or revoke.
Remote stores load and lock only that aggregate; out-of-selection access and thenable
callbacks reject. Enroll locks a namespace capacity counter; identity mapping locks
visitor/full-issuer keys across installations; callbacks re-resolve state after the
enrollment fence. Begin/revoke inspect at most 1,001 operation rows. All valid Unicode
operation IDs count toward limits and revocation. Existing SQLite databases retain
records and initialize the capacity counter from their enrollment rows.

For an existing local synchronous custom store, explicitly wrap it with
`adaptLegacyProviderStore(legacyStore)`. This migration helper ignores selections
and cannot turn local synchronous I/O into remote persistence. New remote/custom
stores implement the targeted contract directly. The bundled Postgres adapter is
`PostgresProviderStore` from `@poppykit/client/provider/postgres`; see
[storage](STORAGE.md) for explicit migrations, TLS and lifecycle.
