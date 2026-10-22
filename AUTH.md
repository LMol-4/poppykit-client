# Authentication lifecycle

`createClientAuth` owns Direct, Device and Mediated sign-in, token renewal,
replacement, revocation and abandoned-operation recovery. Call `recover()` on
startup. Another live process is never interrupted; an ambiguous dispatched
exchange is uncertain and must not be replayed.

Ask `authorization(connectionId, scopes)` for the current grant, missing scopes
and advertised methods. Choose a method explicitly in `beginSignIn`. Direct
requires an HTTPS registered callback and an authenticated browser binding.
Display its URL in the user's browser. Device returns a checked link/code and
company identity; call `continueSignIn(operationId)` when its deadline is due.
Do not automate user approval. Mediated calls the configured `TrustedInput`
adapter for declared fields and correlated one-time codes. Only trusted UI code
implements this adapter. Values are cleared after each submission and never
persisted by the SDK or exposed in public results. Input adapters must not log
values, keep copies, or return them through model tools.

First-time partial grants complete with `grantedScopes` and `missingScopes`.
Replacement preserves every old grant scope by default. An explicit
`requiredExistingScopes` subset permits dropping other old scopes. A rejected
replacement retains the previous grant and queues the new token for revocation;
accepted replacements queue the previous token instead. Grants are never unioned.
`force: true` represents an explicit user request to sign in again. Otherwise a
sufficient current grant is reused. Run `retryCleanup` to retry durable retirement.

Metadata is refreshed through the supplied resolver. A changed exact issuer or
saved destination fails with `metadata_changed`; start a new connection after
reviewing the new metadata. Saved work is never rerouted. Server Retry-After
deadlines are persisted as absolute decimal milliseconds, including enormous
values, and survive restarts without a local delay cap.

`start(domain, { anonymous: true })` uses a fresh identity and DPoP key. Ending
it deletes that private key and local identity; sign-in starts a new regular
connection/session. Consume the returned connection ID and do not transfer old
conversations. Regular issuer identity remains stable and separate.

Provider adapters implement J1's `AssertionProvider` and `ProviderIdentity`;
their authenticated identity supplies the issuer-specific UserID. Only purpose,
issuer and operation binding are passed for assertions, never arbitrary bytes
or claims. The operator must publish the signing key. For anonymous sessions a
separate local `IdentitySigner` is required and its key must also be published in
the client's JWKS. A provider-only configuration reports `anonymous_unavailable`;
it never substitutes the provider's stable identity for an anonymous one.

Account Tokens, device codes, PKCE and DPoP keys belong in the configured
SecretStore; Session Tokens stay in memory. SQLite and secret storage are separate
commit boundaries. A host must sweep orphan staged secrets only after checking
ownership and a grace period; crashes between stage and durable reference can
leave such orphans. Cancellation/revocation generation checks defeat late results.
Revocation stops future protected work and never automatically reconnects.
