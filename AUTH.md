# Authentication lifecycle

`createClientAuth` owns Direct, Device and Mediated sign-in, token renewal,
replacement, revocation and abandoned-operation recovery. Call `recover()` on
startup. Another live process is never interrupted; an ambiguous dispatched
exchange is uncertain and must not be replayed.

Discovery accepts only draft 0.3, checks the final well-known path (including
cache revalidation), exact issuer and reciprocal `protected_resources`.
`signInMethods(metadata)` derives Direct/Device from issuer grants and endpoints
and uses `scopes_supported`; Mediated keeps `auth.mediated.scopes`. Company scope
names cannot start with `poppy:`. Descriptions come from `auth.scopes` or a listed
OpenAPI document. Prefer Direct when the user can receive its callback; Device is
for appropriate device-flow situations. No sign-in method is user consent.

Ask `authorization(connectionId, scopes)` for the current grant, missing scopes
and advertised methods, with `scopeDescriptions` from `auth.scopes`. Choose a method explicitly in `beginSignIn`. Direct
requires an HTTPS registered callback and an authenticated browser binding.
Display its URL in the user's browser. Device returns a checked link/code and
company identity; call `continueSignIn(operationId)` when its deadline is due.
Do not automate user approval. Mediated calls the configured `TrustedInput`
adapter for declared fields and correlated one-time codes. Only trusted UI code
implements this adapter. Values are cleared after each submission and never
persisted by the SDK or exposed in public results. Input adapters must not log
values, keep copies, or return them through model tools.

Direct callbacks accept OAuth error details and ignore unknown response fields.
The registered origin/path/query, browser binding, state and exact issuer still
have to match; duplicate recognized fields and a simultaneous code/error fail.
Error descriptions and error URLs are never included in public auth outcomes.

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

Provider `expiresAt` values are Unix seconds. Session/client assertions and browser
joins accept a local freshness horizon of 60 seconds plus 30 seconds of clock skew;
an assertion at or before the local current time is rejected. This freshness check
does not verify the signed assertion's lifetime: the issuer verifies the signature,
claims, replay and protocol maximum of five minutes between `iat` and `exp`.
`provider_clock_skew` and `provider_assertion_expired` suggest checking automatic
date/time and retrying. `provider_invalid_response`, `provider_unauthorized`,
`provider_rate_limited` and `provider_network_error` distinguish malformed data,
enrollment rejection, throttling and connectivity. Unknown failures remain
`provider_unavailable`. Errors never include assertion or provider response text.

Account Tokens, device codes, PKCE and DPoP keys belong in the configured
SecretStore; Session Tokens stay in memory. SQLite and secret storage are separate
commit boundaries. A host must sweep orphan staged secrets only after checking
ownership and a grace period; crashes between stage and durable reference can
leave such orphans. Cancellation/revocation generation checks defeat late results.
Revocation stops future protected work and never automatically reconnects.
