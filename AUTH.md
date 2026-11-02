# Authentication lifecycle

`createClientAuth` owns discovery, local Sessions, Direct/Device/Mediated OAuth,
refresh rotation, revocation and abandoned-operation recovery. Call `recover()`
on startup. A dispatched exchange with an ambiguous result is never replayed.

`start(domain)` creates a random Session ID and a pairwise User ID for the verified
Company identifier: its issuer, or `https://{organization.domain}` when issuerless.
The User ID is stable across Sessions. No token request is needed to start or use
a signed-out Session. Changing the Company identifier never transfers its identity,
grants or pending work. Domain discovery errors do not establish an issuerless Company.

Every protected request gets a fresh ES256 `Poppy-Session` JWT, bound to its final
method, URL without query/fragment, Company identifier and Session/User identity.
A private delegated key and root-signed `pap-delegation+jwt` vouch for the request;
the root key does not sign Session JWTs directly. Delegated keys are private to one
User ID at one Company. A token-bearing request also binds the token with `ath`.
OAuth endpoints receive client assertions and optional DPoP, without a Session JWT.

OAuth account grants are independent of Sessions. To reuse one explicitly:

```ts
const other = await auth.start(domain, { accountFrom: signedInConnectionId });
```

The source must belong to the same local user/client namespace and Company, be
regular rather than anonymous, and have an active grant. The new Session has its
own sid and signing keys. Refresh rotation is serialized on the shared grant;
ambiguous rotation stops every Session using it. A definite `invalid_grant` clears
the shared grant and continues those Sessions signed out.

Use `authorization(id, scopes)` for current granted/missing scopes and eligible
methods. Scopes may be documented outside `scopes_supported`; hints and descriptions
do not authorize anything. Direct requires a registered callback, high-entropy
browser binding, PKCE and exact callback `iss`. HTTPS callbacks stay on the client
metadata domain; RFC 8252 loopback IP callbacks permit only the port to vary.
The `dpop_jkt` is an OAuth proof-key binding, not the Poppy Session identifier.

Direct and Device are for the human's own sign-in and consent. Show the checked
Device link and code; keep the private device code out of model context. Never
complete the approval page for the User. Prefer Direct where viable, then Device.
Mediated v1 is transitional: the `mediated-sign-in` extension declares trusted
credential fields/scopes, and the issuer's token endpoint accepts
`https://personalagentprotocol.org/grant/mediated-sign-in` as a form grant.
Continuation sends `sign_in_id` and `one_time_code`, without original credentials
or scope. `TrustedInput` runs outside model tools and must not retain/log values.
The SDK clears supplied credential/code objects on exit and persists neither.

Initial sign-in works without account introspection. Additional consent requires
an issuer-authenticated subject from an advertised RFC7662 introspection endpoint
that allows this client to inspect its own refresh grants. The SDK stores only a
hash bound to issuer/client/subject. Before activating a replacement it compares
the new grant's subject with the old one. Different accounts fail account_mismatch;
missing/inactive/unavailable evidence fails account_continuity_unavailable. The
old grant and Session remain authoritative, and the rejected grant is parked for
revocation. Legacy grants can establish their anchor by introspecting the current
refresh token before beginning additional consent. If that is unavailable, use
explicit disconnect/reconnect. Token text, Session IDs and HTTP success never prove
account identity. Successful same-account replacement creates a fresh Session and
new grant authority; old business approvals/uncertain work never adopt it.
Partial grants
report granted/missing scopes. Replacement preserves old required scopes unless
`requiredExistingScopes` explicitly narrows that requirement; grants are not unioned.
An old refresh grant is retired when no other local Session still references it.
Accepting a newer grant does not expand a browser cookie's approved scopes.

Access requests use the response's Bearer or DPoP scheme. Missing `expires_in` uses
a conservative local 60-second lifetime. Missing rotated `refresh_token` retains
the existing one. Resource metadata selects narrower API/conversation/MCP tokens;
see [INTEGRATIONS.md](INTEGRATIONS.md). A definite `invalid_session` restarts once
with a new sid and fresh signatures, then stops. Feedback replaces a definitely
ended sid but returns the failed POST without replay; an explicit later report
uses the new Session. Browser authorization can restart once before one code-only
browser submission. Session restart does not replay
an uncertain OAuth exchange or discard an otherwise valid account grant.

`signOut(id)` revokes every locally held refresh grant for that local User and
Company, clears their access credentials and continues regular Sessions signed out.
OAuth does not reveal a standard opaque account identifier, so this conservative
policy also signs out other accounts for that User at the same Company. Cleanup
references survive remote/vault failures; call `retryCleanup(id)`. A pending or
uncertain outcome is never reported as complete. Re-sign-in requires a User request.

`start(domain, { anonymous: true })` gets a fresh User ID, sid and private keys.
It never carries an account token. Sign-in ends it and starts a regular connection;
use the returned connection ID. Ending anonymous browsing deletes its local private
identity/key material, with durable cleanup references if deletion fails.

`AssertionProvider.assert` supplies constrained client authentication;
`delegate({operationId,jwk})` supplies a delegation for a locally generated public
key. `ProviderIdentity` supplies the authenticated Company-specific identity.
The optional bundled provider uses separate enrolled client identities; see
[PROVIDER.md](PROVIDER.md). A provider-only configuration cannot substitute its
regular identity for anonymous browsing. ES256 is supported directly; a host using
blind PS384 root signatures supplies its own assertion/delegation adapter and
protects cross-user isolation. Blind signing is not implemented by the bundled provider.

Private keys, refresh tokens, device codes and PKCE belong in the host SecretStore;
access tokens remain in process memory. The store and vault are separate commit
boundaries: sweep orphan staged secrets only after ownership checks and a grace
period. Preserve uncertain requests and cleanup references. See [STORAGE.md](STORAGE.md)
for record upgrades and [DELIVERY.md](DELIVERY.md) for operator-signature integration.

Delegations use coarse half-hour issuance buckets with a one-hour signed lifetime,
leaving 30–60 minutes at creation. Host providers may return a different valid
lifetime within the client's one-hour freshness bound. See [CONFORMANCE.md](CONFORMANCE.md).

Authentication lifecycle OperationRecord/operationId values never approve business operations. OAuth access consent, provider enrollment and mediated credential collection cannot supply business consent. [Operations v2](OPERATIONS.md) binds each actual user answer to the exact revision and request, and rechecks current Session/account authority for execution and protected replay.

For business-operation sends, pass the saved `BusinessClientContext` as the final `expectedContext` argument to `apiFetch`/`authorizedFetch`. Channel sender callbacks receive that context. A changed Company/client/User/account or signed-out Session fails before dispatch; target discovery does not authorize a replacement account. See [Operations](OPERATIONS.md).

A cross-browser host must prepare its owner-scoped capability separately, then
establish an unguessable browser secret in the human browser before calling
beginSignIn. Supply that same browser secret to completeSignIn; never replace the
check with a callback state lookup or bind it to the agent's different browser.
The host owns expiry, single-use capability, cancellation and initiating-owner
checks. The SDK continues to enforce PKCE, state, exact issuer and redirect.
