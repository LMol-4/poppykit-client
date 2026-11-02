# Changelog

## 0.6.3 — 2026-11-02

Reject reflected company credentials before persistence and exposure; preserve owner-scoped recovery and uncertainty.

### Consent and approval

- Verify same-account additional consent using advertised OAuth introspection; refuse mismatches or unavailable continuity evidence without replacing old authority.
- Export exact structured operation comparison with explicit semantic limits.

### Correctness and interoperability

- Client metadata may omit `redirect_uris`; omission registers no callbacks. The
  public `ClientMetadata.redirect_uris` type is optional; consumers that inspect it
  must use `redirect_uris ?? []`. Supplied arrays remain validated, and Direct
  Sign-In still requires a registered callback.
- `renew` rejects fragment-bearing and malformed resource URLs before claiming a
  grant or sending a token request. Abstract absolute identifiers such as `urn:`
  remain valid inputs; the issuer decides which resources it permits.
- Streaming releases unfinished-text accounting on completed message events;
  the 1 MiB unfinished/frame and 16 MiB stream limits still apply.

No schema, stored-record, configuration or dependency migration. Preserve pending
operations and credentials; publish and pin the coordinated SDK release before
consumer deployment. This entry describes local source, not a published version.

Local migration block2 adds Operations v2 codecs, negotiated API/MCP/conversation mechanics and durable trusted-consent attempt storage/recovery. See [OPERATIONS.md](OPERATIONS.md). This is a local SDK checkpoint, not full CLI integration or package publication.

## 0.6.1 — 2026-11-01

Handle PostgreSQL socket loss while an SDK transaction or migration owns a
checked-out connection. Invalidate failed transaction handles, discard broken
connections, and preserve the original migration error when rollback also fails.
A failed COMMIT still requires durable-state reconciliation before retry.

## 0.6.0 — current-spec core migration

Separate delegated resource Sessions from OAuth account grants; discover issuers and
service resources independently; support issuerless Companies, Bearer/DPoP tokens,
current mediated grants, code-only browser joining, current errors and feedback.
Client auth records upgrade to v3; reference issuer records upgrade to v5 without
resetting credentials or pending/recovery records. Stop old writers before opening
upgraded stores. Retired public APIs are removed; see [AUTH.md](AUTH.md) and
[STORAGE.md](STORAGE.md). Breaking local migration candidate; publication requires the recorded release gates.

## 0.5.0 — 2026-10-28

Historical snapshot of Personal Agent Protocol draft 0.3; the current live contract supersedes this entry. Break discovery, Session Key/token, author, browser-controller and feedback contracts; retain explicit storage subpaths. Upgrade normalized auth state 1→2; stop old writers and reset incompatible conversation/outbox state before cutover.

Local migration candidate only. Publication and deployment require separate approval.

## 0.4.1

Support Node 24.21.0 and later within Node 24 under the owner-accepted runtime policy.
Build, verification and publication tooling read .node-version.

## 0.4.0

Require Node 24 >=24.22.1 within 24.x. Accept conforming OAuth callback fields,
decode chunked UTF-8 strictly and bound durable terminal-operation history.
Custom auth stores must implement the documented `history` selection. The
explicit provider Postgres adapter can enlist in a guarded host transaction for
atomic consent delivery; protocol-only imports still load no database drivers.
Required release verification now includes isolated PostgreSQL contracts.

## 0.3.1 (release candidate)

Allow 30 seconds of provider clock skew in the local assertion freshness check,
including browser joins. Already-expired assertions remain rejected; the issuer
still verifies signatures, signed lifetime and replay. Safe errors now distinguish
clock/expiry, malformed responses, provider authorization, rate limits and network
failure. No wire protocol, storage format or dependency change.

## 0.3.0 (release candidate)

Add the optional challenge-bound browser enrollment client under `/provider`.
Existing provider APIs, storage adapters and all protocol authentication methods
retain their contracts. Enrollment secrets remain caller-controlled.

## 0.2.0 (release candidate)

Add bundled Postgres auth/conversation/provider stores and explicit migrations. Provider APIs and targeted storage transactions are asynchronous; await callback/result/revocation operations. SQLite and explicit legacy local-store migration remain supported.

## 0.1.1

Documentation refresh: registry installation, runnable quickstarts, focused guides
and the tagged GitHub/OIDC release runbook. No runtime API, storage format or
third-party dependency change.

## 0.1.0

Initial MIT development release, published manually. Discovery, safe HTTPS, all
three sign-in methods, targeted durable storage and recovery, conversations and
API/browser/feedback hooks. The CLI uses the client SDK with trusted secure-backend
adapters. J8 established strict typed tests and exact installed-artifact checks.

Version 0.x may still change APIs/storage; future changes must explain compatibility,
migration/reset and security implications. No stable 1.0 or external-host certification
is promised. Older private 0.0.0 candidates retain their own historical evidence.
