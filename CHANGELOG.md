# Changelog

## 0.5.0 (unreleased)

Target pinned Personal Agent Protocol draft 0.3. Break discovery, Session Key/token, author, browser-controller and feedback contracts; retain explicit storage subpaths. Upgrade normalized auth state 1→2; stop old writers and reset incompatible conversation/outbox state before cutover.

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
