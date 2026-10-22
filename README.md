# PoppyKit client

Personal-agent TypeScript SDK for discovery, authentication, sessions, and conversations.

Designed to be imported into an existing personal-agent product. The host supplies
its runtime, application identity, HTTPS metadata/callback hosting, signing and
credential-storage adapters. PoppyKit supplies protocol behavior; it does not
operate a managed agent or credential service. The CLI is optional.

The SDK design supports explicitly selected independent connections, including
multiple accounts at one company. Account-selection UI is a host policy.
Discovery can be used without authentication dependencies. Direct, Device and
Mediated sign-in share the lifecycle described in [AUTH.md](AUTH.md).
Interrupted exchanges and remote revocation failures
have explicit outcomes rather than silently retrying or reconnecting.

Demo applications are deferred and are not dependencies of this SDK.

Status (2026-10-22): unpublished implementation of discovery, all three sign-in
methods, anonymous sessions, credential lifecycle, and JSON conversations. Known correctness issues
remain; passing tests do not establish complete protocol conformance.

Targets the current [Personal Agent Protocol draft 0.2 specification](https://personalagentprotocol.org/docs/0.2/spec)
and [guides](https://personalagentprotocol.org/docs/0.2/guides).

The October 19 source pin is historical evidence, not overriding authority.
The reviewed implementation programme also adds streaming, feedback, API/browser hooks, and an
optional hosted-identity adapter/reference entry point. These are planned
capabilities, not features available in this checkout. Targeted durable storage
and authentication are available now. Operators supply enrollment
authentication and hosting; the SDK will not require a PoppyKit cloud service.

J1 now supplies targeted storage contracts, optional SQLite adapters, immutable
outbound destinations and owner-aware authentication recovery. See [STORAGE.md](STORAGE.md)
for Node requirements, transaction guarantees, adapter setup and reset instructions.

The official repository now provides JSON Schemas and a partial implementation-kit
validator. Their shape checks supplement the normative prose and behavioral tests;
the schema's stale assertion-audience description must not override the issuer rule.

This is an independent implementation with behavioral tests and a partial review;
complete protocol conformance, clean-package installation, and production adapter
guarantees have not been established.

Creating this repository does not reserve a name on npm, PyPI, or crates.io.


## Package names

- npm: @poppykit/client
- Future PyPI distribution: poppykit-client (Python import: poppykit_client)
- Future crates.io package: poppykit-client (Rust library name: poppykit_client, if applicable)

These are intended names, not reserved registry packages. Python and Rust implementations are not yet present.


See [DELIVERY.md](DELIVERY.md) for bounded HTTPS pools, SSE/JSON conversation
consumers, cancellation, metadata revalidation and record-specific retention.
