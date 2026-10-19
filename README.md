# PoppyKit client

Personal-agent TypeScript SDK for discovery, authentication, sessions, and conversations.

Designed to be imported into an existing personal-agent product. The host supplies
its runtime, application identity, HTTPS metadata/callback hosting, signing and
credential-storage adapters. PoppyKit supplies protocol behavior; it does not
operate a managed agent or credential service. The CLI is optional.

The SDK design supports explicitly selected independent connections, including
multiple accounts at one company. The demo's one-active-account UI is a host
policy. Discovery can be used without authentication dependencies; Direct Sign-In
is a separate capability. Interrupted exchanges and remote revocation failures
have explicit outcomes rather than silently retrying or reconnecting.

See [poppykit-demo](https://github.com/LMol-4/poppykit-demo) for the planned local integration example.

Status: initial project scaffold. No SDK or CLI implementation is published yet.

Targets the Personal Agent Protocol (Poppy): https://personalagentprotocol.org/docs/spec

Current design target (reviewed 2026-10-19): draft **0.2, in progress**, pinned to
`30c476455c20c23c13b050c74c47d9b3269413c7`. Pre-1.0 versions require exact
major.minor support; do not silently treat published 0.1 as compatible. Discovery
must support optional issuer DPoP algorithm metadata, issuer paths, and safe
HTTPS/address/redirect handling. Credential selection is resource-specific, and
user sign-out/disconnection must prevent automatic re-sign-in without a new request.
These are implementation requirements, not claims of implemented features.

The official repository now provides JSON Schemas and a partial implementation-kit
validator. Their shape checks supplement the normative prose and behavioral tests;
the schema's stale assertion-audience description must not override the issuer rule.

This is an independent implementation. Protocol conformance has not yet been tested.

Creating this repository does not reserve a name on npm, PyPI, or crates.io.


## Package names

- npm: @poppykit/client
- Future PyPI distribution: poppykit-client (Python import: poppykit_client)
- Future crates.io package: poppykit-client (Rust library name: poppykit_client, if applicable)

These are intended names, not reserved registry packages. Python and Rust implementations are not yet present.

