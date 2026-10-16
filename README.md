# PoppyKit client

Personal-agent TypeScript SDK for discovery, authentication, sessions, and conversations.

Designed to be imported into an existing personal-agent product. The host supplies
its runtime, application identity, HTTPS metadata/callback hosting, signing and
credential-storage adapters. PoppyKit supplies protocol behavior; it does not
operate a managed agent or credential service. The CLI is optional.

See [poppykit-demo](https://github.com/LMol-4/poppykit-demo) for the planned local integration example.

Status: initial project scaffold. No SDK or CLI implementation is published yet.

Targets the Personal Agent Protocol (Poppy): https://personalagentprotocol.org/docs/spec

This is an independent implementation. Protocol conformance has not yet been tested.

Creating this repository does not reserve a name on npm, PyPI, or crates.io.


## Package names

- npm: @poppykit/client
- Future PyPI distribution: poppykit-client (Python import: poppykit_client)
- Future crates.io package: poppykit-client (Rust library name: poppykit_client, if applicable)

These are intended names, not reserved registry packages. Python and Rust implementations are not yet present.

