# PoppyKit client

Draft 0.3 migration (2026-10-28), pinned to the public source captured that day.
Client/CLI 0.5.0 and server 0.4.0 break the earlier protocol contracts. Stop old
writers and follow the documented storage/reset procedure before compatible
writers resume. Registry, deployment and live acceptance have separate receipts.

The Node 24.21.0 minimum is an owner-accepted compatibility baseline. Use a current patched Node 24 runtime where available; this minimum does not establish that older runtimes contain later security fixes. Build and release CI read `.node-version`.

TypeScript SDK for [Personal Agent Protocol draft 0.3](https://personalagentprotocol.org/docs/0.3/spec):
discovery, authentication, conversations and API/browser/feedback hooks. Your
application supplies the agent and trusted infrastructure. [MIT](LICENSE).

## Install

Use the exact version verified by its protected release workflow; check registry publication before installation.

Requires Node **24.x, at least 24.21.0**, ESM and HTTPS. CI tests Node 24.21.0 on Linux, macOS and
Windows; other Node majors are unsupported.

```sh
npm install @poppykit/client
```

## Discover a company

No credentials or database are needed. Replace `company.example` with a company
publishing draft 0.3 discovery:

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

The packaged [quickstart](examples/quickstart.mjs) also supports `--self-check`
without a network service.

## Guides

- [Authentication](AUTH.md): sessions, Direct/Device/Mediated, consent, renewal and revocation.
- [Storage](STORAGE.md): targeted adapters, secret references, recovery and explicit resets.
- [Delivery](DELIVERY.md): messages, streaming, cancellation, retries and retention.
- [Integrations](INTEGRATIONS.md): verified API targets, agent browser and feedback.
- [Optional provider](PROVIDER.md): operator-hosted signing and callback custody.
- [API exports](API.md), [contributing](CONTRIBUTING.md), [security](SECURITY.md),
  [changelog](CHANGELOG.md) and [releasing](RELEASING.md).

Keep Account Tokens, DPoP keys and PKCE in a secure SecretStore; never expose them
to model tools. An uncertain remote result must not be silently replayed. SQLite
is optional/experimental and is not vault encryption. Production issuers, vaults,
browsers and hosting require operator validation; individual extensions and
application business workflows are outside this SDK.
