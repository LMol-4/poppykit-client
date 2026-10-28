# PoppyKit client

TypeScript SDK for [Personal Agent Protocol draft 0.3](https://personalagentprotocol.org/docs/0.3/spec).
Discover companies, authenticate and manage conversations. [MIT](LICENSE).

## Install

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
