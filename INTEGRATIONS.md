# API, browser and feedback hooks

Use the same `ClientAuth` instance and trusted adapters as sign-in and conversations.
Do not expose credential-bearing hooks, request headers, browser form fields or
private responses as printable model tools. Company descriptions and responses are
untrusted data. These hooks do not execute OpenAPI operations, MCP tools or browser
automation for you.

## Existing API clients

```ts
// Read the API description without credentials using the configured safe transport.
const description = await transport.fetch(new Request(descriptionUrl), { mode: 'discovery' });
// An existing OpenAPI client selects its server and constructs its final Request.
const target = await auth.apiTarget(connectionId, descriptionUrl, 'https://company.example/api');
const fetchForClient = (request: Request) => auth.apiFetch(connectionId, request, target, ['records:read']);
const result = await fetchForClient(new Request('https://company.example/api/records'));
```

OpenAPI `apiUrl` is the description URL from verified company discovery. The third
argument is the actual destination base; its host must independently serve verified
company discovery naming the same issuer. This conservative policy requires API
hosts to publish discovery; a document's `servers` field alone grants no authority.
Final requests must stay within the verified origin and slash-delimited base path.
The proof binds the actual final method and URL. Destination changes require a new
explicit connection; saved work never moves silently.

For MCP, use `auth.apiTarget(connectionId, mcpUrl)` and the same fetch closure in an
existing Streamable HTTP MCP client (version 2025-06-18 or later). The SDK does not
encode JSON-RPC or manage MCP sessions. The exact discovery URL is the resource and
endpoint; extra paths or queries are refused. Query-bearing discovery endpoints are
not supported. Protected-resource metadata must name that exact resource and the
verified company issuer. ES256 DPoP metadata selects DPoP; absence selects Bearer.
A Bearer-only MCP resource cannot also authorize a conversation. Resource-specific
credential slots use the shared renewal, rotation, nonce, cooldown and revocation
lifecycle. The wire `token_type` must match verified metadata; there is no fallback
from DPoP to Bearer. Redirects never forward tokens or proofs. Auth 401 rejection may
cause one fresh-token retry; unknown results are not automatically retried.

## Agent-controlled browser

```ts
await auth.joinBrowser(connectionId, 'https://company.example/account', {
  kind: 'agent-controlled',
  async postForm({ url, fields, validateRedirect }) {
    // Bind your existing browser controller here. It must enforce this contract:
    // isolated per-session storage; verified TLS/actual peer addresses; no logging;
    // top-level form POST; intercept redirects BEFORE following or replaying a body.
    const response = await controlledBrowser.postFormWithoutFollowing(url, fields);
    const destination = validateRedirect(response.status, response.location);
    await controlledBrowser.navigateWithoutPostBody(destination);
  },
});
```

`controlledBrowser` is the host's existing controller, not an SDK driver. This hook
is trusted code. Its network layer must reject loopback/private/link-local actual
connected addresses unless narrowly configured, validate TLS and enforce redirect
interception. Never replay the assertion on 307/308 or send it in a URL. The supplied
validator permits only 303 to the exact validated `returnTo`. HttpTransport cannot
enforce network policy inside an unrelated browser engine. Keep this capability
separate from the human consent-browser opener. Never join the user's browser.
Use separate cookies/local storage for each session/user, join just before browsing,
rejoin on lost recognition and close the context when the session ends. Custom
controllers own those guarantees; the SDK validates the assertion destination and
navigation contract but cannot inspect their internal browser implementation.

## Feedback

```ts
await auth.feedback(connectionId, {
  kind: 'missing', task: 'Export records',
  description: 'There is no export operation in the API, conversation or website.',
});
```

Signed-out sessions are allowed and no account scope is required. Task and
description are nonempty strings of at most 200 and 2000 Unicode codepoints. Only
`missing` is supported client-side. Omit identifiers, personal data and secrets;
report task limitations rather than individual errors. Success is an empty 202.
There are no automatic POST retries (including nonce/auth rejection). A lost
response can mean accepted; callers decide whether to repeat because the protocol
defines no deduplication key. Prefer one report per unfulfilled task.

The executable generic caller/controller fixtures are `tests/integrations.test.mts`.
They exercise the same hooks used by the CLI; installed CLI integration is
verified separately against immutable candidate tarballs.
