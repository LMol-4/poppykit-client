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
company discovery naming the same verified Company identifier. This conservative policy requires API
hosts to publish discovery; a document's `servers` field alone grants no authority.
Final requests must stay within the verified origin and slash-delimited base path.
The proof binds the actual final method and URL. Destination changes require a new
explicit connection; saved work never moves silently.

Service authorization comes from RFC 9728 protected-resource metadata, fetched
without credentials before the first signed-in API/conversation request and cached
through the resolver. A real 404 permits the default Company token; network errors
and malformed metadata fail closed. A service resource other than the Company
domain selects a token for that exact resource via normal sign-in/refresh. Discovery
resource fields do not grant authority. An invalid_token challenge with
resource_metadata causes one bounded revalidation/refresh retry.

For MCP, use auth.apiTarget(connectionId, mcpUrl) and the same fetch closure in an
existing MCP HTTP client. The exact discovery URL is the resource and endpoint,
including any query; changed queries or child paths are refused. Its metadata must
name that resource and the Company's issuer when sign-in exists. ES256 DPoP
advertisement selects DPoP; absence selects Bearer. Account credentials use normal
OAuth grants, without token exchange. Requests use the token response's scheme.

The SDK does not encode JSON-RPC or manage MCP initialization/Mcp-Session-Id.
Poppy Session continuity is independent of earlier MCP transport lifecycles and
MCP 2026-07-28 per-request metadata. Signed-out issuerless APIs/MCP still get Session
JWTs. Redirects never forward tokens or proofs; unknown results are not retried.

## Agent-controlled browser

```ts
await auth.joinBrowser(connectionId, 'https://company.example/account', {
  kind: 'agent-controlled',
  async loadJoinForm(url) {
    // Top-level GET in this isolated browser; verify the final URL and form action
    // are exactly url. Read the hidden code only here, outside model context.
    return controlledBrowser.loadJoinForm(url);
  },
  navigate: url => controlledBrowser.navigateWithoutPostBody(url),
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
interception. Never replay the code on 307/308 or send it in a URL. The supplied
validator permits only 303 to an HTTPS company page. After that redirect, the SDK
asks the controller to navigate to the validated `returnTo`. HttpTransport cannot
enforce network policy inside an unrelated browser engine. Keep this capability
separate from the human consent-browser opener. Never join the user's browser.
Use separate cookies/local storage for each session/user, join just before browsing,
rejoin on lost recognition and close the context when the session ends. Custom
controllers own those guarantees. The SDK separately authorizes the code at the
endpoint path plus /authorize, preserving its query, with a signed Session request
and current account token when signed in. It requires 204 before the browser
submits only code. No JWT/token/proof enters the browser form. The cookie snapshots
the approved account/scopes; later sign-in or scope expansion requires rejoin.

## Feedback

```ts
await auth.feedback(connectionId, {
  task: 'Export records',
  description: 'There is no export operation in the API, conversation or website.',
});
```

Signed-out sessions are allowed and no account scope is required. Task and
description are nonempty strings of at most 200 and 2000 Unicode codepoints. Omit identifiers, personal data and secrets;
report task limitations rather than individual errors. Success is an empty 202
(returning undefined) or HTTP 200 with an `Alternative`. The SDK validates the latter
and returns instructions/references as company data, never as user consent. Unlisted
OpenAPI/MCP references and unknown reference types are ignored; known malformed
references fail. Web links must be HTTPS. No alternative is executed automatically.
Feedback does not automatically repeat a POST after nonce/auth/Session rejection. A lost
response can mean accepted; callers decide whether to repeat because the protocol
defines no deduplication key. Prefer one report per unfulfilled task.

The executable generic caller/controller fixtures are `tests/integrations.test.mts`.
They exercise the same hooks used by the CLI; installed CLI integration is
verified separately against immutable candidate tarballs.

## Task metadata

Call `auth.excludedTasks(connectionId)` before choosing how to perform a task.
It uses `MetadataResolver.resolveExcludedTasks(document)` (optional for custom
resolvers), fetches the advertised document without credentials and shares the
resolver's bounded HTTP cache/revalidation. Alternatives use the feedback validator;
cached references are checked against current discovery on every read.

Discovery exposes `auth.scope_hints`: both fields are required, unknown changes
become irreversible, and unknown fields are ignored. Missing hints remain unknown.
Hints and excluded task phrases are company claims, never user approval. The host
agent decides whether a phrase matches its task. The SDK/CLI intentionally omit the
SHOULD-level automatic pre-task check: they have no task planner; callers choose
when to read the metadata. No task-policy engine or alternative executor is supplied.

## Operations v2

[OPERATIONS.md](OPERATIONS.md) defines API403/Poppy-Approval, MCP structuredContent/_meta and conversation operation/approval integration. Publish support only after all interfaces in use have trusted consent and durable effect recovery. Ordinary MCP clients retain their OAuth flow; one unsupported tool returns a tool error. No v1 extension endpoint is added.

For business-operation sends, pass the saved `BusinessClientContext` as the final `expectedContext` argument to `apiFetch`/`authorizedFetch`. Channel sender callbacks receive that context. A changed Company/client/User/account or signed-out Session fails before dispatch; target discovery does not authorize a replacement account. See [Operations](OPERATIONS.md).
