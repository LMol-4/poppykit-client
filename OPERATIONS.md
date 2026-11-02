# Business operations (Operations v2)

Operations are optional on the wire and have no separate endpoint. Both verified
metadata documents must list `extensions.operations.version: "2"`. Publish support
only after configuring trusted consent, durable attempt storage and recovery for
every API, MCP and conversation interface your agent uses. Import `operationsV2`
for the metadata value; the SDK never advertises it automatically. OAuth consent,
provider enrollment, Company text and model output never approve business work.

`BusinessOperation` has `operation_id`, `revision`, `summary`, optional object
`terms`, and RFC3339 `expires_at`. `OperationApproval` names the exact ID/revision.
`parseBusinessOperation`, `parseOperationApproval`, `parseApprovalHeader`,
`approvalHeader`, `mcpApproval` and `approvalMetaKey` implement the wire contract.
Unknown JSON members survive; unknown valid Structured Field members are ignored.
The pinned RFC9651 parser has no runtime dependencies. The API body snapshot is
base64, preserving arbitrary bytes and the complete URL/query.

## Trusted client

Configure `createOperationClient` with:

- `store`: `SqliteBusinessAttemptStore(path,namespace)`,
  `PostgresBusinessAttemptStore(pool,namespace)`, or `BusinessAttemptStore`.
- `context`: `() => auth.businessContext(connectionId)`. This reads current
  verified Company/client metadata and binds Company, User, client and local
  authority. Signed-in contexts use the local grant identity; signed-out contexts
  use the exact sid. Separate grants are conservatively distinct because OAuth
  does not expose a portable account identifier. Share the same grant via
  `start(domain,{accountFrom})` for an account continuation in another Session.
- `consent.confirm`: your trusted interface, outside model tools. Display the
  Company name, exact summary and comparison differences. Treat all of them as
  inert literal text, including terminal controls; render no links, images or
  HTML. Collect a fresh actual User answer for each operation/revision. Only this
  callback can transition a pending attempt to approved. Return `approve` or
  `decline`; a thrown/interrupted callback never becomes approval.
- `checkTerms`: trusted comparison of the saved request, summary and structured
  terms. Return discrepancies for the UI to display. The SDK cannot establish
  the semantic agreement of arbitrary Company business JSON.
- `send`: `createOperationSender` with the actual channel integrations below.

Choose one stable local attempt ID per business action in trusted application
code. Keep that ID through revisions and recovery; do not let a model invent a
new attempt ID to bypass an unresolved action. A received revision is persisted
with its original request before asking the User. Authentication lifecycle
`OperationRecord`/`AuthOutcome.operationId`, provider operation IDs, conversation
message receipts and business attempt IDs are separate concepts/stores.

`receiveApi(id,originalRequest,response)` accepts a 403 `approval_required`.
`receiveMcp(id,{channel:'mcp',url,name,arguments},toolResult)` accepts
`isError:true` and `structuredContent.operation`.
`receiveConversation(id,{channel:'conversation',endpoint,conversationId},message)`
accepts only a recorded Company message's operation. None reports an action done.
`receive` is the lower-level equivalent for an already validated channel result.
It rejects changed terms under the same revision and replacing uncertain work.
A new revision before sending requires fresh consent and invalidates late UI
answers; previous decisions remain in the attempt.

Call `requestConsent(id)`, then explicitly `retry(id)`. There is no `approve` API
or unattended consent flag. Rejection, withdrawal and expiry are durable.
`get` reads a bound attempt. `recover(after?,limit=100)` pages pending IDs and
returns attempts or ownership errors without sending or approving anything.
After dismissing an interrupted UI, `resumeConsent` fences its late answer and
requires a new one. `withdraw` cancels a local dispatch through its AbortSignal.
Channel adapters must observe that signal before actual dispatch. After a send
may have started, withdrawal preserves uncertainty and suppresses later retries;
it does not claim to cancel the Company's effect.

`retry` commits uncertainty before sending. A crash, network error, authorization
failure, new operation on retry, or 503 retains the same request and approval.
Respect the stored `retryAt`; expiry after dispatch does not discard an uncertain
attempt. Do not ask for another operation until the old action's outcome is known.
Use `reconcile(id,lookup)` with trusted business-state lookup; a new operation is
not evidence of failure. Completed results cannot be overwritten by late sends.

## Channel adapters

`createOperationSender({api,mcp,conversation})` preserves the saved channel:

- API: implement `api(request,context)` with `auth.apiFetch(connectionId,request,target,
  scopes,context)` using the verified original target. `approvedApiRequest` repeats the
  exact method, URL and bytes with `Poppy-Approval`. It drops the initial
  Idempotency-Key; approved retries use the operation ID and no additional key.
  Saved headers exclude credentials/cookies. Successful final status, headers and body
  are stored as JSON (body base64); HTTP202 and non-success remain uncertain with Retry-After.
- MCP: implement `mcp(url,params,signal,context)` with your authenticated Streamable HTTP
  transport. `approvedMcpParams` repeats the original tool/arguments with approval
  in `params._meta['personalagentprotocol.org/approval']`. Preserve HTTP503 and
  Retry-After as a pending delivery in custom transport adapters. An error tool
  result remains uncertain, including a new operation.
- Conversation: configure `createConversationClient` with `operations:{client,
  company}` from verified metadata. Both must advertise v2. Implement
  `conversation(binding,message,signal,context)` with that client's `send` and original
  conversation ID. `approvedConversationMessage` is approval-only and retains its
  message ID on retry. Acceptance is pending, not completion; reconcile the later
  business result. Event pages and SSE support operation-only Company messages.

Raw serialization helpers are trusted low-level APIs; exposing them as model
approval tools would violate the consent contract. Account credentials remain
inside the authentication lifecycle, never in consent inputs or model messages.

## Persistence and migration

Attempt format is version1, separate from auth v3. SQLite creates the additive
`business_attempts(ns,id,body)` table. PostgreSQL uses existing
`poppy_client.records`, kind `business_attempts`; no applied SQL migration changes.
Existing rows, grants and pending/uncertain work are untouched. Use a private
namespace per local user/client and protect stored requests/terms/results as
personal data. Custom adapters serialize absent-row races across processes,
reject async callbacks/non-JSON/unknown versions, roll back on exceptions, return
detached snapshots and page nonterminal IDs in ascending binary order. Run
`runBusinessAttemptAdapterContract` from the adapter-contract subpath. Never prune
uncertain attempts. Explicit application retention may archive terminal decisions
only after recovery references no longer need them; storage removal is not remote
cancellation. Bundled adapters preserve all decisions by default.

Run `node examples/operations.mjs --self-check` for a local synthetic flow that
declines without dispatch. Without the flag it asks through a terminal interface.
See tests/operations.test.mts for independent-wire and real persistent cases.

Every sender callback receives the original `BusinessClientContext`. Pass it as the final `expectedContext` argument to `auth.apiFetch` or `auth.authorizedFetch`, including conversation approval dispatch. The authentication lifecycle checks it through metadata/credential waits and retries, so a changed Session/account cannot silently supply replacement authority. Custom MCP transports must pin that same context through their final dispatch.

The standard `compareOperationTerms` helper supplies an honest default for trusted
review UIs. It compares exact JSON paths and reports absent facts; arbitrary prose,
renamed fields, currency/unit conversion and independent business verification
remain outside its scope. It never substitutes for the actual human decision.
