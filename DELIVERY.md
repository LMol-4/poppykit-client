# Conversation delivery and transport

Conversation wire migration to draft 0.3 is pending; this layer still uses draft 0.2. Company content, messages,
unknown events and partial text remain untrusted data for the host application.

## Client

Bind `createConversationClient` to the existing auth lifecycle:

```ts
const target = await auth.target(connectionId);
const conversations = createConversationClient({
  ...target, connectionId, store, clock: { now: Date.now },
  authorizedRequest: request => auth.authorizedFetch(connectionId, request, target),
  authorization: (id, scopes) => auth.authorization(id, scopes),
});
for await (const item of conversations.watch(conversationId, { consumer: 'ui', signal })) {
  await processEvent(item.event);
  await item.ack();
}
```

`authorization(eventOrError)` returns the single auth lifecycle's verified
required/granted/missing scopes and eligible methods. The UI requests consent and
chooses an advertised method; Device or Mediated does not require Direct support.

`read` returns one page; `drain` follows `has_more` immediately. Named consumers
advance only on explicit acknowledgement. `watch` accepts SSE or JSON fallback,
skips unknown event types, deduplicates up to 10,000 event IDs per invocation, and
never rewinds its cursor on a duplicate. JSON pagination has its separate
`maxPages` bound (default 1000), without consuming reconnect attempts. Reconnects
are bounded (default 4); exhaustion is explicit `reconnect_exhausted`.

`lastEventId` takes precedence over the starting cursor. On reconnect the watcher
sends `Last-Event-ID`. `onPartial` is display-only: a null value clears unfinished
text on completion/disconnect; never execute or reason from an incomplete delta.
Messages are actionable only after a complete `message` event. SSE frames and
JSON fallback are limited to 1 MiB, streams to 16 MiB, and partial text per stream
to 1 MiB. UTF-8 fragmentation and CR/LF/CRLF are supported.

`cursor_expired` is an explicit history gap. Inform the user, then reset a named
consumer and reread retained history, or supply `onHistoryGap` returning true.
Automatic recovery is limited to one reset per watch; it does not recover missing
events. Checkpoints and pending sends survive process restart with durable stores.
Send retries keep their original connection, issuer, endpoint, ID, body and read
parameters. Abort signals are invocation-local and are never persisted. Canceling
delivery does not cancel an accepted company action or prove a lost send failed.

## Node transport

`createNodeTransport` uses Node HTTPS agents, with separate discovery, JSON and
stream pools. Defaults: 8 pools total, 2 connections per pool (including pending
TLS), 32 active operations, 15-second JSON timeout, and 5-second discovery timeout.
There is no hidden request queue: excess pool capacity fails `overloaded`, so a
later attempt performs fresh DNS and policy checks. Hosts decide scheduling.
Streams use `transport.stream` with a 5-minute/16-MiB lifetime budget. Call
`transport.close()` to cancel outstanding reads, DNS waiters, connects and streams.

Every request rechecks DNS and current address policy before pool assignment.
Changed approved addresses retire incompatible pools; actual TLS peers and reused
sockets are checked before HTTP bytes. TLS certificates remain verified. Only
explicit hostname/address exceptions permit private peers. Discovery never carries
credentials and follows only HTTPS redirects; credential-bearing requests never
follow redirects. Pool retirement may interrupt an active stream; reconnect uses
the durable cursor and fresh authorization.

Metadata caching remains bounded and honors freshness, Age, validators, no-cache
and no-store, with a 300-second upper bound. Expired entries revalidate; 304s retain
prior caching directives. `resolver.invalidate(target?)` fences old pending cache
writes without bypassing fetch concurrency/rate limits. The auth lifecycle rejects changed saved
issuer/endpoint/resource bindings rather than rerouting persisted work.

## Peer retention

The [server delivery guide](https://github.com/LMol-4/poppykit-server/blob/main/DELIVERY.md)
describes service configuration, byte budgets, notifications and bounded streams.
Keep the following distinct lifetimes when choosing an operator retention policy:

| Record | Lifetime / deletion rule |
| --- | --- |
| Conversation and message receipts | Entire conversation lifetime, including after closure and payload pruning; no automatic deletion |
| Event payloads | Retained indefinitely by default; host may call SQLite `pruneEvents(id, before, limit)` in bounded batches; recommend at least 30 days |
| Event cursor identities | Conversation lifetime; distinguish expired payloads (410) from foreign cursors (400) |
| Active work | Never pruned while held/pending/claimed; event pruning protects these conversations |
| Completed work | Bounded inspection retention; stale fences cannot publish |
| Latest user message, context and account binding | Operational conversation record, retained for its lifetime, including handoff after payload pruning |
| Client outbound/checkpoints | Retained until explicit local store deletion/reset; preserve pending/uncertain sends until reconciled |
| Pending auth and replay records | Separate auth validity/owner rules in AUTH.md and STORAGE.md; not the event TTL |
| CLI transcripts/retries | CLI ownership; local deletion never deletes company history or revokes authorization |

Pruning is explicit operator policy, never automatic data loss. It preserves old
message receipts and cursor identity. Concurrent reads see a coherent snapshot or
`cursor_expired`. Invalid/expired waited-POST cursors are rejected before accepting
the new write; an existing message ID still returns its original receipt.
