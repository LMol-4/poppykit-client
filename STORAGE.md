# Persistence and recovery

J1 introduces breaking storage contracts for this unpublished package. Node 24.12.0
or later is required. The optional `@poppykit/client/sqlite` entry point exports
`SqliteAuthStore` and `SqliteConversationStore`; importing the client core does not
load SQLite. `node:sqlite` is experimental in the tested Node 24.12.0 runtime.
Consumers can implement `AuthStore` and `ConversationStore` using their own database.

```ts
import { SqliteAuthStore, SqliteConversationStore } from '@poppykit/client/sqlite';
const authStore = new SqliteAuthStore('/private/path/auth.db');
const conversationStore = new SqliteConversationStore('/private/path/messages.db');
// Pass authStore to createClientAuth and conversationStore to createConversationClient.
// Close both after all operations have finished.
```

Use one auth database per namespace/local user/client identity. The owner tuple is
checked on every SDK auth read and mutation. Identities are keyed by the exact full
issuer, connections by immutable IDs, operations by ID and callback state hash,
cleanup by connection, and token slots by session/resource. Secret values are never
stored in auth records: immutable references point to the host's `SecretStore`.
Session Tokens remain in process memory. Conversation databases contain message
bodies; operators must provide private storage and their required encryption.

Auth selections load an identity or a connection aggregate (its grants, operations,
and cleanup), never unrelated connections. Operation/callback selectors resolve the
owning connection through indexes. `list` explicitly enumerates connections.
Recovery pages nonterminal operation IDs in batches of 100, then rechecks each
operation and its owner inside its transaction. `cleanup(before, limit)` removes
only terminal, non-uncertain auth history; the limit is at most 1000. It does not
erase grants, pending exchanges, uncertain results, or secrets.

Transactions must serialize conflicting domain updates across processes, roll back
on exceptions, reject asynchronous mutation callbacks and non-JSON persisted values,
enforce unique keys, and return detached values. SQLite uses WAL, FULL synchronous
commits and a bounded busy wait. It serializes writers; parallel writers are not a
promise. The database file must be on a local filesystem that supports SQLite's
locking; this is not a distributed database. Create adapters before starting work,
and keep network/vault calls outside transaction callbacks.

Conversation storage has separate prepare/get/settle operations and checkpoint
compare-and-set. An outbound ID is unique per connection/full issuer, and also
records its endpoint. Retry rejects an endpoint change before sending. Preparation
returns the existing record instead of replacing content; terminal outcomes cannot
be overwritten by a late sender. Checkpoints include endpoint, conversation and
consumer. Receipts remain available for retries: the old `keepCompleted` deletion
behavior is removed. J3 owns retention with preserved message identity and bounded
payload cleanup; no automatic age-based deletion is currently performed.

`MemoryConversationStore` from `@poppykit/client/memory` is non-durable and confined
to one process. The SQLite adapters also accept `:memory:` for non-durable tests;
each such adapter has its own database. Neither mode demonstrates process recovery.

## Operation ownership

Each active rotation or code exchange records a random execution owner, host name,
and PID before dispatch. The default liveness check keeps other running local
processes live; within this process it tracks actual active executions. Unknown
remote hosts and permission errors are conservatively live. A new invocation cannot
invalidate an active exchange just by starting recovery. A reused PID can delay
recovery; it cannot authorize replay. Multi-host adapters must supply a trustworthy
`ownerAlive` hook backed by their deployment's ownership/fencing mechanism. Returning
false is an assertion of abandonment, not a request to cancel an active operation.

Recovery rechecks phase/generation and liveness under the database transaction. A
prepared abandoned rotation can release its claim; a dispatched exchange without a
durably staged response becomes uncertain. A staged rotation can activate locally
only if its connection/grant generations still match. Cancellation, disconnection,
or another generation wins over late activation. No remote token exchange is replayed
by recovery, and lease expiry would not prove that a request was never sent.

The vault and remote issuer are outside the database transaction. Stage immutable
secrets first, conditionally activate references, then remove superseded secrets.
Vault failure or process death can leave an unreferenced staged secret; the host
needs an orphan-secret sweep that respects active owners and a grace period. A lost
remote rotation response remains uncertain. This adapter does not promise automatic
recovery of a token that the issuer rotated but never delivered.

## Development reset

There is no automatic migration from old whole-state development stores. Stop all
users of a disposable store, resolve uncertain remote outcomes, and explicitly move
aside its database and WAL/SHM files and the matching host-managed secret namespace
before creating a fresh store. Never reset live credentials by deleting a database
behind a running process. Old stores are not silently deleted or reinterpreted.

`tests/storage.test.mjs` uses actual child processes, SQLite contention and forced
termination. It covers rollback, durable prepare, live-owner recovery and an external
synthetic effect followed by owner death. The latter becomes uncertain, not an
exactly-once execution claim. Auth unit tests also retain staged-secret, generation,
revocation-race and vault-failure coverage.
