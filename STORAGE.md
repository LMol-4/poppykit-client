# Persistence and recovery

Use targeted storage contracts. Node 24.12.0
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
behavior is removed. Retention preserves message identity and bounds payload cleanup; no automatic
age-based deletion is performed.

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

Contract tests cover real child-process contention, crash recovery, uncertain
external effects, staged secrets and revocation races; see [contributing](CONTRIBUTING.md).

## Conversation delivery lifetime

See [DELIVERY.md](DELIVERY.md) for the retention table. Outbound records and
checkpoints are retained until explicit local deletion; pending/uncertain retries
must first be reconciled. Checkpoint acknowledgements use compare-and-set and do
not acknowledge merely because a page or stream frame was read. Local deletion
never deletes company history, revokes access or cancels accepted business work.

## Postgres (0.2 API)

The optional `@poppykit/client/postgres` exports `PostgresAuthStore` and
`PostgresConversationStore`; `/provider/postgres` exports `PostgresProviderStore`.
Install the optional peer `pg@8.23.1` only when choosing these subpaths.
Protocol-only imports load neither pg nor SQLite. PostgreSQL 17 and Node 24.12+
are supported; plain PostgreSQL and Supabase transaction pooling use the same adapter.
There is no Supabase Auth or application dependency.

```ts
import { createPostgresPool, migratePostgres, PostgresAuthStore,
  PostgresConversationStore } from '@poppykit/client/postgres';
import { PostgresProviderStore } from '@poppykit/client/provider/postgres';
const pool = createPostgresPool({ connectionString: process.env.DATABASE_URL });
// Explicit deployment administration, once before accepting traffic:
await migratePostgres(pool, 'poppy_client');
await migratePostgres(pool, 'poppy_provider');
const auth = new PostgresAuthStore(pool, 'installation:user');
const conversations = new PostgresConversationStore(pool, 'installation:user');
const provider = new PostgresProviderStore(pool, 'provider-instance');
// After requests finish:
await auth.close(); await conversations.close(); await provider.close();
await pool.end();
```

A supplied pool belongs to the caller: adapter `close` stops that adapter and
never ends the pool. `createPostgresPool` returns a pool owned by its caller.
Defaults: two connections, 3s acquisition, 10s idle, verified TLS. Supply a CA via
`ssl: { ca, rejectUnauthorized: true }` for a private root. TLS URL overrides and
`rejectUnauthorized: false` are rejected; `ssl: false` is an explicit trusted-local
server choice. Caller-created pools are the caller's responsibility. Queries are
unnamed/parameterized, and each transaction uses one checked-out connection.
Transaction/statement limits are 5s and lock waits 2s. No session locks, named
prepared statements, LISTEN or session state are required by transaction pooling.
Do not perform HTTP, model or KMS calls in storage callbacks.

Versioned SQL ships at `migrations/postgres/0001_poppy_client.sql` and
`0001_poppy_provider.sql`. `postgresMigration(schema)` returns its SQL for review;
`migratePostgres` explicitly applies it atomically or accepts existing version 1.
Construction/request paths never create or upgrade schemas. Unknown/missing
versions fail closed. Version checks do not certify arbitrary operator edits to
table definitions: inspect deployment migration history and stop on schema drift.
Applied migration files are immutable; corrections require a new migration/version.
Keep SQL and the deployment's applied-migration ledger under version control.
Back up and rehearse before applying to durable data. Roll back application code
only to a compatible schema/API; restore a reviewed backup for destructive reversal.
No automatic SQLite import, live reset, schema drop or downgrade is supplied.

Auth uses its namespace owner/epoch fence and indexed connection/operation selectors.
Provider uses indexed enrollment/state/mapping selectors, an atomic capacity counter,
and bounded per-enrollment operations. These are individual row records, not a
whole-database snapshot. `cleanup` preserves pending/uncertain auth operations.
Namespaces are constructor configuration, never request-supplied authority.

Custom backends can run `runClientConversationAdapterContract` and
`runProviderAdapterContract` from `@poppykit/client/adapter-contract` with two
handles to a fresh shared namespace. Real process death and engine atomicity still
need backend-specific checks. Database credentials and encryption keys stay outside
records, prompts and logs; provider callback URLs remain encrypted by ResultCipher.
