import type { Pool } from 'pg';
import { initialClientAuthState, upgradeClientAuthState } from './auth/client-auth.js';
import type { ClientAuthState } from './auth/client-auth.js';
import type { AuthSelection, AuthStore } from './auth/store.js';
import type { ConversationKey, ConversationStore } from './conversation-store.js';
import type { ConsumerCheckpoint, OutboundRecord } from './conversation.js';
import { PostgresRuntime, json, synchronous } from './postgres-runtime.js';
export { createPostgresPool, migratePostgres, postgresMigration, postgresSchemaVersion } from './postgres-runtime.js';

const tables = ['identities', 'connections', 'grants', 'operations', 'cleanup'] as const;
/** Namespaced references only; credentials still belong in SecretStore. The pool remains caller-owned. */
export class PostgresAuthStore implements AuthStore {
  private readonly db: PostgresRuntime;
  constructor(pool: Pool, readonly namespace: string) { this.db = new PostgresRuntime(pool, 'poppy_client'); }
  close(): Promise<void> { return this.db.close(); }
  get metrics() { return this.db.metrics; }
  private async select(selection: AuthSelection): Promise<ClientAuthState> {
    // Epoch/owner are shared by this auth namespace and must fence every connection mutation.
    await this.db.lock(`${this.namespace}:auth`);
    const get = async (table: string, id: string) => (await this.db.query('SELECT body FROM poppy_client.records WHERE ns=$1 AND kind=$2 AND id=$3', [this.namespace, table, id]))[0];
    const meta = await get('auth_meta', 'meta');
    const initial = initialClientAuthState();
    if (!meta) await this.put('auth_meta', 'meta', { version: initial.version, epoch: initial.epoch, owner: initial.owner });
    const state: ClientAuthState = { ...(meta ? JSON.parse(meta.body) : { version: initial.version, epoch: initial.epoch, owner: initial.owner }), identities: {}, connections: {}, grants: {}, operations: {}, cleanup: {} };
    const one = async (table: typeof tables[number], id: string) => { const row = await get(table, id); if (row) (state[table] as Record<string, unknown>)[id] = JSON.parse(row.body); };
    const rows = async (table: typeof tables[number], where: string, values: unknown[] = []) => {
      for (const row of await this.db.query(`SELECT id,body FROM poppy_client.records WHERE ns=$1 AND kind=$2 ${where}`, [this.namespace, table, ...values])) (state[table] as Record<string, unknown>)[row.id] = JSON.parse(row.body);
    };
    if (state.version === 1) {
      for (const table of tables) await rows(table, '');
      upgradeClientAuthState(state);
      for (const table of tables) for (const [id, value] of Object.entries(state[table])) await this.put(table, id, value);
      await this.put('auth_meta', 'meta', { version: state.version, epoch: state.epoch, owner: state.owner });
      for (const table of tables) state[table] = {};
    }
    if (state.version !== 2) throw new Error('unsupported auth state version');
    if ('issuer' in selection) await one('identities', selection.issuer);
    else {
      if ('connectionId' in selection) await one('connections', selection.connectionId);
      else if ('operationId' in selection) await one('operations', selection.operationId);
      else if ('callbackHash' in selection) await rows('operations', "AND body::jsonb#>>'{direct,stateHash}'=$3", [selection.callbackHash]);
      else await rows('connections', '');
      for (const operation of Object.values(state.operations)) await one('connections', operation.connectionId);
      for (const connection of Object.values(state.connections)) {
        if (connection.grantId) await one('grants', connection.grantId);
        if (!('list' in selection)) {
          await rows('operations', "AND body::jsonb->>'connectionId'=$3", [connection.id]);
          await rows('cleanup', "AND body::jsonb->>'connectionId'=$3", [connection.id]);
        }
      }
      for (const operation of Object.values(state.operations)) if (operation.grantId) await one('grants', operation.grantId);
    }
    if (selection.history) await rows('operations', "AND body::jsonb->>'phase'='terminal' AND body::jsonb->>'status'!='uncertain' AND body::jsonb->>'kind'!='renew' ORDER BY (body::jsonb->>'createdAt')::double precision DESC,id COLLATE \"C\" DESC LIMIT 201");
    return state;
  }
  read(selection: AuthSelection): Promise<ClientAuthState> { return this.db.run(() => this.select(selection)); }
  transaction<T>(selection: AuthSelection, change: (draft: ClientAuthState) => T): Promise<T> {
    return this.db.run(async () => {
      const state = await this.select(selection), before = structuredClone(state), result = synchronous(change(state));
      const { version, epoch, owner } = state;
      await this.put('auth_meta', 'meta', { version, epoch, owner });
      for (const table of tables) {
        for (const id of Object.keys(before[table])) if (!Object.hasOwn(state[table], id)) await this.db.query('DELETE FROM poppy_client.records WHERE ns=$1 AND kind=$2 AND id=$3', [this.namespace, table, id]);
        for (const [id, value] of Object.entries(state[table])) if (json(value) !== json((before[table] as Record<string, unknown>)[id] ?? null)) await this.put(table, id, value);
      }
      return result;
    });
  }
  private async put(kind: string, id: string, value: unknown): Promise<void> {
    await this.db.query('INSERT INTO poppy_client.records(ns,kind,id,body) VALUES($1,$2,$3,$4) ON CONFLICT(ns,kind,id) DO UPDATE SET body=excluded.body', [this.namespace, kind, id, json(value)]); this.db.metrics.rowsWritten++;
  }
  async pendingOperations(after: string | undefined, limit: number): Promise<string[]> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw new TypeError('recovery limit');
    return this.db.run(async () => (await this.db.query("SELECT id FROM poppy_client.records WHERE ns=$1 AND kind='operations' AND body::jsonb->>'phase'!='terminal' AND id>$2 ORDER BY id LIMIT $3", [this.namespace, after ?? '', limit])).map(row => row.id));
  }
  async cleanup(before: number, limit = 100): Promise<number> {
    if (!Number.isFinite(before) || !Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw new TypeError('cleanup limit');
    return this.db.run(async () => { await this.db.lock(`${this.namespace}:auth`); return (await this.db.query("DELETE FROM poppy_client.records WHERE ns=$1 AND kind='operations' AND id IN (SELECT id FROM poppy_client.records WHERE ns=$1 AND kind='operations' AND body::jsonb->>'phase'='terminal' AND body::jsonb->>'status'!='uncertain' AND (body::jsonb->>'createdAt')::double precision<$2 ORDER BY (body::jsonb->>'createdAt')::double precision LIMIT $3) RETURNING id", [this.namespace, before, limit])).length; });
  }
}

export class PostgresConversationStore implements ConversationStore {
  private readonly db: PostgresRuntime;
  constructor(pool: Pool, readonly namespace: string) { this.db = new PostgresRuntime(pool, 'poppy_client'); }
  close(): Promise<void> { return this.db.close(); }
  private async outbound(key: ConversationKey, id: string): Promise<OutboundRecord | undefined> {
    const row = (await this.db.query('SELECT body FROM poppy_client.outbound WHERE ns=$1 AND connection=$2 AND issuer=$3 AND id=$4', [this.namespace, key.connectionId, key.issuer, id]))[0]; return row ? JSON.parse(row.body) : undefined;
  }
  getOutbound(key: ConversationKey, id: string): Promise<OutboundRecord | undefined> { return this.db.run(() => this.outbound(key, id)); }
  async prepareOutbound(key: ConversationKey, record: OutboundRecord): Promise<OutboundRecord> {
    if (record.connectionId !== key.connectionId || record.issuer !== key.issuer || record.endpoint !== key.endpoint) throw new TypeError('outbound binding');
    return this.db.run(async () => {
      await this.db.query('INSERT INTO poppy_client.outbound VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING', [this.namespace, key.connectionId, key.issuer, record.id, json(record)]);
      return (await this.outbound(key, record.id))!;
    });
  }
  settleOutbound(key: ConversationKey, id: string, result: Pick<OutboundRecord, 'phase' | 'response' | 'error'>): Promise<void> {
    return this.db.run(async () => {
      await this.db.lock(JSON.stringify([this.namespace, 'outbound', key.connectionId, key.issuer, id]));
      const record = await this.outbound(key, id); if (!record || record.endpoint !== key.endpoint) throw new TypeError('outbound binding');
      if (record.phase === 'pending') await this.db.query('UPDATE poppy_client.outbound SET body=$5 WHERE ns=$1 AND connection=$2 AND issuer=$3 AND id=$4', [this.namespace, key.connectionId, key.issuer, id, json({ ...record, ...result })]);
    });
  }
  removeOutbound(key: ConversationKey, id: string): Promise<void> {
    return this.db.run(async () => {
      await this.db.lock(JSON.stringify([this.namespace, 'outbound', key.connectionId, key.issuer, id]));
      const record = await this.outbound(key, id); if (record && record.endpoint !== key.endpoint) throw new TypeError('outbound binding');
      await this.db.query('DELETE FROM poppy_client.outbound WHERE ns=$1 AND connection=$2 AND issuer=$3 AND id=$4', [this.namespace, key.connectionId, key.issuer, id]);
    });
  }
  private checkpointValues(key: ConversationKey, conversation: string, name: string) { return [this.namespace, key.connectionId, key.issuer, key.endpoint, conversation, name]; }
  private async checkpoint(key: ConversationKey, conversation: string, name: string): Promise<string | undefined> { return (await this.db.query('SELECT cursor FROM poppy_client.checkpoints WHERE ns=$1 AND connection=$2 AND issuer=$3 AND endpoint=$4 AND conversation=$5 AND name=$6', this.checkpointValues(key, conversation, name)))[0]?.cursor; }
  getCheckpoint(key: ConversationKey, conversation: string, name: string): Promise<string | undefined> { return this.db.run(() => this.checkpoint(key, conversation, name)); }
  async advanceCheckpoint(key: ConversationKey, row: ConsumerCheckpoint, from: readonly (string | undefined)[]): Promise<void> {
    if (row.connectionId !== key.connectionId || row.issuer !== key.issuer) throw new TypeError('checkpoint binding');
    return this.db.run(async () => {
      const values = this.checkpointValues(key, row.conversationId, row.name); await this.db.lock(JSON.stringify(['checkpoint', ...values]));
      if (from.includes(await this.checkpoint(key, row.conversationId, row.name))) await this.db.query('INSERT INTO poppy_client.checkpoints VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(ns,connection,issuer,endpoint,conversation,name) DO UPDATE SET cursor=excluded.cursor', [...values, row.cursor]);
    });
  }
  resetCheckpoint(key: ConversationKey, conversation: string, name: string): Promise<void> { return this.db.run(async () => { const values = this.checkpointValues(key, conversation, name); await this.db.lock(JSON.stringify(['checkpoint', ...values])); await this.db.query('DELETE FROM poppy_client.checkpoints WHERE ns=$1 AND connection=$2 AND issuer=$3 AND endpoint=$4 AND conversation=$5 AND name=$6', values); }); }
}
