import type { Pool } from 'pg';
import type { ProviderSelection, ProviderStore, ProviderTransaction } from './provider.js';
import { providerMemoryTransaction, providerUserKey, scopedProviderTransaction } from './provider-storage.js';
import { PostgresRuntime, json, synchronous } from './postgres-runtime.js';
import type { PostgresConnection } from './postgres-runtime.js';
export { createPostgresPool, migratePostgres, postgresMigration, postgresSchemaVersion } from './postgres-runtime.js';
export type { PostgresConnection } from './postgres-runtime.js';

/** Targeted provider aggregates. Cryptography and human/session verification run outside its transactions. */
export class PostgresProviderStore implements ProviderStore {
  private readonly db: PostgresRuntime;
  constructor(pool: Pool, readonly namespace: string) { this.db = new PostgresRuntime(pool, 'poppy_provider'); }
  close(): Promise<void> { return this.db.close(); }
  get metrics() { return this.db.metrics; }
  /** Only bounded SQL/crypto work; connection comes from the host's active transaction. */
  withTransaction<T>(connection: PostgresConnection, action: () => Promise<T>): Promise<T> { return this.db.withConnection(connection, action); }
  transaction<T>(selection: ProviderSelection, action: (tx: ProviderTransaction) => T): Promise<T> {
    return this.db.run(async () => {
      const rows = new Map<string, Record<string, any>>();
      const one = async (kind: string, id: string) => {
        const row = (await this.db.query('SELECT body FROM poppy_provider.records WHERE ns=$1 AND kind=$2 AND id=$3', [this.namespace, kind, id]))[0];
        const key = JSON.stringify([kind, id]); rows.delete(key);
        if (row) rows.set(key, JSON.parse(row.body));
        return row ? JSON.parse(row.body) as Record<string, any> : undefined;
      };
      const lock = (kind: string, id: string) => this.db.lock(JSON.stringify([this.namespace, kind, id]));
      if (selection.kind === 'enroll') {
        await lock('capacity', 'enrollments');
        await one('capacity', 'enrollments'); await one('visitor', selection.subjectHash); await one('enrollmentRequest', selection.requestHash);
      } else {
        const lookup = selection.kind === 'callback' ? await one('state', selection.stateHash) : undefined;
        const enrollmentId = selection.kind === 'callback' ? lookup?.enrollmentId : selection.enrollmentId;
        if (enrollmentId) {
          await lock('enrollment', enrollmentId);
          const enrollment = await one('enrollment', enrollmentId);
          if ('issuer' in selection && enrollment) { const key = providerUserKey(enrollment.visitor, selection.issuer); await lock('user', key); await one('user', key); }
          if (selection.kind === 'begin' || selection.kind === 'revoke') {
            const operations = await this.db.query("SELECT id,body FROM poppy_provider.records WHERE ns=$1 AND kind='operation' AND split_part(id,':',1)=$2 ORDER BY id LIMIT 1001", [this.namespace, enrollmentId]);
            for (const row of operations) rows.set(JSON.stringify(['operation', row.id]), JSON.parse(row.body));
            if (operations.length > 1000) throw new Error('provider aggregate exceeds retained operation limit');
            if (selection.kind === 'begin') {
              const states = new Set<string>(); if (selection.stateHash) states.add(selection.stateHash);
              for (const row of operations) { const hash = JSON.parse(row.body).binding?.stateHash; if (hash) states.add(hash); }
              for (const hash of [...states].sort()) { await lock('state', hash); await one('state', hash); }
            }
          } else {
            if (selection.kind === 'callback') {
              // Re-resolve after the enrollment lock; cleanup may have removed/rebound the selector.
              const current = await one('state', selection.stateHash);
              if (json(current ?? null) !== json(lookup ?? null)) throw new Error('provider callback selector changed');
            }
            const operationId = selection.kind === 'callback' ? lookup?.operationId : 'operationId' in selection ? selection.operationId : undefined;
            if (operationId) await one('operation', `${enrollmentId}:${operationId}`);
          }
        }
      }
      const before = new Map([...rows].map(([key, value]) => [key, json(value)]));
      const result = synchronous(action(scopedProviderTransaction(selection, providerMemoryTransaction(rows))));
      const removed = [...before.keys()].filter(key => !rows.has(key)).map(key => { const [kind,id] = JSON.parse(key); return {kind,id}; });
      if (removed.length) await this.db.query('DELETE FROM poppy_provider.records r USING jsonb_to_recordset($2::jsonb) AS d(kind text,id text) WHERE r.ns=$1 AND r.kind=d.kind AND r.id=d.id', [this.namespace, json(removed)]);
      const changed: {kind:string;id:string;body:string}[]=[];
      for (const [key, value] of rows) {
        const body = json(value); if (before.get(key) === body) continue;
        const [kind, id] = JSON.parse(key);
        changed.push({kind,id,body});
      }
      if (changed.length) await this.db.query('INSERT INTO poppy_provider.records(ns,kind,id,body) SELECT $1,kind,id,body FROM jsonb_to_recordset($2::jsonb) AS d(kind text,id text,body text) ON CONFLICT(ns,kind,id) DO UPDATE SET body=excluded.body', [this.namespace, json(changed)]);
      this.metrics.rowsWritten += removed.length + changed.length;
      return result;
    });
  }
}
