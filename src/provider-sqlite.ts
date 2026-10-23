import { DatabaseSync } from 'node:sqlite';
import { initializeSqlite } from './sqlite-init.js';
import type { ProviderSelection, ProviderStore, ProviderTransaction } from './provider.js';
import { scopedProviderTransaction } from './provider-storage.js';
/** Optional durable provider records. Callback results must be encrypted by the separately configured cipher. */
export class SqliteProviderStore implements ProviderStore {
  private readonly db: DatabaseSync;
  constructor(path: string) {
    this.db = new DatabaseSync(path);
    initializeSqlite(this.db, () => this.db.exec('PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS provider_records(kind TEXT NOT NULL,id TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(kind,id));'));
    this.db.exec(`INSERT OR IGNORE INTO provider_records SELECT 'capacity','enrollments',json_object('count',count(*)) FROM provider_records WHERE kind='enrollment'`);
  }
  close(): void { this.db.close(); }
  async transaction<T>(selection: ProviderSelection, action: (tx: ProviderTransaction) => T): Promise<T> {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = action(scopedProviderTransaction(selection, {
        get: (kind, id) => { const row = this.db.prepare('SELECT body FROM provider_records WHERE kind=? AND id=?').get(kind, id); return row ? JSON.parse(row.body as string) : undefined; },
        put: (kind, id, value) => { this.db.prepare('INSERT OR REPLACE INTO provider_records VALUES (?,?,?)').run(kind, id, JSON.stringify(value)); },
        remove: (kind, id) => { this.db.prepare('DELETE FROM provider_records WHERE kind=? AND id=?').run(kind, id); },
        list: (kind, prefix, limit) => this.db.prepare('SELECT id,body FROM provider_records WHERE kind=? AND id>=? AND id<? ORDER BY id LIMIT ?').all(kind, prefix, `${prefix.slice(0,-1)};`, limit).map(row => ({ id: row.id as string, value: JSON.parse(row.body as string) })),
      }));
      if (result && typeof (result as { then?: unknown }).then === 'function') throw new TypeError('provider transaction must be synchronous');
      const detached = structuredClone(result);
      this.db.exec('COMMIT'); return detached;
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
}
