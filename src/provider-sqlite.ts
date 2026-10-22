import { DatabaseSync } from 'node:sqlite';
import { initializeSqlite } from './sqlite-init.js';
import type { ProviderStore, ProviderTransaction } from './provider.js';
/** Optional durable provider records. Callback results must be encrypted by the separately configured cipher. */
export class SqliteProviderStore implements ProviderStore {
  private readonly db: DatabaseSync;
  constructor(path: string) {
    this.db = new DatabaseSync(path);
    initializeSqlite(this.db, () => this.db.exec('PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS provider_records(kind TEXT NOT NULL,id TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(kind,id));'));
  }
  close(): void { this.db.close(); }
  transaction<T>(action: (tx: ProviderTransaction) => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = action({
        get: (kind, id) => { const row = this.db.prepare('SELECT body FROM provider_records WHERE kind=? AND id=?').get(kind, id); return row ? JSON.parse(row.body as string) : undefined; },
        put: (kind, id, value) => { this.db.prepare('INSERT OR REPLACE INTO provider_records VALUES (?,?,?)').run(kind, id, JSON.stringify(value)); },
        remove: (kind, id) => { this.db.prepare('DELETE FROM provider_records WHERE kind=? AND id=?').run(kind, id); },
        list: (kind, prefix, limit) => this.db.prepare('SELECT id,body FROM provider_records WHERE kind=? AND id>=? AND id<? ORDER BY id LIMIT ?').all(kind, prefix, `${prefix}\uffff`, limit).map(row => ({ id: row.id as string, value: JSON.parse(row.body as string) })),
      });
      if (result instanceof Promise) throw new TypeError('provider transaction must be synchronous');
      this.db.exec('COMMIT'); return result;
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
}
