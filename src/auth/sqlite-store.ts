import { DatabaseSync } from 'node:sqlite';
import { initializeSqlite } from '../sqlite-init.js';
import { initialClientAuthState } from './client-auth.js';
import type { ClientAuthState } from './client-auth.js';
import type { AuthSelection, AuthStore } from './store.js';

const tables = ['identities', 'connections', 'grants', 'operations', 'cleanup'] as const;
function json(value: unknown): string {
  return JSON.stringify(value, (_key, item) => {
    if (item === undefined || typeof item === 'function' || typeof item === 'bigint' || (typeof item === 'number' && !Number.isFinite(item))) throw new TypeError('non-JSON auth record');
    return item;
  });
}

/** One database per local auth namespace/user/client. References only: secrets belong in SecretStore. */
export class SqliteAuthStore implements AuthStore {
  private readonly db: DatabaseSync;
  constructor(path: string) {
    this.db = new DatabaseSync(path);
    initializeSqlite(this.db, () => {
    this.db.exec('PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
    this.db.exec('CREATE TABLE IF NOT EXISTS auth_meta (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL)');
    for (const table of tables) this.db.exec(`CREATE TABLE IF NOT EXISTS auth_${table} (id TEXT PRIMARY KEY, body TEXT NOT NULL)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS operations_connection ON auth_operations(json_extract(body,'$.connectionId'));
      CREATE UNIQUE INDEX IF NOT EXISTS operations_callback ON auth_operations(json_extract(body,'$.direct.stateHash'));
      CREATE INDEX IF NOT EXISTS operations_pending ON auth_operations(id) WHERE json_extract(body,'$.phase')!='terminal';
      CREATE INDEX IF NOT EXISTS operations_cleanup ON auth_operations(json_extract(body,'$.createdAt')) WHERE json_extract(body,'$.phase')='terminal' AND json_extract(body,'$.status')!='uncertain';
      CREATE INDEX IF NOT EXISTS cleanup_connection ON auth_cleanup(json_extract(body,'$.connectionId'));`);
    const { version, epoch, owner } = initialClientAuthState();
    this.db.prepare('INSERT OR IGNORE INTO auth_meta VALUES (1,?)').run(json({ version, epoch, owner }));
    });
  }
  close(): void { this.db.close(); }
  async pendingOperations(after: string | undefined, limit: number): Promise<string[]> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw new TypeError('recovery limit');
    return this.db.prepare("SELECT id FROM auth_operations WHERE json_extract(body,'$.phase')!='terminal' AND id>? ORDER BY id LIMIT ?").all(after ?? '', limit).map(row => row.id as string);
  }
  /** Explicit bounded history cleanup; uncertain outcomes and pending operations always remain. */
  async cleanup(before: number, limit = 100): Promise<number> {
    if (!Number.isFinite(before) || !Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw new TypeError('cleanup limit');
    return Number(this.db.prepare("DELETE FROM auth_operations WHERE id IN (SELECT id FROM auth_operations WHERE json_extract(body,'$.phase')='terminal' AND json_extract(body,'$.status')!='uncertain' AND json_extract(body,'$.createdAt')<? ORDER BY json_extract(body,'$.createdAt') LIMIT ?)").run(before, limit).changes);
  }
  private select(selection: AuthSelection): ClientAuthState {
    const state: ClientAuthState = { ...JSON.parse(this.db.prepare('SELECT body FROM auth_meta WHERE id=1').get()!.body as string), identities: {}, connections: {}, grants: {}, operations: {}, cleanup: {} };
    const get = (table: typeof tables[number], id: string) => {
      const row = this.db.prepare(`SELECT body FROM auth_${table} WHERE id=?`).get(id);
      if (row) (state[table] as Record<string, unknown>)[id] = JSON.parse(row.body as string);
    };
    const rows = (table: typeof tables[number], clause: string, ...params: string[]) => {
      for (const row of this.db.prepare(`SELECT id,body FROM auth_${table} ${clause}`).all(...params)) (state[table] as Record<string, unknown>)[row.id as string] = JSON.parse(row.body as string);
    };
    const history = () => {
      if (selection.history) rows('operations', "WHERE json_extract(body,'$.phase')='terminal' AND json_extract(body,'$.status')!='uncertain' AND json_extract(body,'$.kind')!='renew' ORDER BY json_extract(body,'$.createdAt') DESC,id DESC LIMIT 201");
    };
    if ('issuer' in selection) { get('identities', selection.issuer); history(); return state; }
    if ('connectionId' in selection) get('connections', selection.connectionId);
    else if ('operationId' in selection) get('operations', selection.operationId);
    else if ('callbackHash' in selection) rows('operations', "WHERE json_extract(body,'$.direct.stateHash')=?", selection.callbackHash);
    else if ('list' in selection) rows('connections', '');
    for (const operation of Object.values(state.operations)) get('connections', operation.connectionId);
    for (const connection of Object.values(state.connections)) {
      if (connection.grantId) get('grants', connection.grantId);
      if (!('list' in selection)) {
        rows('operations', "WHERE json_extract(body,'$.connectionId')=?", connection.id);
        rows('cleanup', "WHERE json_extract(body,'$.connectionId')=?", connection.id);
      }
    }
    for (const operation of Object.values(state.operations)) if (operation.grantId) get('grants', operation.grantId);
    history(); return state;
  }
  async read(selection: AuthSelection): Promise<ClientAuthState> {
    this.db.exec('BEGIN');
    try { const state = this.select(selection); this.db.exec('COMMIT'); return state; }
    catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  async transaction<T>(selection: AuthSelection, change: (draft: ClientAuthState) => T): Promise<T> {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const state = this.select(selection), before = structuredClone(state);
      const result = change(state);
      if (result && typeof (result as { then?: unknown }).then === 'function') throw new TypeError('async auth transaction');
      const { version, epoch, owner } = state;
      const metadata = json({ version, epoch, owner });
      if (metadata !== json({ version: before.version, epoch: before.epoch, owner: before.owner })) this.db.prepare('UPDATE auth_meta SET body=? WHERE id=1').run(metadata);
      for (const table of tables) {
        for (const id of Object.keys(before[table])) if (!Object.hasOwn(state[table], id)) this.db.prepare(`DELETE FROM auth_${table} WHERE id=?`).run(id);
        for (const [id, value] of Object.entries(state[table])) {
          const body = json(value);
          if (!Object.hasOwn(before[table], id) || body !== json((before[table] as Record<string, unknown>)[id])) this.db.prepare(`INSERT INTO auth_${table} VALUES (?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body`).run(id, body);
        }
      }
      const detached = structuredClone(result);
      this.db.exec('COMMIT');
      return detached;
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
}
