import { DatabaseSync } from 'node:sqlite';
import { initializeSqlite } from './sqlite-init.js';
export { SqliteAuthStore } from './auth/sqlite-store.js';
import type { ConversationKey, ConversationStore } from './conversation-store.js';
import type { ConsumerCheckpoint, OutboundRecord } from './conversation.js';

/** Optional durable adapter. One local SQLite database; not a secret vault. */
export class SqliteConversationStore implements ConversationStore {
  private readonly db: DatabaseSync;
  constructor(path: string) {
    this.db = new DatabaseSync(path);
    initializeSqlite(this.db, () => this.db.exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS outbound (
        connection TEXT NOT NULL, issuer TEXT NOT NULL, id TEXT NOT NULL, body TEXT NOT NULL,
        PRIMARY KEY(connection, issuer, id));
      CREATE TABLE IF NOT EXISTS checkpoints (
        connection TEXT NOT NULL, issuer TEXT NOT NULL, endpoint TEXT NOT NULL,
        conversation TEXT NOT NULL, name TEXT NOT NULL, cursor TEXT NOT NULL,
        PRIMARY KEY(connection, issuer, endpoint, conversation, name));`));
  }
  close(): void { this.db.close(); }
  private atomic<T>(action: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try { const result = action(); this.db.exec('COMMIT'); return result; }
    catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  private outbound(key: ConversationKey, id: string): OutboundRecord | undefined {
    const row = this.db.prepare('SELECT body FROM outbound WHERE connection=? AND issuer=? AND id=?').get(key.connectionId, key.issuer, id);
    return row ? JSON.parse(row.body as string) : undefined;
  }
  async getOutbound(key: ConversationKey, id: string): Promise<OutboundRecord | undefined> { return this.outbound(key, id); }
  async prepareOutbound(key: ConversationKey, record: OutboundRecord): Promise<OutboundRecord> {
    if (record.connectionId !== key.connectionId || record.issuer !== key.issuer || record.endpoint !== key.endpoint) throw new TypeError('outbound binding');
    return this.atomic(() => {
      this.db.prepare('INSERT OR IGNORE INTO outbound VALUES (?,?,?,?)').run(key.connectionId, key.issuer, record.id, JSON.stringify(record));
      return this.outbound(key, record.id)!;
    });
  }
  async settleOutbound(key: ConversationKey, id: string, result: Pick<OutboundRecord, 'phase' | 'response' | 'error'>): Promise<void> {
    this.atomic(() => {
      const record = this.outbound(key, id);
      if (!record || record.endpoint !== key.endpoint) throw new TypeError('outbound binding');
      if (record.phase !== 'pending') return;
      this.db.prepare('UPDATE outbound SET body=? WHERE connection=? AND issuer=? AND id=?').run(JSON.stringify({ ...record, ...result }), key.connectionId, key.issuer, id);
    });
  }
  private checkpoint(key: ConversationKey, conversation: string, name: string): string | undefined {
    return this.db.prepare('SELECT cursor FROM checkpoints WHERE connection=? AND issuer=? AND endpoint=? AND conversation=? AND name=?')
      .get(key.connectionId, key.issuer, key.endpoint, conversation, name)?.cursor as string | undefined;
  }
  async getCheckpoint(key: ConversationKey, conversation: string, name: string): Promise<string | undefined> { return this.checkpoint(key, conversation, name); }
  async advanceCheckpoint(key: ConversationKey, row: ConsumerCheckpoint, from: readonly (string | undefined)[]): Promise<void> {
    if (row.connectionId !== key.connectionId || row.issuer !== key.issuer) throw new TypeError('checkpoint binding');
    this.atomic(() => {
      if (!from.includes(this.checkpoint(key, row.conversationId, row.name))) return;
      this.db.prepare('INSERT OR REPLACE INTO checkpoints VALUES (?,?,?,?,?,?)').run(key.connectionId, key.issuer, key.endpoint, row.conversationId, row.name, row.cursor);
    });
  }
  async resetCheckpoint(key: ConversationKey, conversation: string, name: string): Promise<void> {
    this.db.prepare('DELETE FROM checkpoints WHERE connection=? AND issuer=? AND endpoint=? AND conversation=? AND name=?').run(key.connectionId, key.issuer, key.endpoint, conversation, name);
  }
}
