import type { ConversationKey, ConversationStore } from './conversation-store.js';
import type { ConsumerCheckpoint, OutboundRecord } from './conversation.js';

/** Non-durable, single-process test/development adapter. */
export class MemoryConversationStore implements ConversationStore {
  private readonly outbound = new Map<string, OutboundRecord>();
  private readonly checkpoints = new Map<string, string>();
  private outKey(key: ConversationKey, id: string): string { return JSON.stringify([key.connectionId, key.issuer, id]); }
  private checkKey(key: ConversationKey, conversation: string, name: string): string { return JSON.stringify([key.connectionId, key.issuer, key.endpoint, conversation, name]); }
  async getOutbound(key: ConversationKey, id: string): Promise<OutboundRecord | undefined> { return structuredClone(this.outbound.get(this.outKey(key, id))); }
  async prepareOutbound(key: ConversationKey, row: OutboundRecord): Promise<OutboundRecord> {
    if (row.connectionId !== key.connectionId || row.issuer !== key.issuer || row.endpoint !== key.endpoint) throw new TypeError('outbound binding');
    const id = this.outKey(key, row.id);
    if (!this.outbound.has(id)) this.outbound.set(id, structuredClone(row));
    return structuredClone(this.outbound.get(id)!);
  }
  async settleOutbound(key: ConversationKey, id: string, result: Pick<OutboundRecord, 'phase' | 'response' | 'error'>): Promise<void> {
    const row = this.outbound.get(this.outKey(key, id));
    if (!row || row.endpoint !== key.endpoint) throw new TypeError('outbound binding');
    if (row.phase === 'pending') Object.assign(row, structuredClone(result));
  }
  async getCheckpoint(key: ConversationKey, conversation: string, name: string): Promise<string | undefined> { return this.checkpoints.get(this.checkKey(key, conversation, name)); }
  async advanceCheckpoint(key: ConversationKey, row: ConsumerCheckpoint, from: readonly (string | undefined)[]): Promise<void> {
    if (row.connectionId !== key.connectionId || row.issuer !== key.issuer) throw new TypeError('checkpoint binding');
    const id = this.checkKey(key, row.conversationId, row.name);
    if (from.includes(this.checkpoints.get(id))) this.checkpoints.set(id, row.cursor);
  }
  async resetCheckpoint(key: ConversationKey, conversation: string, name: string): Promise<void> { this.checkpoints.delete(this.checkKey(key, conversation, name)); }
}
