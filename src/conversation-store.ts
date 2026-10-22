import type { ConsumerCheckpoint, OutboundRecord } from './conversation.js';

export interface ConversationKey { connectionId: string; issuer: string; endpoint: string }
export interface ConversationStore {
  getOutbound(key: ConversationKey, id: string): Promise<OutboundRecord | undefined>;
  /** Insert or return the existing record atomically; never replace its destination/content. */
  prepareOutbound(key: ConversationKey, record: OutboundRecord): Promise<OutboundRecord>;
  settleOutbound(key: ConversationKey, id: string, result: Pick<OutboundRecord, 'phase' | 'response' | 'error'>): Promise<void>;
  getCheckpoint(key: ConversationKey, conversationId: string, name: string): Promise<string | undefined>;
  advanceCheckpoint(key: ConversationKey, checkpoint: ConsumerCheckpoint, from: readonly (string | undefined)[]): Promise<void>;
  resetCheckpoint(key: ConversationKey, conversationId: string, name: string): Promise<void>;
}
