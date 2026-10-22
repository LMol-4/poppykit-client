export { createClientAuth, initialClientAuthState, AuthFailure } from './auth/client-auth.js';
export type { ClientAuth, ClientAuthOptions, SignOutOutcome, ClientAuthState, AuthStore, AuthSelection, SecretStore, IdentitySigner, Connection, ConnectionStatus, AuthOutcome, OperationStatus, ConversationTarget } from './auth/client-auth.js';
export { createNodeTransport } from './network/transport.js';
export type { HttpTransport, NetworkOptions } from './network/transport.js';
export { createMetadataResolver } from './network/discovery.js';
export type { MetadataResolver } from './network/discovery.js';
export { createConversationClient, initialConversationClientState, ConversationError } from './conversation.js';
export type { ConversationClientOptions, ConsumerCheckpoint, ConversationClientState, OutboundInput, OutboundRecord, ReadOptions, ReadParams } from './conversation.js';

export type { ConversationStore, ConversationKey } from './conversation-store.js';

export type { OperationOwner } from './auth/ownership.js';

export type { WatchOptions, WatchedEvent } from './conversation.js';
export { parseEventStream } from './protocol/sse.js';
export type { StreamFrame } from './protocol/sse.js';
