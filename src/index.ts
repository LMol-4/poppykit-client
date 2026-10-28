export { createClientAuth, initialClientAuthState, AuthFailure } from './auth/client-auth.js';
export type { ClientAuth, ClientAuthOptions, SignOutOutcome, ClientAuthState, AuthStore, AuthSelection, SecretStore, IdentitySigner, Connection, ConnectionStatus, AuthOutcome, OperationStatus, ConversationTarget } from './auth/client-auth.js';
export { createNodeTransport } from './network/transport.js';
export type { HttpTransport, NetworkOptions } from './network/transport.js';
export { createMetadataResolver, signInMethods } from './network/discovery.js';
export type { MetadataResolver } from './network/discovery.js';
export { createConversationClient, initialConversationClientState, ConversationError } from './conversation.js';
export type { ConversationClientOptions, ConsumerCheckpoint, ConversationClientState, OutboundInput, OutboundRecord, ReadOptions, ReadParams } from './conversation.js';

export type { ConversationStore, ConversationKey } from './conversation-store.js';

export type { OperationOwner } from './auth/ownership.js';

export type { WatchOptions, WatchedEvent } from './conversation.js';
export { parseEventStream } from './protocol/sse.js';
export type { StreamFrame } from './protocol/sse.js';

export type { AssertionRequest, AssertionProvider, ProviderIdentity, TrustedInput, SignInMethod, SignInInput, SignInStart, AuthorizationRequirement } from './auth/client-auth.js';
export { authChallenge } from './auth/challenge.js';
export type { AuthChallenge } from './auth/challenge.js';
export type { ApiTarget, AgentBrowserController, FeedbackReport } from './integrations.js';
export { protectedResourceMetadataUrl } from './integrations.js';

export type { Author, AuthorType, Message, RecordedMessage, ConversationRequest, ConversationState, ConversationEvent, KnownEvent, EventPage } from './protocol/wire.js';

export type { Alternative, AlternativeReference, ExcludedTask } from './network/tasks.js';
export type { ScopeHint } from './network/discovery.js';
