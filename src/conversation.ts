import { parseConversationRequest, parseConversationState, parseEventPage, parseMessage, parseProtocolError, retryAfterMilliseconds } from './protocol/wire.js';
import type { ConversationRequest, ConversationState, EventPage, Message } from './protocol/wire.js';

export interface StateStore<State> { read(): Promise<State>; transaction<Result>(change: (draft: State) => Result): Promise<Result> }
export interface OutboundRecord {
  connectionId: string; issuer: string; id: string; target: string | null; request: ConversationRequest; fingerprint: string;
  phase: 'pending' | 'accepted' | 'rejected'; response?: ConversationState; error?: { code: string; status: number };
}
export interface ConsumerRecord { connectionId: string; issuer: string; conversationId: string; name: string; checkpoint: string | null; delivered?: { from: string | null; to: string | null } }
export interface ConversationClientState { version: 1; outbound: OutboundRecord[]; consumers: ConsumerRecord[] }
export const initialConversationClientState = (): ConversationClientState => ({ version: 1, outbound: [], consumers: [] });

export class ConversationError extends Error {
  constructor(readonly code: string, readonly status?: number, readonly retryAfterMs?: number) { super(`Conversation ${code}`); this.name = 'ConversationError'; }
}
export interface ConversationClientOptions {
  authorizedRequest(request: Request): Promise<Response>;
  endpoint: string; connectionId: string; issuer: string;
  store: StateStore<ConversationClientState>;
  clock: { now(): number };
  newId?: () => string; sleep?: (ms: number) => Promise<void>;
  maxAttempts?: number; baseDelayMs?: number; maxDelayMs?: number;
}
export type OutboundInput = Omit<Message, 'id'> & { id?: string };

// Sorted keys so structural equality ignores key order but keeps arrays, text and unknown members exact.
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
// A definite rejection will not change on retry; anything else (auth, 408, 429, 5xx) leaves the operation retryable.
const definite = (status: number) => status >= 400 && status < 500 && ![401, 403, 408, 429].includes(status);

export function createConversationClient(options: ConversationClientOptions) {
  const { authorizedRequest, store, clock, connectionId, issuer } = options;
  const endpoint = options.endpoint.replace(/\/+$/, '');
  const newId = options.newId ?? (() => `msg_${crypto.randomUUID().replaceAll('-', '')}`);
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms)));
  const maxAttempts = options.maxAttempts ?? 4, baseDelayMs = options.baseDelayMs ?? 250, maxDelayMs = options.maxDelayMs ?? 60000;
  const mine = (r: { connectionId: string; issuer: string }) => r.connectionId === connectionId && r.issuer === issuer;
  const conversationUrl = (id: string, tail: string) => `${endpoint}/${encodeURIComponent(id)}/${tail}`;

  // Idempotent by construction: callers reuse the same message ID, so retrying network errors, 429 and 5xx is safe.
  async function call(make: () => Request): Promise<Response> {
    for (let attempt = 1; ; attempt++) {
      let response: Response | undefined;
      try { response = await authorizedRequest(make()); } catch { if (attempt >= maxAttempts) throw new ConversationError('network_error'); }
      let delay = baseDelayMs * 2 ** (attempt - 1);
      if (response) {
        if (response.status !== 429 && response.status < 500) return response;
        delay = retryAfterMilliseconds(response.headers.get('retry-after'), clock.now()) ?? delay;
        // A very long Retry-After would stall the caller; surface it instead of waiting.
        if (attempt >= maxAttempts || delay > maxDelayMs) return response;
      }
      await sleep(delay);
    }
  }
  async function failure(response: Response): Promise<ConversationError> {
    let code = 'http_error';
    try { code = parseProtocolError(await response.json()).error; } catch { /* non-protocol body */ }
    return new ConversationError(code, response.status, retryAfterMilliseconds(response.headers.get('retry-after'), clock.now()));
  }

  async function dispatch(id: string): Promise<ConversationState> {
    const record = (await store.read()).outbound.find(r => mine(r) && r.id === id);
    if (!record) throw new ConversationError('unknown_operation');
    if (record.phase === 'accepted') return record.response!;
    if (record.phase === 'rejected') throw new ConversationError(record.error!.code, record.error!.status);
    const url = record.target === null ? endpoint : conversationUrl(record.target, 'messages');
    const response = await call(() => new Request(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(record.request) }));
    if (response.status >= 200 && response.status < 300) {
      let state: ConversationState;
      try { state = parseConversationState(await response.json()); } catch { throw new ConversationError('invalid_response', response.status); }
      await store.transaction(draft => { const r = draft.outbound.find(x => mine(x) && x.id === id)!; r.phase = 'accepted'; r.response = state; });
      return state;
    }
    const error = await failure(response);
    if (definite(response.status)) await store.transaction(draft => { const r = draft.outbound.find(x => mine(x) && x.id === id)!; r.phase = 'rejected'; r.error = { code: error.code, status: response.status }; });
    throw error;
  }

  // Persist identity, content and target before the first dispatch; a duplicate ID must match exactly.
  async function submit(input: OutboundInput, target: string | null, parent?: string): Promise<ConversationState & { messageId: string }> {
    const message = parseMessage({ ...input, id: input.id ?? newId() }) as Message;
    const request = parseConversationRequest({ message, ...(parent === undefined ? {} : { parent_conversation_id: parent }) });
    const fingerprint = canonical({ target, request });
    await store.transaction(draft => {
      const existing = draft.outbound.find(r => mine(r) && r.id === message.id);
      if (!existing) draft.outbound.push({ connectionId, issuer, id: message.id, target, request, fingerprint, phase: 'pending' });
      else if (existing.fingerprint !== fingerprint) throw new ConversationError('message_id_conflict');
    });
    return { ...(await dispatch(message.id)), messageId: message.id };
  }

  async function simplePost(conversationId: string, tail: 'handoff' | 'close'): Promise<ConversationState> {
    const response = await call(() => new Request(conversationUrl(conversationId, tail), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }));
    if (!response.ok) throw await failure(response);
    try { return parseConversationState(await response.json()); } catch { throw new ConversationError('invalid_response', response.status); }
  }

  const client = {
    start: (message: OutboundInput, parentConversationId?: string) => submit(message, null, parentConversationId),
    send: (conversationId: string, message: OutboundInput) => submit(message, conversationId),
    /** Re-dispatch a pending outbound operation with its original ID and content. */
    retry: dispatch,
    async operation(messageId: string): Promise<OutboundRecord | undefined> { return (await store.read()).outbound.find(r => mine(r) && r.id === messageId); },
    handoff: (conversationId: string) => simplePost(conversationId, 'handoff'),
    close: (conversationId: string) => simplePost(conversationId, 'close'),
    /** Reads one whole page. With a consumer, starts at its checkpoint and records the delivery; it never acknowledges. */
    async read(conversationId: string, opts: { cursor?: string; wait?: number; consumer?: string } = {}): Promise<EventPage> {
      let cursor = opts.cursor;
      if (opts.consumer !== undefined && cursor === undefined) {
        cursor = (await store.read()).consumers.find(c => mine(c) && c.conversationId === conversationId && c.name === opts.consumer)?.checkpoint ?? undefined;
      }
      const url = new URL(conversationUrl(conversationId, 'events'));
      if (cursor !== undefined) url.searchParams.set('cursor', cursor);
      if (opts.wait !== undefined) url.searchParams.set('wait', String(opts.wait));
      const response = await call(() => new Request(url, { method: 'GET' }));
      if (!response.ok) throw await failure(response); // cursor_expired (410) is the explicit history gap
      let page: EventPage;
      try { page = parseEventPage(await response.json(), cursor); } catch { throw new ConversationError('invalid_response', response.status); }
      if (opts.consumer !== undefined) {
        await store.transaction(draft => {
          let c = draft.consumers.find(x => mine(x) && x.conversationId === conversationId && x.name === opts.consumer);
          if (!c) draft.consumers.push(c = { connectionId, issuer, conversationId, name: opts.consumer!, checkpoint: null });
          c.delivered = { from: cursor ?? null, to: page.cursor };
        });
      }
      return page;
    },
    /** Reads pages until has_more is false. Nothing is acknowledged; callers acknowledge each page after processing. */
    async drain(conversationId: string, opts: { cursor?: string; wait?: number } = {}): Promise<EventPage[]> {
      const pages: EventPage[] = [];
      let cursor = opts.cursor;
      for (;;) {
        const page = await client.read(conversationId, { cursor, wait: pages.length ? 0 : opts.wait });
        pages.push(page);
        if (!page.has_more) return pages;
        cursor = page.cursor ?? undefined;
      }
    },
    /** Advances the consumer checkpoint only to the page last delivered to it; a stale acknowledgment is a no-op. */
    async acknowledge(conversationId: string, consumer: string, page: Pick<EventPage, 'cursor'>): Promise<void> {
      await store.transaction(draft => {
        const c = draft.consumers.find(x => mine(x) && x.conversationId === conversationId && x.name === consumer);
        if (!c?.delivered || c.delivered.to !== page.cursor) throw new ConversationError('page_not_delivered');
        if (c.checkpoint !== c.delivered.from) return;
        if (c.delivered.to !== null) c.checkpoint = c.delivered.to;
      });
    },
    async checkpoint(conversationId: string, consumer: string): Promise<string | null> {
      return (await store.read()).consumers.find(c => mine(c) && c.conversationId === conversationId && c.name === consumer)?.checkpoint ?? null;
    },
  };
  return client;
}
