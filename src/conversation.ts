import { dpopChallenge } from './auth/challenge.js';
import { id as parseId, parseConversationRequest, parseConversationState, parseEventPage, parseMessage, parseProtocolError, retryAfterMilliseconds } from './protocol/wire.js';
import type { ConversationRequest, ConversationState, EventPage, Message } from './protocol/wire.js';

export interface StateStore<State> { read(): Promise<State>; transaction<Result>(change: (draft: State) => Result): Promise<Result> }
export interface OutboundRecord {
  connectionId: string; issuer: string; id: string; target: string | null; request: ConversationRequest; fingerprint: string;
  phase: 'pending' | 'accepted' | 'rejected'; read?: ReadParams; response?: ConversationState | EventPage; error?: { code: string; status: number; conversationId?: string };
}
// POST ?wait/?cursor, persisted with the record so a retry repeats the original read parameters (spec 7.3).
export interface ReadParams { wait?: number; cursor?: string }
// A named consumer's durable checkpoint; only ack() moves it.
export interface ConsumerCheckpoint { connectionId: string; issuer: string; conversationId: string; name: string; cursor: string }
export interface ConversationClientState { version: 1; outbound: OutboundRecord[]; consumers: ConsumerCheckpoint[] }
export const initialConversationClientState = (): ConversationClientState => ({ version: 1, outbound: [], consumers: [] });

// Only known spec codes (7.13, 6) reach messages and callers; a company-chosen string never does.
const knownCodes = new Set(['conversation_not_found', 'conversation_closed', 'direct_conversation_open', 'message_id_conflict', 'invalid_cursor', 'cursor_expired', 'invalid_request', 'extension_required', 'rate_limited', 'invalid_token', 'invalid_dpop_proof', 'use_dpop_nonce', 'sign_in_required', 'insufficient_scope']);
export class ConversationError extends Error {
  constructor(readonly code: string, readonly status?: number, readonly retryAfterMs?: number, readonly scope?: string, readonly conversationId?: string) { super(`Conversation ${code}`); this.name = 'ConversationError'; }
}
export interface ConversationClientOptions {
  authorizedRequest(request: Request): Promise<Response>;
  endpoint: string; connectionId: string; issuer: string;
  store: StateStore<ConversationClientState>;
  clock: { now(): number };
  newId?: () => string; sleep?: (ms: number) => Promise<void>;
  maxAttempts?: number; baseDelayMs?: number; maxDelayMs?: number; maxPages?: number; keepCompleted?: number;
}
export interface ReadOptions extends ReadParams { consumer?: string }
export type OutboundInput = Omit<Message, 'id'> & { id?: string };

// Sorted keys so structural equality ignores key order but keeps arrays, text and unknown members exact.
function canonical(value: unknown): string {
  return walk(JSON.parse(JSON.stringify(value))); // same shape as the wire (drops undefined members)
}
function walk(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(walk).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${walk((value as Record<string, unknown>)[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
// A definite rejection will not change on retry; anything else (auth, 408, 429, 5xx) leaves the operation retryable.
const definite = (status: number) => status >= 400 && status < 500 && ![401, 403, 408, 429].includes(status);

export function createConversationClient(options: ConversationClientOptions) {
  const { authorizedRequest, store, clock, connectionId, issuer } = options;
  const endpoint = options.endpoint.replace(/\/+$/, '');
  const newId = options.newId ?? (() => `msg_${crypto.randomUUID().replaceAll('-', '')}`);
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms)));
  const maxAttempts = options.maxAttempts ?? 4, baseDelayMs = options.baseDelayMs ?? 250, maxDelayMs = options.maxDelayMs ?? 60000, maxPages = options.maxPages ?? 1000, keepCompleted = options.keepCompleted ?? 100;
  const mine = (r: { connectionId: string; issuer: string }) => r.connectionId === connectionId && r.issuer === issuer;
  // Validated IDs only: '.' and '..' survive encodeURIComponent and would escape the endpoint.
  const conversationUrl = (id: string, tail: string) => `${endpoint}/${parseId(id, 'conversation_id')}/${tail}`;

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
    let code = '', scope: string | undefined, conversationId: string | undefined;
    try { const body = parseProtocolError(await response.json()); code = body.error; if (code === 'direct_conversation_open') conversationId = body.conversation_id; } catch { /* non-protocol body */ }
    if (!knownCodes.has(code)) {
      // Token errors (spec 6) arrive in WWW-Authenticate: DPoP error="...", scope="...".
      const challenge = dpopChallenge(response.headers.get('www-authenticate'));
      code = challenge?.error ?? '';
      scope = challenge?.scope;
    }
    if (!knownCodes.has(code)) code = 'http_error';
    return new ConversationError(code, response.status, retryAfterMilliseconds(response.headers.get('retry-after'), clock.now()), code === 'insufficient_scope' ? scope : undefined, conversationId);
  }

  // Pages handed to a consumer in this process; the checkpoint moves only when one of them is acked.
  const delivered = new WeakMap<EventPage, { conversationId: string; consumer: string; chain: (string | undefined)[] }>();
  async function checkpoint(conversationId: string, consumer: string): Promise<string | undefined> {
    parseId(consumer, 'consumer');
    return ((await store.read()).consumers ?? []).find(c => mine(c) && c.conversationId === conversationId && c.name === consumer)?.cursor;
  }

  async function dispatch(id: string): Promise<ConversationState> {
    parseId(id, 'message.id');
    const record = (await store.read()).outbound.find(r => mine(r) && r.id === id);
    if (!record) throw new ConversationError('unknown_operation');
    if (record.phase === 'accepted') return record.response!;
    if (record.phase === 'rejected') throw new ConversationError(record.error!.code, record.error!.status, undefined, undefined, record.error!.conversationId);
    const url = new URL(record.target === null ? endpoint : conversationUrl(record.target, 'messages'));
    if (record.read?.cursor !== undefined) url.searchParams.set('cursor', record.read.cursor);
    if (record.read?.wait !== undefined) url.searchParams.set('wait', String(record.read.wait));
    const response = await call(() => new Request(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(record.request) }));
    if (response.status >= 200 && response.status < 300) {
      let state: ConversationState | EventPage;
      try {
        const body = await response.json();
        // A 2xx means accepted; a company that ignores wait answers with a plain state.
        try { state = record.read ? parseEventPage(body, record.read.cursor) : parseConversationState(body); } catch { state = parseConversationState(body); }
      } catch { throw new ConversationError('invalid_response', response.status); }
      await store.transaction(draft => { const r = draft.outbound.find(x => mine(x) && x.id === id)!; r.phase = 'accepted'; r.response = state; });
      return state;
    }
    const error = await failure(response);
    // direct_conversation_open lasts only until the Direct Conversation closes (spec 7.10), so the same message stays retryable.
    if (definite(response.status) && error.code !== 'direct_conversation_open') await store.transaction(draft => { const r = draft.outbound.find(x => mine(x) && x.id === id)!; r.phase = 'rejected'; r.error = { code: error.code, status: response.status, ...(error.conversationId === undefined ? {} : { conversationId: error.conversationId }) }; });
    throw error;
  }

  // Persist identity, content and target before the first dispatch; a duplicate ID must match exactly.
  async function submit(input: OutboundInput, target: string | null, read: ReadParams, parent?: string): Promise<(ConversationState | EventPage) & { messageId: string }> {
    if (target !== null) parseId(target, 'conversation_id');
    if (read.wait !== undefined && (!Number.isSafeInteger(read.wait) || read.wait < 0)) throw new ConversationError('invalid_request');
    if (read.cursor !== undefined) { parseId(read.cursor, 'cursor'); if (read.wait === undefined) throw new ConversationError('invalid_request'); } // spec 7.3 adds cursor alongside wait
    const message = parseMessage({ ...input, id: input.id ?? newId() }) as Message;
    const request = parseConversationRequest({ message, ...(parent === undefined ? {} : { parent_conversation_id: parent }) });
    const fingerprint = canonical({ target, request });
    await store.transaction(draft => {
      const existing = draft.outbound.find(r => mine(r) && r.id === message.id);
      if (!existing) {
        draft.outbound.push({ connectionId, issuer, id: message.id, target, request, fingerprint, phase: 'pending', ...(read.wait === undefined && read.cursor === undefined ? {} : { read: { ...read } }) });
        // Keep only the newest completed records (enough to dedupe a recent retry); pending ones always stay.
        let kept = 0;
        draft.outbound = draft.outbound.reverse().filter(r => r.phase === 'pending' || !mine(r) || ++kept <= keepCompleted).reverse();
      } else if (existing.fingerprint !== fingerprint) throw new ConversationError('message_id_conflict');
    });
    return { ...(await dispatch(message.id)), messageId: message.id };
  }

  async function simplePost(conversationId: string, tail: 'handoff' | 'close'): Promise<ConversationState> {
    parseId(conversationId, 'conversation_id');
    const response = await call(() => new Request(conversationUrl(conversationId, tail), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }));
    if (!response.ok) throw await failure(response);
    try { return parseConversationState(await response.json()); } catch { throw new ConversationError('invalid_response', response.status); }
  }

  const client = {
    start: (message: OutboundInput, opts: ReadParams & { parentConversationId?: string } = {}) => submit(message, null, opts, opts.parentConversationId),
    send: (conversationId: string, message: OutboundInput, opts: ReadParams = {}) => submit(message, conversationId, opts),
    /** Re-dispatch a pending outbound operation with its original ID and content. */
    retry: dispatch,
    async operation(messageId: string): Promise<OutboundRecord | undefined> { return (await store.read()).outbound.find(r => mine(r) && r.id === messageId); },
    handoff: (conversationId: string) => simplePost(conversationId, 'handoff'),
    close: (conversationId: string) => simplePost(conversationId, 'close'),
    /** Reads one whole page. Explicit `cursor`, or the checkpoint of a named `consumer` (not both). Never acknowledges. */
    async read(conversationId: string, opts: ReadOptions = {}): Promise<EventPage> {
      parseId(conversationId, 'conversation_id');
      if (opts.consumer !== undefined && opts.cursor !== undefined) throw new ConversationError('invalid_request'); // the ack would be silently meaningless
      const cursor = opts.consumer === undefined ? opts.cursor : await checkpoint(conversationId, opts.consumer);
      const url = new URL(conversationUrl(conversationId, 'events'));
      if (cursor !== undefined) url.searchParams.set('cursor', cursor);
      if (opts.wait !== undefined) url.searchParams.set('wait', String(opts.wait));
      const response = await call(() => new Request(url, { method: 'GET' }));
      if (!response.ok) throw await failure(response); // cursor_expired (410) is the explicit history gap: see resetConsumer
      let page: EventPage;
      try { page = parseEventPage(await response.json(), cursor); } catch { throw new ConversationError('invalid_response', response.status); }
      if (opts.consumer !== undefined) delivered.set(page, { conversationId, consumer: opts.consumer, chain: [cursor] });
      return page;
    },
    /** Reads pages until has_more is false. Pages are returned whole, never acknowledged. */
    async drain(conversationId: string, opts: ReadOptions = {}): Promise<EventPage[]> {
      if (opts.consumer !== undefined && opts.cursor !== undefined) throw new ConversationError('invalid_request');
      const pages: EventPage[] = [];
      let cursor = opts.consumer === undefined ? opts.cursor : await checkpoint(conversationId, opts.consumer);
      const chain = [cursor]; // checkpoints this page may legitimately advance from
      for (; pages.length < maxPages; ) {
        const page = await client.read(conversationId, { cursor, wait: pages.length ? 0 : opts.wait });
        if (opts.consumer !== undefined) delivered.set(page, { conversationId, consumer: opts.consumer, chain: [...chain] });
        pages.push(page);
        if (!page.has_more) return pages;
        // has_more with no new events or an unchanged cursor can never finish.
        if (!page.events.length || page.cursor === null || page.cursor === cursor) throw new ConversationError('invalid_response');
        cursor = page.cursor; chain.push(cursor);
      }
      throw new ConversationError('too_many_pages');
    },
    /** Durably advances the consumer to the page's cursor, after the application processed that page. A page never delivered to this consumer by this client instance is refused. */
    async ack(conversationId: string, consumer: string, page: EventPage): Promise<void> {
      parseId(conversationId, 'conversation_id'); parseId(consumer, 'consumer');
      const from = delivered.get(page);
      if (from?.conversationId !== conversationId || from.consumer !== consumer) throw new ConversationError('invalid_request');
      if (page.cursor === null) return; // empty foreign page: nothing to advance past
      const cursor = page.cursor;
      // Compare-and-set: cursors are opaque, so a page advances only from a checkpoint it was read from; stale acks do nothing.
      await store.transaction(draft => {
        const list = draft.consumers ??= [];
        const row = list.find(c => mine(c) && c.conversationId === conversationId && c.name === consumer);
        if (!from.chain.includes(row?.cursor)) return;
        if (row) row.cursor = cursor; else list.push({ connectionId, issuer, conversationId, name: consumer, cursor });
      });
    },
    /** After cursor_expired: forget the checkpoint so the consumer rereads retained history from the start (dedupe by event ID; missing events were not processed). */
    async resetConsumer(conversationId: string, consumer: string): Promise<void> {
      parseId(conversationId, 'conversation_id'); parseId(consumer, 'consumer');
      await store.transaction(draft => { draft.consumers = (draft.consumers ?? []).filter(c => !(mine(c) && c.conversationId === conversationId && c.name === consumer)); });
    },
  };
  return client;
}
