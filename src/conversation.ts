import { dpopChallenge } from './auth/challenge.js';
import { id as parseId, parseConversationRequest, parseConversationState, parseEventPage, parseMessage, parseProtocolError, retryAfterMilliseconds } from './protocol/wire.js';
import type { ConversationRequest, ConversationState, EventPage, Message } from './protocol/wire.js';

export interface StateStore<State> { read(): Promise<State>; transaction<Result>(change: (draft: State) => Result): Promise<Result> }
export interface OutboundRecord {
  connectionId: string; issuer: string; id: string; target: string | null; request: ConversationRequest; fingerprint: string;
  phase: 'pending' | 'accepted' | 'rejected'; response?: ConversationState; error?: { code: string; status: number };
}
export interface ConversationClientState { version: 1; outbound: OutboundRecord[] }
export const initialConversationClientState = (): ConversationClientState => ({ version: 1, outbound: [] });

// Only known spec codes (7.13, 6) reach messages and callers; a company-chosen string never does.
const knownCodes = new Set(['conversation_not_found', 'conversation_closed', 'direct_conversation_open', 'message_id_conflict', 'invalid_cursor', 'cursor_expired', 'invalid_request', 'extension_required', 'rate_limited', 'invalid_token', 'invalid_dpop_proof', 'use_dpop_nonce', 'sign_in_required', 'insufficient_scope']);
export class ConversationError extends Error {
  constructor(readonly code: string, readonly status?: number, readonly retryAfterMs?: number, readonly scope?: string) { super(`Conversation ${code}`); this.name = 'ConversationError'; }
}
export interface ConversationClientOptions {
  authorizedRequest(request: Request): Promise<Response>;
  endpoint: string; connectionId: string; issuer: string;
  store: StateStore<ConversationClientState>;
  clock: { now(): number };
  newId?: () => string; sleep?: (ms: number) => Promise<void>;
  maxAttempts?: number; baseDelayMs?: number; maxDelayMs?: number; maxPages?: number;
}
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
  const maxAttempts = options.maxAttempts ?? 4, baseDelayMs = options.baseDelayMs ?? 250, maxDelayMs = options.maxDelayMs ?? 60000, maxPages = options.maxPages ?? 1000;
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
    let code = '', scope: string | undefined;
    try { code = parseProtocolError(await response.json()).error; } catch { /* non-protocol body */ }
    if (!knownCodes.has(code)) {
      // Token errors (spec 6) arrive in WWW-Authenticate: DPoP error="...", scope="...".
      const challenge = dpopChallenge(response.headers.get('www-authenticate'));
      code = challenge?.error ?? '';
      scope = challenge?.scope;
    }
    if (!knownCodes.has(code)) code = 'http_error';
    return new ConversationError(code, response.status, retryAfterMilliseconds(response.headers.get('retry-after'), clock.now()), code === 'insufficient_scope' ? scope : undefined);
  }

  async function dispatch(id: string): Promise<ConversationState> {
    parseId(id, 'message.id');
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
    if (target !== null) parseId(target, 'conversation_id');
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
    parseId(conversationId, 'conversation_id');
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
    /** Reads one whole page from an explicit cursor. */
    async read(conversationId: string, opts: { cursor?: string; wait?: number } = {}): Promise<EventPage> {
      parseId(conversationId, 'conversation_id');
      const cursor = opts.cursor;
      const url = new URL(conversationUrl(conversationId, 'events'));
      if (cursor !== undefined) url.searchParams.set('cursor', cursor);
      if (opts.wait !== undefined) url.searchParams.set('wait', String(opts.wait));
      const response = await call(() => new Request(url, { method: 'GET' }));
      if (!response.ok) throw await failure(response); // cursor_expired (410) is the explicit history gap
      let page: EventPage;
      try { page = parseEventPage(await response.json(), cursor); } catch { throw new ConversationError('invalid_response', response.status); }
      return page;
    },
    /** Reads pages until has_more is false. Pages are returned whole, never acknowledged. */
    async drain(conversationId: string, opts: { cursor?: string; wait?: number } = {}): Promise<EventPage[]> {
      const pages: EventPage[] = [];
      let cursor = opts.cursor;
      for (; pages.length < maxPages; ) {
        const page = await client.read(conversationId, { cursor, wait: pages.length ? 0 : opts.wait });
        pages.push(page);
        if (!page.has_more) return pages;
        // has_more with no new events or an unchanged cursor can never finish.
        if (!page.events.length || page.cursor === null || page.cursor === cursor) throw new ConversationError('invalid_response');
        cursor = page.cursor;
      }
      throw new ConversationError('too_many_pages');
    },
  };
  return client;
}
