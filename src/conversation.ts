import { parseEventStream } from './protocol/sse.js';
import type { ConversationEvent } from './protocol/wire.js';
import type { ConversationStore } from './conversation-store.js';
import { dpopChallenge } from './auth/challenge.js';
import { secureUrl, TransportError } from './network/transport.js';
import { canonical, id as parseId, parseJson, parseConversationRequest, parseConversationState, parseEventPage, parseMessage, parseProtocolError, retryAfterMilliseconds, ValidationError } from './protocol/wire.js';
import type { ConversationRequest, ConversationState, EventPage, Message } from './protocol/wire.js';

export interface OutboundRecord {
  connectionId: string; issuer: string; endpoint: string; id: string; target: string | null; request: ConversationRequest; fingerprint: string;
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
  constructor(readonly code: string, readonly status?: number, readonly retryAfterMs?: number, readonly scope?: string, readonly conversationId?: string, readonly extension?: string) { super(`Conversation ${code}`); this.name = 'ConversationError'; }
}
export interface ConversationClientOptions {
  authorizedRequest(request: Request): Promise<Response>;
  endpoint: string; connectionId: string; issuer: string;
  store: ConversationStore;
  clock: { now(): number };
  newId?: () => string; sleep?: (ms: number) => Promise<void>; random?: () => number;
  /** Optional safe UI hook supplied by the single authentication lifecycle. */
  authorization?: (connectionId: string, scopes: string[]) => Promise<unknown>;
  maxAttempts?: number; baseDelayMs?: number; maxDelayMs?: number; maxPages?: number;
}
export interface ReadOptions extends ReadParams { consumer?: string; signal?: AbortSignal }
export interface WatchOptions extends ReadOptions { lastEventId?: string; maxReconnects?: number; onPartial?: (value: { messageId: string; text: string } | null) => void; onHistoryGap?: () => Promise<boolean> | boolean }
export interface WatchedEvent { event: ConversationEvent; ack(): Promise<void> }
export type OutboundInput = Omit<Message, 'id'> & { id?: string };

// A definite rejection will not change on retry; anything else (auth, 408, 429, 5xx) leaves the operation retryable.
const definite = (status: number) => status >= 400 && status < 500 && ![401, 403, 408, 429].includes(status);

export function createConversationClient(options: ConversationClientOptions) {
  const { authorizedRequest, store, clock, connectionId, issuer } = options;
  const endpoint = secureUrl(options.endpoint).href;
  const newId = options.newId ?? (() => `msg_${Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url')}`); // 128 random bits
  const random = options.random ?? Math.random;
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms)));
  const maxAttempts = options.maxAttempts ?? 4, baseDelayMs = options.baseDelayMs ?? 250, maxDelayMs = options.maxDelayMs ?? 60000, maxPages = options.maxPages ?? 1000;
  const key = { connectionId, issuer, endpoint };
  // Validated IDs only: '.' and '..' survive encodeURIComponent and would escape the endpoint.
  const conversationUrl = (id: string, tail: string) => { const url = new URL(endpoint); url.pathname = `${url.pathname.replace(/\/+$/, '')}/${parseId(id, 'conversation_id')}/${tail}`; return url.href; };

  // Idempotent by construction: callers reuse the same message ID, so retrying transport failures, 429 and 5xx is safe.
  // Auth failures (including a rate-limited token renewal and its retryAfterMs) are not ours to retry and propagate unchanged.
  async function call(make: () => Request): Promise<Response> {
    for (let attempt = 1; ; attempt++) {
      let response: Response | undefined;
      try { response = await authorizedRequest(make()); } catch (error) { // A renewal's lost connection is an AuthFailure('transport_error'); it is as retryable as a lost request.
        if (!(error instanceof TransportError || (error as { code?: unknown })?.code === 'transport_error')) throw error; if (attempt >= maxAttempts) throw new ConversationError('network_error'); }
      let delay = Math.min(maxDelayMs, random() * baseDelayMs * 2 ** (attempt - 1)); // full jitter
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
    const challenge = dpopChallenge(response.headers.get('www-authenticate'));
    let code = '', scope = challenge?.scope, conversationId: string | undefined, extension: string | undefined;
    try { const body = parseProtocolError(parseJson(await response.text())); code = body.error; extension = body.extension ?? (challenge as { extension?: string } | undefined)?.extension; if (typeof body.scope === 'string') scope = body.scope; if (code === 'direct_conversation_open') conversationId = body.conversation_id; } catch { /* non-protocol body */ }
    if (!knownCodes.has(code)) {
      // Token errors (spec 6) arrive in WWW-Authenticate: DPoP error="...", scope="...".
      const challenge = dpopChallenge(response.headers.get('www-authenticate'));
      code = challenge?.error ?? '';
      scope ??= challenge?.scope;
    }
    if (!knownCodes.has(code)) code = 'http_error';
    return new ConversationError(code, response.status, retryAfterMilliseconds(response.headers.get('retry-after'), clock.now()), scope, conversationId, extension);
  }

  // Pages handed to a consumer in this process; the checkpoint moves only when one of them is acked.
  const delivered = new WeakMap<EventPage, { conversationId: string; consumer: string; chain: (string | undefined)[] }>();
  async function checkpoint(conversationId: string, consumer: string): Promise<string | undefined> {
    parseId(consumer, 'consumer');
    return store.getCheckpoint(key, conversationId, consumer);
  }

  async function dispatch(id: string): Promise<ConversationState> {
    parseId(id, 'message.id');
    const record = await store.getOutbound(key, id);
    if (!record) throw new ConversationError('unknown_operation');
    if (record.endpoint !== endpoint) throw new ConversationError('invalid_target');
    if (record.phase === 'accepted') return record.response!;
    if (record.phase === 'rejected') throw new ConversationError(record.error!.code, record.error!.status, undefined, undefined, record.error!.conversationId);
    const url = new URL(record.target === null ? endpoint : conversationUrl(record.target, 'messages'));
    if (record.read?.cursor !== undefined) url.searchParams.set('cursor', record.read.cursor);
    if (record.read?.wait !== undefined) url.searchParams.set('wait', String(record.read.wait));
    const response = await call(() => new Request(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(record.request) }));
    if (response.status >= 200 && response.status < 300) {
      let state: ConversationState | EventPage;
      try {
        const body = parseJson(await response.text());
        // A 2xx means accepted; a company that ignores wait answers with a plain state.
        state = body && typeof body === 'object' && ['events', 'cursor', 'has_more'].some(key => key in body) ? parseEventPage(body, record.read?.cursor) : parseConversationState(body);
      } catch { throw new ConversationError('invalid_response', response.status); }
      await store.settleOutbound(key, id, { phase: 'accepted', response: state });
      return state;
    }
    const error = await failure(response);
    // direct_conversation_open lasts only until the Direct Conversation closes (spec 7.10), so the same message stays retryable.
    if (definite(response.status) && error.code !== 'direct_conversation_open') await store.settleOutbound(key, id, { phase: 'rejected', error: { code: error.code, status: response.status, ...(error.conversationId === undefined ? {} : { conversationId: error.conversationId }) } });
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
    const existing = await store.prepareOutbound(key, { connectionId, issuer, endpoint, id: message.id, target, request, fingerprint, phase: 'pending', ...(read.wait === undefined && read.cursor === undefined ? {} : { read: { ...(read.wait === undefined ? {} : { wait: read.wait }), ...(read.cursor === undefined ? {} : { cursor: read.cursor }) } }) });
    if (existing.fingerprint !== fingerprint || existing.endpoint !== endpoint) throw new ConversationError('message_id_conflict');
    return { ...(await dispatch(message.id)), messageId: message.id };
  }

  async function simplePost(conversationId: string, tail: 'handoff' | 'close'): Promise<ConversationState> {
    parseId(conversationId, 'conversation_id');
    const response = await call(() => new Request(conversationUrl(conversationId, tail), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }));
    if (!response.ok) throw await failure(response);
    try { return parseConversationState(parseJson(await response.text())); } catch { throw new ConversationError('invalid_response', response.status); }
  }

  const client = {
    async authorization(event: ConversationEvent): Promise<unknown> {
      if (event.type !== 'authorization' || !options.authorization) throw new ConversationError('authorization_unavailable');
      return options.authorization(connectionId,typeof event.scope === 'string' ? event.scope.split(' ').filter(Boolean) : []);
    },
    async *watch(conversationId: string, opts: WatchOptions = {}): AsyncGenerator<WatchedEvent> {
      parseId(conversationId,'conversation_id');
      if(opts.consumer !== undefined && opts.cursor !== undefined)throw new ConversationError('invalid_request');
      let cursor = opts.lastEventId ?? (opts.consumer === undefined ? opts.cursor : await checkpoint(conversationId,opts.consumer));
      let reconnects=0, attempts=0;
      const maxReconnects=opts.maxReconnects ?? 4;
      if(!Number.isSafeInteger(maxReconnects)||maxReconnects<0)throw new ConversationError('invalid_request');
      const seen = new Set<string>(); // Bounded per watch; durable consumers ack explicitly.
      const eventAck = (event: ConversationEvent, previous: string | undefined): WatchedEvent => ({event, async ack() { if(opts.consumer!==undefined) await store.advanceCheckpoint(key,{connectionId,issuer,conversationId,name:opts.consumer,cursor:event.id},[previous]); }});
      for (;;) {
        opts.signal?.throwIfAborted();
        const url=new URL(conversationUrl(conversationId,'events')); if(opts.cursor!==undefined)url.searchParams.set('cursor',opts.cursor);
        const headers=new Headers({accept:'text/event-stream'}); if(cursor!==undefined)headers.set('last-event-id',cursor);
        let response: Response;
        try { response=await authorizedRequest(new Request(url,{headers,signal:opts.signal})); }
        catch(error){opts.onPartial?.(null);opts.signal?.throwIfAborted();if(!(error instanceof TransportError)||reconnects++>=maxReconnects)throw error;await sleep(Math.min(maxDelayMs,baseDelayMs*2**attempts++));continue;}
        if(!response.ok){const error=await failure(response);if(error.code==='cursor_expired'&&await opts.onHistoryGap?.()){cursor=undefined;opts.cursor=undefined;seen.clear();if(opts.consumer!==undefined)await client.resetConsumer(conversationId,opts.consumer);continue;}throw error;}
        let closed=false;
        try {
          if(response.headers.get('content-type')?.split(';')[0].trim()==='text/event-stream') {
            if(!response.body)throw new ConversationError('invalid_response');
            let partialBytes=0;
            for await(const frame of parseEventStream(response.body,{signal:opts.signal})){
              if(frame.kind==='delta'){partialBytes+=Buffer.byteLength(frame.text);if(partialBytes>1048576)throw new ConversationError('body_limit');opts.onPartial?.({messageId:frame.messageId,text:frame.text});continue;}
              const event=frame.event,previous=cursor;
              if(!seen.has(event.id)){if(seen.size>=10000)throw new ConversationError('too_many_events');seen.add(event.id);if(event.type==='message')opts.onPartial?.(null);yield eventAck(event,previous);}
              cursor=event.id;closed=event.type==='state'&&event.status==='closed';
            }
          } else {
            const page=parseEventPage(parseJson(await response.text()),cursor);
            for(const event of page.events){const previous=cursor;if(!seen.has(event.id)){if(seen.size>=10000)throw new ConversationError('too_many_events');seen.add(event.id);yield eventAck(event,previous);}cursor=event.id;}
            closed=page.status==='closed';
          }
        } catch(error) { opts.signal?.throwIfAborted(); if(error instanceof ValidationError || error instanceof ConversationError)throw error; } finally { opts.onPartial?.(null); await response.body?.cancel().catch(()=>{}); }
        if(closed||reconnects++>=maxReconnects)return;
        opts.signal?.throwIfAborted(); await sleep(Math.min(maxDelayMs,baseDelayMs*2**attempts++));
      }
    },
    start: (message: OutboundInput, opts: ReadParams & { parentConversationId?: string } = {}) => submit(message, null, opts, opts.parentConversationId),
    send: (conversationId: string, message: OutboundInput, opts: ReadParams = {}) => submit(message, conversationId, opts),
    /** Re-dispatch a pending outbound operation with its original ID and content. */
    retry: dispatch,
    async operation(messageId: string): Promise<OutboundRecord | undefined> { return store.getOutbound(key, messageId); },
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
      const response = await call(() => new Request(url, { method: 'GET', signal: opts.signal }));
      if (!response.ok) throw await failure(response); // cursor_expired (410) is the explicit history gap: see resetConsumer
      let page: EventPage;
      try { page = parseEventPage(parseJson(await response.text()), cursor); } catch { throw new ConversationError('invalid_response', response.status); }
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
      await store.advanceCheckpoint(key, { connectionId, issuer, conversationId, name: consumer, cursor }, from.chain);
    },
    /** After cursor_expired: forget the checkpoint so the consumer rereads retained history from the start (dedupe by event ID; missing events were not processed). */
    async resetConsumer(conversationId: string, consumer: string): Promise<void> {
      parseId(conversationId, 'conversation_id'); parseId(consumer, 'consumer');
      await store.resetCheckpoint(key, conversationId, consumer);
    },
  };
  return client;
}
