import {ValidationError} from '../dist/protocol/wire.js';
import { expectValue } from '../test-support/assertions.mjs';
import type { ConversationStore } from '../dist/conversation-store.js';
import type { ConversationClientOptions, ConversationClientState, OutboundRecord } from '../dist/conversation.js';
import type { ConversationState, EventPage, Message } from '../dist/protocol/wire.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createConversationClient, initialConversationClientState, ConversationError } from '../dist/conversation.js';
import { TransportError } from '../dist/network/transport.js';

const EP = 'https://api.example.com/poppy/conversations';
const json = (body:unknown, status = 200, headers:Record<string,string> = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
// Strict-JSON store check (INTERFACES v1.1): undefined values are rejected, as a SQLite/JSON store would.
const assertJson = (value:unknown, path = '$') => {
  if (value === undefined) throw new TypeError(`${path}: unsupported undefined`);
  if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) assertJson(v, `${path}.${k}`);
};
const memoryStore = (): ConversationStore & {read():Promise<ConversationClientState>;transaction<T>(change:(draft:ConversationClientState)=>T):Promise<T>} => {
  let state = initialConversationClientState();
  return {
    read: async () => structuredClone(state),
    async getOutbound(key,id) { return structuredClone(state.outbound.find(r => r.connectionId === key.connectionId && r.issuer === key.issuer && r.id === id)); },
    async prepareOutbound(key, record) { const old = await this.getOutbound(key, record.id); if (old) return old; state.outbound.push(structuredClone(record)); return structuredClone(record); },
    async settleOutbound(key, id, result) { const row = state.outbound.find(r => r.connectionId === key.connectionId && r.issuer === key.issuer && r.id === id); if (expectValue(row).phase === 'pending') Object.assign(expectValue(row), structuredClone(result)); },
    async getCheckpoint(key, conversationId, name) { return (state.consumers ?? []).find(r => r.connectionId === key.connectionId && r.issuer === key.issuer && r.conversationId === conversationId && r.name === name)?.cursor; },
    async advanceCheckpoint(key,row,from) { state.consumers ??= []; const old = state.consumers.find(r => r.connectionId === key.connectionId && r.issuer === key.issuer && r.conversationId === row.conversationId && r.name === row.name); if (from.includes(old?.cursor)) { if (old) expectValue(old).cursor = row.cursor; else state.consumers.push(structuredClone(row)); } },
    async resetCheckpoint(key,conversationId,name) { state.consumers = (state.consumers ?? []).filter(r => !(r.connectionId === key.connectionId && r.issuer === key.issuer && r.conversationId === conversationId && r.name === name)); },
    transaction: async <T,>(change:(draft:ConversationClientState)=>T) => { const draft = structuredClone(state); const result = change(draft); assertJson(draft); state = draft; return structuredClone(result); },
  };
};
const sorted = (value:unknown):unknown => Array.isArray(value) ? value.map(sorted) : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>[k,sorted(v)])) : value;

// Independently written Poppy company fixture (spec 7.2-7.13), with fault hooks.
type PeerEvent = {id:string;created_at:string;type:string;[key:string]:unknown};
type PeerConversation = {events:PeerEvent[]};
function company() {
  const byMessage = new Map<string,{key:string;target:string|null;state?:ConversationState;status?:number}>(); // message id -> { body, conversation, status }
  const conversations = new Map<string,PeerConversation>(); // id -> { events: [] }
  const log: string[] = [];
  const hooks:{dropResponses:number;failures:Response[]} = { dropResponses: 0, failures: [] };
  let n = 0;
  const addEvent = (conv:PeerConversation|undefined,event:{type:string;[key:string]:unknown}) => expectValue(conv).events.push({ id: `evt_${++n}`, created_at: '2026-10-19T10:00:00Z', ...event });
  async function handle(request:Request):Promise<Response> {
    const url = new URL(request.url);
    log.push(`${request.method} ${url.pathname}${url.search}`);
    if (hooks.failures.length) { const f = hooks.failures.shift(); return expectValue(f); }
    const path = url.pathname.replace('/poppy/conversations', '');
    if (request.method === 'POST' && (path === '' || path.endsWith('/messages'))) {
      const body = await request.json();
      const id = body.message.id;
      const target = path === '' ? null : path.split('/')[1];
      const key = JSON.stringify(sorted(body));
      let entry = byMessage.get(id);
      if (entry && (entry.key !== key || entry.target !== target)) return json({ error: 'message_id_conflict' }, 409);
      if (!entry) {
        let conversation = target;
        if (target === null) { conversation = `cnv_${conversations.size + 1}`; conversations.set(conversation, { events: [] }); }
        else if (!conversations.has(target)) return json({ error: 'conversation_not_found' }, 404);
        addEvent(conversations.get(expectValue(conversation)), { type: 'message', message: { ...body.message, role: 'user' } });
        entry = { key, target, state: { conversation_id: expectValue(conversation), status: 'working', responder: 'agent' }, status: target === null ? 201 : 202 };
        byMessage.set(id, expectValue(entry));
      }
      if (hooks.dropResponses > 0) { hooks.dropResponses--; throw new TransportError('network_error'); }
      return json(expectValue(entry).state, expectValue(entry).status);
    }
    const events = /^\/([^/]+)\/events$/.exec(path);
    if (request.method === 'GET' && events) {
      const conv = conversations.get(events[1]);
      if (!conv) return json({ error: 'conversation_not_found' }, 404);
      const cursor = url.searchParams.get('cursor');
      let from = 0;
      if (cursor === 'evt_gone') return json({ error: 'cursor_expired' }, 410);
      if (cursor) { const i = conv.events.findIndex((e: { id: string; } ) => e.id === cursor); if (i < 0) return json({ error: 'invalid_cursor' }, 400); from = i + 1; }
      const page = conv.events.slice(from, from + 2);
      return json({ conversation_id: events[1], events: page, cursor: page.at(-1)?.id ?? cursor, has_more: from + 2 < conv.events.length, status: 'idle', responder: 'agent' });
    }
    return json({ error: 'invalid_request' }, 400);
  }
  return { handle, log, hooks, conversations, addEvent, byMessage };
}

function setup(overrides:Partial<ConversationClientOptions>&{keepCompleted?:number} = {}) {
  const server = company();
  const sleeps: number[] = [];
  const store = memoryStore();
  const client = createConversationClient({
    authorizedRequest: request => server.handle(request), endpoint: EP, connectionId: 'conn1', issuer: 'https://issuer.example.com',
    store, clock: { now: () => Date.parse('2026-10-19T10:00:00Z') }, sleep: async ms => { sleeps.push(ms); },
    newId: (() => { let i = 0; return () => `msg_gen${++i}`; })(), ...overrides,
  });
  return { server, sleeps, store, client };
}
const msg:Omit<Message,'id'> = { sender: 'agent', text: 'hello' };

test('lost first POST response then retry reuses the ID and the company dedupes', async () => {
  const { server, client } = setup({ maxAttempts: 1 });
  server.hooks.dropResponses = 1;
  await assert.rejects(client.start({ ...msg, id: 'msg_a' }), e => e instanceof ConversationError && e.code === 'network_error');
  const pending = await client.operation('msg_a');
  assert.equal(expectValue(pending).phase, 'pending'); // persisted before send
  assert.equal(expectValue(pending).request.message.text, 'hello');
  const state = await client.retry('msg_a');
  assert.equal(state.conversation_id, 'cnv_1');
  assert.equal(server.conversations.size, 1);
  assert.equal(expectValue(server.conversations.get('cnv_1')).events.length, 1);
  assert.equal(expectValue((await client.operation('msg_a'))).phase, 'accepted');
  // Further calls are served from the saved result without another POST.
  const posts = server.log.length;
  assert.equal((await client.start({ ...msg, id: 'msg_a' })).conversation_id, 'cnv_1');
  assert.equal(server.log.length, posts);
});

test('automatic retries reuse the ID after a transient network error', async () => {
  const { server, client } = setup();
  server.hooks.dropResponses = 2;
  const state = await client.start({ ...msg, id: 'msg_b' });
  assert.equal(state.conversation_id, 'cnv_1');
  assert.equal(expectValue(server.conversations.get('cnv_1')).events.length, 1);
});

test('outbound content is persisted before the first dispatch', async () => {
  let seen!:OutboundRecord[];
  const { client, store } = setup({ authorizedRequest: async () => { seen = (await store.read()).outbound; throw new Error('down'); }, maxAttempts: 1 });
  await assert.rejects(client.send('cnv_9', { ...msg, id: 'msg_c', data: { x: 1 } }));
  assert.equal(expectValue(seen)[0].id, 'msg_c');
  assert.equal(expectValue(seen)[0].target, 'cnv_9');
  assert.deepEqual(expectValue(seen)[0].request.message.data, { x: 1 });
});

test('same ID with different content or target is a local conflict; key order is ignored', async () => {
  const { client, server } = setup();
  await client.start({ id: 'msg_d', sender: 'agent', data: { a: 1, b: [1, 2] }, text: 't' });
  await client.start({ id: 'msg_d', sender: 'agent', text: 't', data: { b: [1, 2], a: 1 } });
  await assert.rejects(client.start({ id: 'msg_d', sender: 'agent', text: 't', data: { a: 1, b: [2, 1] } }), e => e instanceof ConversationError && e.code === 'message_id_conflict');
  await assert.rejects(client.start({ id: 'msg_d', sender: 'agent', text: 't ', data: { a: 1, b: [1, 2] } }), e => e instanceof ConversationError && e.code === 'message_id_conflict');
  await assert.rejects(client.send('cnv_1', { id: 'msg_d', sender: 'agent', text: 't', data: { a: 1, b: [1, 2] } }), e => e instanceof ConversationError && e.code === 'message_id_conflict');
  assert.equal(server.conversations.size, 1);
});

test('unknown extension members are part of the identity', async () => {
  const { client } = setup();
  await client.start({ id: 'msg_e', sender: 'agent', text: 'x', ext: { v: 1 } });
  await assert.rejects(client.start({ id: 'msg_e', sender: 'agent', text: 'x', ext: { v: 2 } }), e => e instanceof ConversationError && e.code === 'message_id_conflict');
});

test('rejections: definite 4xx is recorded and not resent; 5xx stays retryable', async () => {
  const { client, server } = setup({ maxAttempts: 1 });
  await assert.rejects(client.send('cnv_missing', { ...msg, id: 'msg_f' }), e => e instanceof ConversationError && e.code === 'conversation_not_found' && e.status === 404);
  const posts = server.log.length;
  assert.equal(expectValue((await client.operation('msg_f'))).phase, 'rejected');
  await assert.rejects(client.retry('msg_f'), e => e instanceof ConversationError && e.code === 'conversation_not_found');
  assert.equal(server.log.length, posts);
  server.hooks.failures.push(json({ error: 'server_error' }, 503));
  await assert.rejects(client.start({ ...msg, id: 'msg_g' }), e => e instanceof ConversationError && e.status === 503);
  assert.equal(expectValue((await client.operation('msg_g'))).phase, 'pending');
  assert.equal((await client.retry('msg_g')).conversation_id, 'cnv_1');
  await assert.rejects(client.retry('msg_unknown'), e => e instanceof ConversationError && e.code === 'unknown_operation');
});

test('company message_id_conflict is definite', async () => {
  const { client, server } = setup();
  server.byMessage.set('msg_h', { key: 'other', target: null });
  await assert.rejects(client.start({ ...msg, id: 'msg_h' }), e => e instanceof ConversationError && e.code === 'message_id_conflict' && e.status === 409);
  assert.equal(expectValue((await client.operation('msg_h'))).phase, 'rejected');
});

test('Retry-After seconds and HTTP-date are respected, then the same ID is resent', async () => {
  const { client, server, sleeps } = setup();
  server.hooks.failures.push(json({ error: 'rate_limited' }, 429, { 'retry-after': '7' }));
  server.hooks.failures.push(json({ error: 'rate_limited' }, 429, { 'retry-after': 'Mon, 19 Oct 2026 10:00:03 GMT' }));
  await client.start({ ...msg, id: 'msg_i' });
  assert.deepEqual(sleeps, [7000, 3000]);
  assert.equal(server.conversations.size, 1);
});

test('Retry-After beyond the cap or exhausted attempts surfaces the delay', async () => {
  const { client, server, sleeps } = setup();
  server.hooks.failures.push(json({ error: 'rate_limited' }, 429, { 'retry-after': '3600' }));
  await assert.rejects(client.start({ ...msg, id: 'msg_j' }), e => e instanceof ConversationError && e.code === 'rate_limited' && e.retryAfterMs === 3600000);
  assert.deepEqual(sleeps, []);
  assert.equal(expectValue((await client.operation('msg_j'))).phase, 'pending');
});

test('invalid input fails before anything is persisted', async () => {
  const { client, store } = setup();
  await assert.rejects(client.start({ id: 'bad id!', sender: 'agent', text: 'x' }));
  await assert.rejects(client.start({ id: 'msg_k', sender: 'agent' }));
  assert.equal((await store.read()).outbound.length, 0);
});

test('malformed success body leaves the operation pending', async () => {
  const { client, server } = setup({ maxAttempts: 1 });
  server.hooks.failures.push(json({ nope: true }, 201));
  await assert.rejects(client.start({ ...msg, id: 'msg_l' }), e => e instanceof ConversationError && e.code === 'invalid_response');
  assert.equal(expectValue((await client.operation('msg_l'))).phase, 'pending');
});

test('read drains has_more pages whole and keeps unknown events raw', async () => {
  const { client, server } = setup();
  const { conversation_id } = await client.start({ ...msg, id: 'msg_m' });
  const conv = server.conversations.get(conversation_id);
  server.addEvent(conv, { type: 'x-vendor/new', payload: { secret: [1, 2, 3] } });
  server.addEvent(conv, { type: 'state', status: 'idle', responder: 'agent' });
  const pages = await client.drain(conversation_id);
  assert.equal(pages.length, 2);
  assert.deepEqual(pages.map(p => p.has_more), [true, false]);
  const events = pages.flatMap(p => p.events);
  assert.equal(events.length, 3);
  assert.deepEqual(events[1], { id: events[1].id, type: 'x-vendor/new', created_at: '2026-10-19T10:00:00Z', payload: { secret: [1, 2, 3] } });
  assert.ok(server.log.some(l => l.includes('cursor=' + pages[0].cursor)));
});

test('history gap and invalid cursor are explicit errors', async () => {
  const { client } = setup();
  const { conversation_id } = await client.start({ ...msg, id: 'msg_o' });
  await assert.rejects(client.read(conversation_id, { cursor: 'evt_gone' }), e => e instanceof ConversationError && e.code === 'cursor_expired' && e.status === 410);
  await assert.rejects(client.read(conversation_id, { cursor: 'evt_zzz' }), e => e instanceof ConversationError && e.code === 'invalid_cursor');
  await assert.rejects(client.read('cnv_nope'), e => e instanceof ConversationError && e.code === 'conversation_not_found');
});

test('read rejects an inconsistent page and retries 429 with Retry-After', async () => {
  const { client, server, sleeps } = setup();
  const { conversation_id } = await client.start({ ...msg, id: 'msg_p' });
  server.hooks.failures.push(json({ conversation_id, events: [], cursor: null, has_more: true, status: 'idle', responder: 'agent' }));
  await assert.rejects(client.read(conversation_id), e => e instanceof ConversationError && e.code === 'invalid_response');
  server.hooks.failures.push(json({ error: 'rate_limited' }, 429, { 'retry-after': '2' }));
  const page = await client.read(conversation_id, { wait: 5 });
  assert.deepEqual(sleeps, [2000]);
  assert.equal(page.events.length, 1);
  assert.ok(expectValue(server.log.at(-1)).endsWith('wait=5'));
});

test('handoff and close return state; closed conversation error is surfaced', async () => {
  const { client, server } = setup();
  const { conversation_id } = await client.start({ ...msg, id: 'msg_q' });
  server.hooks.failures.push(json({ conversation_id, status: 'queued', responder: 'agent' }, 202));
  assert.equal((await client.handoff(conversation_id)).status, 'queued');
  server.hooks.failures.push(json({ error: 'conversation_closed' }, 409));
  await assert.rejects(client.close(conversation_id), e => e instanceof ConversationError && e.code === 'conversation_closed');
});

test('operations are scoped to connection and issuer', async () => {
  const shared = memoryStore();
  const a = setup({ store: shared });
  const b = setup({ store: shared, connectionId: 'conn2' });
  await a.client.start({ ...msg, id: 'msg_r' });
  assert.equal(await b.client.operation('msg_r'), undefined);
  await b.client.start({ ...msg, id: 'msg_r', text: 'different' }); // no cross-connection conflict
  assert.equal(b.server.conversations.size, 1);
});

test('conversation IDs are validated before anything is persisted or sent', async () => {
  const { client, server, store } = setup();
  for (const bad of ['..', '.', 'a/b', '', 'x'.repeat(257)]) {
    await assert.rejects(client.send(bad, { ...msg, id: 'msg_v' }), e => e instanceof ValidationError && e.field === 'conversation_id');
    await assert.rejects(client.read(bad), e => e instanceof ValidationError && e.field === 'conversation_id');
    await assert.rejects(client.handoff(bad), e => e instanceof ValidationError && e.field === 'conversation_id');
    await assert.rejects(client.close(bad), e => e instanceof ValidationError && e.field === 'conversation_id');
    await assert.rejects(client.start({ ...msg, id: 'msg_v' }, { parentConversationId: bad }), e => e instanceof ValidationError && e.field === 'parent_conversation_id');
  }
  await assert.rejects(client.retry('../x'));
  assert.equal(server.log.length, 0);
  assert.equal((await store.read()).outbound.length, 0);
});

test('drain fails on a has_more page that makes no progress, and caps the page count', async () => {
  const { client, server } = setup();
  const { conversation_id } = await client.start({ ...msg, id: 'msg_s' });
  const stuck = (cursor: string|null ) => json({ conversation_id, events: [], cursor, has_more: true, status: 'idle', responder: 'agent' });
  server.hooks.failures.push(stuck(null));
  await assert.rejects(client.drain(conversation_id), e => e instanceof ConversationError && e.code === 'invalid_response');
  const first = (await client.read(conversation_id)).cursor;
  server.hooks.failures.push(stuck(first));
  await assert.rejects(client.drain(conversation_id, { cursor: expectValue(first) }), e => e instanceof ConversationError && e.code === 'invalid_response');
  const { client: capped, server: s2 } = setup({ maxPages: 1 });
  const started = await capped.start({ ...msg, id: 'msg_t' });
  for (let i = 0; i < 3; i++) s2.addEvent(s2.conversations.get(started.conversation_id), { type: 'state', status: 'idle', responder: 'agent' });
  await assert.rejects(capped.drain(started.conversation_id), e => e instanceof ConversationError && e.code === 'too_many_pages');
});

test('token errors from WWW-Authenticate are exposed; unknown company codes become http_error', async () => {
  const { client, server } = setup({ maxAttempts: 1 });
  const challenge = (value:{status:number;header:string}) => new Response('', { status: value.status, headers: { 'www-authenticate': value.header } });
  server.hooks.failures.push(challenge({ status: 401, header: 'DPoP error="invalid_token"' }));
  await assert.rejects(client.read('cnv_1'), e => e instanceof ConversationError && e.code === 'invalid_token' && e.status === 401);
  server.hooks.failures.push(challenge({ status: 403, header: 'DPoP error="sign_in_required"' }));
  await assert.rejects(client.read('cnv_1'), e => e instanceof ConversationError && e.code === 'sign_in_required' && e.scope === undefined);
  server.hooks.failures.push(challenge({ status: 403, header: 'DPoP error="insufficient_scope", scope="orders:read orders:write"' }));
  await assert.rejects(client.read('cnv_1'), e => e instanceof ConversationError && e.code === 'insufficient_scope' && e.scope === 'orders:read orders:write');
  server.hooks.failures.push(json({ error: 'x'.repeat(5000) }, 400));
  await assert.rejects(client.read('cnv_1'), e => e instanceof ConversationError && e.code === 'http_error' && e.message.length < 60);
  server.hooks.failures.push(challenge({ status: 403, header: 'DPoP error="made_up"' }));
  await assert.rejects(client.read('cnv_1'), e => e instanceof ConversationError && e.code === 'http_error');
});

test('operations are scoped to issuer as well as connection', async () => {
  const shared = memoryStore();
  const a = setup({ store: shared });
  const b = setup({ store: shared, issuer: 'https://other.example.com' });
  await a.client.start({ ...msg, id: 'msg_u' });
  assert.equal(await b.client.operation('msg_u'), undefined);
  await b.client.start({ ...msg, id: 'msg_u', text: 'different' });
  assert.equal(b.server.conversations.size, 1);
});

test('dpopChallenge reads only the DPoP challenge and respects quoting and case', async () => {
  const { dpopChallenge } = await import('../dist/auth/challenge.js');
  assert.deepEqual(dpopChallenge('Bearer scope="openid", DPoP error="insufficient_scope", scope="orders:read orders:write"'), { error: 'insufficient_scope', scope: 'orders:read orders:write' });
  assert.deepEqual(dpopChallenge('Bearer error="invalid_token", DPoP error="use_dpop_nonce"'), { error: 'use_dpop_nonce' });
  assert.deepEqual(dpopChallenge('DPoP error="invalid_token", Bearer error="insufficient_scope", scope="x"'), { error: 'invalid_token' });
  assert.deepEqual(dpopChallenge('DPoP error_description="a, b error=\\"x\\"", error="invalid_token"'), { error: 'invalid_token' });
  assert.deepEqual(dpopChallenge('dpop Error="invalid_token", SCOPE=abc'), { error: 'invalid_token', scope: 'abc' });
  assert.equal(dpopChallenge('Bearer error="invalid_token"'), undefined);
  assert.equal(dpopChallenge(null), undefined);
  assert.deepEqual(dpopChallenge('!!!, ===, "unterminated'), undefined);
});

test('WWW-Authenticate with several schemes and garbage map to the right code', async () => {
  const { client, server } = setup({ maxAttempts: 1 });
  const with_ = (header: string ) => new Response('', { status: 401, headers: { 'www-authenticate': header } });
  server.hooks.failures.push(with_('Bearer scope="openid", DPoP error="insufficient_scope", scope="orders:read orders:write"'));
  await assert.rejects(client.read('cnv_1'), e => e instanceof ConversationError && e.code === 'insufficient_scope' && e.scope === 'orders:read orders:write');
  server.hooks.failures.push(with_('Bearer error="invalid_token", DPoP error="use_dpop_nonce"'));
  await assert.rejects(client.read('cnv_1'), e => e instanceof ConversationError && e.code === 'use_dpop_nonce');
  server.hooks.failures.push(with_('DPoP Error="invalid_token", error_description="x, error=\\"sign_in_required\\""'));
  await assert.rejects(client.read('cnv_1'), e => e instanceof ConversationError && e.code === 'invalid_token');
  server.hooks.failures.push(with_('@@@ ,,, "'));
  await assert.rejects(client.read('cnv_1'), e => e instanceof ConversationError && e.code === 'http_error');
});

// ---- J16: consumers, checkpoints, POST wait, pruning ----
const seed = async (client:ReturnType<typeof createConversationClient>,server:ReturnType<typeof company>,n:number) => {
  const { conversation_id } = await client.start({ ...msg, id: 'msg_seed' });
  for (let i = 1; i < n; i++) server.addEvent(server.conversations.get(conversation_id), { type: 'state', status: 'idle', responder: 'agent' });
  return conversation_id;
};
const ids = (pages:EventPage[]) => pages.flatMap(p => p.events.map(e => e instanceof ConversationError && e.id));
const otherClient = (server:ReturnType<typeof company>,store:ConversationStore, connectionId = 'conn1') => createConversationClient({ authorizedRequest: r => server.handle(r), endpoint: EP, connectionId, issuer: 'https://issuer.example.com', store, clock: { now: () => 0 }, sleep: async () => {} });

test('retryAfter of a huge integer is Infinity and surfaces as the delay', async () => {
  const { client, server, sleeps } = setup();
  server.hooks.failures.push(json({ error: 'rate_limited' }, 429, { 'retry-after': '9'.repeat(30) }));
  await assert.rejects(client.start({ ...msg, id: 'msg_huge' }), e => e instanceof ConversationError && e.code === 'rate_limited' && e.retryAfterMs === Infinity);
  assert.deepEqual(sleeps, []);
});

test('consumer checkpoint moves only on ack; reads and drain never acknowledge', async () => {
  const { client, server, store } = setup();
  const cid = await seed(client, server, 3);
  const first = await client.read(cid, { consumer: 'worker' });
  assert.equal(first.events.length, 2);
  assert.deepEqual((await store.read()).consumers, []);
  const again = await client.read(cid, { consumer: 'worker' }); // redelivery, not skipping
  assert.deepEqual(ids([again]), ids([first]));
  const seen = ids(await client.drain(cid, { consumer: 'worker' }));
  assert.equal(seen.length, 3);
  assert.deepEqual((await store.read()).consumers, []);
  await client.ack(cid, 'worker', first);
  assert.equal((await store.read()).consumers[0].cursor, first.cursor);
  const next = await client.read(cid, { consumer: 'worker' });
  assert.deepEqual(ids([next]), [seen[2]]);
  assert.ok(expectValue(server.log.at(-1)).includes('cursor=' + first.cursor));
});

test('two reads before an ack: acking either delivered page works', async () => {
  const { client, server, store } = setup();
  const cid = await seed(client, server, 3);
  const a = await client.read(cid, { consumer: 'w' });
  const b = await client.read(cid, { consumer: 'w' });
  await client.ack(cid, 'w', a);
  await client.ack(cid, 'w', b);
  assert.equal((await store.read()).consumers[0].cursor, b.cursor);
});

test('ack refuses pages not delivered to that consumer; cursor with consumer is rejected', async () => {
  const { client, server, store } = setup();
  const cid = await seed(client, server, 3);
  const explicit = await client.read(cid);
  await assert.rejects(client.ack(cid, 'w', explicit), e => e instanceof ConversationError && e.code === 'invalid_request');
  const page = await client.read(cid, { consumer: 'w' });
  await assert.rejects(client.ack(cid, 'other', page), e => e instanceof ConversationError && e.code === 'invalid_request');
  await assert.rejects(client.ack(cid, 'w', { ...page }), e => e instanceof ConversationError && e.code === 'invalid_request');
  await assert.rejects(client.read(cid, { consumer: 'w', cursor: expectValue(page.cursor) }), e => e instanceof ConversationError && e.code === 'invalid_request');
  await assert.rejects(client.drain(cid, { consumer: 'w', cursor: expectValue(page.cursor) }), e => e instanceof ConversationError && e.code === 'invalid_request');
  await assert.rejects(client.read(cid, { consumer: 'bad name' }));
  assert.deepEqual((await store.read()).consumers, []);
});

test('crash before ack redelivers after restart; an ack survives restart', async () => {
  const { client, server, store } = setup();
  const cid = await seed(client, server, 3);
  const lost = await client.read(cid, { consumer: 'w' }); // process dies before ack
  const second = otherClient(server, store);
  const redelivered = await second.read(cid, { consumer: 'w' });
  assert.deepEqual(ids([redelivered]), ids([lost]));
  await second.ack(cid, 'w', redelivered);
  const next = await otherClient(server, store).read(cid, { consumer: 'w' });
  assert.equal(next.events.length, 1);
  assert.notEqual(next.events[0].id, ids([lost])[0]);
});

test('two consumers keep independent checkpoints, also per connection', async () => {
  const { client, server, store } = setup();
  const cid = await seed(client, server, 3);
  await client.ack(cid, 'a', await client.read(cid, { consumer: 'a' }));
  assert.equal((await client.read(cid, { consumer: 'b' })).events.length, 2);
  assert.equal((await client.read(cid, { consumer: 'a' })).events.length, 1);
  assert.equal((await otherClient(server, store, 'conn2').read(cid, { consumer: 'a' })).events.length, 2);
});

test('cursor_expired is explicit, then resetConsumer recovers from retained history', async () => {
  const { client, server, store } = setup();
  const cid = await seed(client, server, 3);
  await client.ack(cid, 'w', await client.read(cid, { consumer: 'w' }));
  await store.transaction((d: { consumers: { cursor: string; }[]; } ) => { d.consumers[0].cursor = 'evt_gone'; });
  await assert.rejects(client.read(cid, { consumer: 'w' }), e => e instanceof ConversationError && e.code === 'cursor_expired');
  await assert.rejects(client.read(cid, { consumer: 'w' }), e => e instanceof ConversationError && e.code === 'cursor_expired'); // never silently restarted
  await client.resetConsumer(cid, 'w');
  assert.deepEqual((await store.read()).consumers, []);
  assert.deepEqual(ids(await client.drain(cid, { consumer: 'w' })), ids(await client.drain(cid)));
});

test('narrow null cursor: accepted only for a first empty page, never sent, never acked', async () => {
  const { client, server, store } = setup();
  const empty = { conversation_id: 'cnv_1', events: [], cursor: null, has_more: false, status: 'idle', responder: 'agent' };
  server.hooks.failures.push(json(empty));
  const page = await client.read('cnv_1', { consumer: 'w' });
  await client.ack('cnv_1', 'w', page);
  assert.deepEqual((await store.read()).consumers, []);
  assert.ok(!expectValue(server.log.at(-1)).includes('cursor'));
  server.hooks.failures.push(json(empty));
  await assert.rejects(client.read('cnv_1', { cursor: 'evt_1' }), e => e instanceof ConversationError && e.code === 'invalid_response');
  server.hooks.failures.push(json({ ...empty, has_more: true }));
  await assert.rejects(client.read('cnv_1'), e => e instanceof ConversationError && e.code === 'invalid_response');
});

test('POST wait and cursor return a page receipt; a repeat with other parameters does not resend', async () => {
  const { client, server } = setup();
  const { conversation_id } = await client.start({ ...msg, id: 'msg_first' });
  const page = { conversation_id, events: [{ id: 'evt_9', type: 'state', created_at: '2026-10-19T10:00:00Z', status: 'idle', responder: 'agent' }], cursor: 'evt_9', has_more: false, status: 'idle', responder: 'agent' };
  server.hooks.failures.push(json(page, 202));
  const sent = await client.send(conversation_id, { ...msg, id: 'msg_w' }, { wait: 10, cursor: 'evt_1' });
  assert.deepEqual(sent.events, page.events);
  assert.ok(expectValue(server.log.at(-1)).endsWith('/messages?cursor=evt_1&wait=10'));
  const before = server.log.length;
  assert.deepEqual((await client.send(conversation_id, { ...msg, id: 'msg_w' }, { wait: 0 })).events, page.events);
  assert.equal(server.log.length, before);
  server.hooks.failures.push(json(page, 201));
  await client.start({ ...msg, id: 'msg_sw' }, { wait: 3 });
  assert.ok(expectValue(server.log.at(-1)).endsWith('/poppy/conversations?wait=3'));
});

test('POST wait: bad parameters and a malformed body are rejected', async () => {
  const { client, server } = setup();
  await assert.rejects(client.start({ ...msg, id: 'msg_n1' }, { wait: -1 }), e => e instanceof ConversationError && e.code === 'invalid_request');
  await assert.rejects(client.start({ ...msg, id: 'msg_n2' }, { wait: 1.5 }), e => e instanceof ConversationError && e.code === 'invalid_request');
  await assert.rejects(client.start({ ...msg, id: 'msg_n3' }, { cursor: 'a&b' }));
  assert.equal(server.log.length, 0);
  await assert.rejects(client.start({ ...msg, id: 'msg_n5' }, { cursor: 'evt_1' }), e => e instanceof ConversationError && e.code === 'invalid_request'); // cursor only alongside wait
  assert.equal(server.log.length, 0);
  assert.equal((await client.operation('msg_n5')), undefined);
  server.hooks.failures.push(json({ conversation_id: 'cnv_1', status: 'working' }, 201));
  await assert.rejects(client.start({ ...msg, id: 'msg_n4' }, { wait: 2 }), e => e instanceof ConversationError && e.code === 'invalid_response');
  assert.equal(expectValue((await client.operation('msg_n4'))).phase, 'pending');
});

test('a waited POST answered with a plain state is accepted, not stuck pending', async () => {
  const { client, server } = setup();
  server.hooks.failures.push(json({ conversation_id: 'cnv_1', status: 'working', responder: 'agent' }, 201));
  const r = await client.start({ ...msg, id: 'msg_st' }, { wait: 2 });
  assert.equal(r.conversation_id, 'cnv_1');
  assert.equal(expectValue((await client.operation('msg_st'))).phase, 'accepted');
});

test('stale acks cannot regress the checkpoint, across a drain chain or a reset', async () => {
  const { client, server, store } = setup();
  const cid = await seed(client, server, 3);
  const [p1, p2] = await client.drain(cid, { consumer: 'w' });
  await client.ack(cid, 'w', p2);
  await client.ack(cid, 'w', p1);
  assert.equal((await store.read()).consumers[0].cursor, p2.cursor);
  const pages = await client.drain(cid, { consumer: 'w' }); // from p2: one event
  const old = await client.read(cid, { consumer: 'w' });
  await client.resetConsumer(cid, 'w');
  await client.ack(cid, 'w', old);
  await client.ack(cid, 'w', pages[0]);
  assert.deepEqual((await store.read()).consumers, []);
});

test('an old v1 state without consumers works for read, ack and reset', async () => {
  const { client, server, store } = setup();
  const cid = await seed(client, server, 1);
  await store.transaction(d => { Reflect.deleteProperty(d,'consumers'); });
  const page = await client.read(cid, { consumer: 'w' });
  await client.ack(cid, 'w', page);
  assert.equal((await store.read()).consumers[0].cursor, page.cursor);
  await client.resetConsumer(cid, 'w');
  await store.transaction(d => { Reflect.deleteProperty(d,'consumers'); });
  await client.resetConsumer(cid, 'w');
});

test('direct_conversation_open surfaces the conversation ID and stays retryable until the Direct Conversation closes', async () => {
  const { client, server } = setup();
  const cid = await seed(client, server, 1);
  const open = () => json({ error: 'direct_conversation_open', conversation_id: 'cnv_direct' }, 409);
  server.hooks.failures.push(open());
  await assert.rejects(client.send(cid, { ...msg, id: 'msg_d1' }), e => e instanceof ConversationError && e.code === 'direct_conversation_open' && e.conversationId === 'cnv_direct');
  assert.equal(expectValue((await client.operation('msg_d1'))).phase, 'pending');
  server.hooks.failures.push(open());
  const sent = server.log.length;
  await assert.rejects(client.retry('msg_d1'), e => e instanceof ConversationError && e.code === 'direct_conversation_open' && e.conversationId === 'cnv_direct');
  assert.equal(server.log.length, sent + 1, 'the retry was sent, not answered from a stored rejection');
  // The Direct Conversation closed: the parent takes messages again (spec 7.10), with the same ID and content.
  const state = await client.retry('msg_d1');
  assert.equal(state.conversation_id, cid);
  assert.equal(expectValue((await client.operation('msg_d1'))).phase, 'accepted');
  assert.equal(expectValue(server.byMessage.get('msg_d1')).target, cid);
  server.hooks.failures.push(json({ error: 'direct_conversation_open', conversation_id: 'bad id' }, 409));
  await assert.rejects(client.handoff(cid), e => e instanceof ConversationError && e.code === 'http_error' && e.conversationId === undefined);
});

test('close success returns the closed state', async () => {
  const { client, server } = setup();
  const cid = await seed(client, server, 1);
  server.hooks.failures.push(json({ conversation_id: cid, status: 'closed', responder: 'agent' }));
  assert.equal((await client.close(cid)).status, 'closed');
  assert.ok(expectValue(server.log.at(-1)).startsWith('POST') && expectValue(server.log.at(-1)).endsWith(`/${cid}/close`));
});

test('outbound receipts remain available for later retries', async () => {
  const { client, server, store } = setup({ keepCompleted: 2 });
  server.hooks.failures.push(json({ error: 'x' }, 500), json({ error: 'x' }, 500), json({ error: 'x' }, 500), json({ error: 'x' }, 500));
  await assert.rejects(client.start({ ...msg, id: 'msg_pend' })); // stays pending
  for (const i of [1, 2, 3, 4]) await client.start({ ...msg, id: `msg_p${i}` });
  // Keep receipts until an explicit retention policy can preserve retry identity.
  assert.deepEqual((await store.read()).outbound.map(r => r.id), ['msg_pend', 'msg_p1', 'msg_p2', 'msg_p3', 'msg_p4']);
  const before = server.byMessage.size;
  await client.start({ ...msg, id: 'msg_p4' }); // recent retry is still deduped locally
  assert.equal(server.byMessage.size, before);
});

test('a definite rejection persists as strict JSON, is rejected, and is not resent', async () => {
  const { server, client, store } = setup();
  server.hooks.failures.push(json({ error: 'conversation_closed' }, 409));
  await assert.rejects(client.send('cnv_1', { ...msg, id: 'msg_closed' }), e => e instanceof ConversationError && e.code === 'conversation_closed' && e.status === 409);
  assert.equal((await store.read()).outbound[0].phase, 'rejected');
  const before = server.log.length;
  await assert.rejects(client.retry('msg_closed'), e => e instanceof ConversationError && e.code === 'conversation_closed');
  assert.equal(server.log.length, before);
});

test('start persists only wait and cursor as read, never parentConversationId or undefined', async () => {
  const { client, store } = setup();
  await client.start({ ...msg, id: 'msg_rd' }, { wait: 0, parentConversationId: undefined });
  assert.deepEqual((await store.read()).outbound[0].read, { wait: 0 });
  await client.start({ ...msg, id: 'msg_rd2' }, { wait: 0, parentConversationId: 'cnv_parent' });
  assert.deepEqual((await store.read()).outbound[1].read, { wait: 0 });
});

test('only transport failures are retried; auth failures propagate unchanged, with their retryAfterMs', async () => {
  for (const error of [Object.assign(new Error('rate'), { retryAfterMs: 30000 }), new TypeError('disconnected')]) {
    let calls = 0;
    const { client } = setup({ authorizedRequest: async () => { calls++; throw error; } });
    await assert.rejects(client.start({ ...msg, id: 'msg_z' }), thrown => thrown === error);
    assert.equal(calls, 1);
  }
  let calls = 0;
  const { client } = setup({ authorizedRequest: async () => { calls++; throw new TransportError('timeout'); }, maxAttempts: 3 });
  await assert.rejects(client.start({ ...msg, id: 'msg_y' }), e => e instanceof ConversationError && e.code === 'network_error');
  assert.equal(calls, 3);
});

test('backoff is capped full jitter with injectable randomness', async () => {
  const delays:number[] = [];
  const { client } = setup({ authorizedRequest: async () => new Response('', { status: 503 }), sleep: async ms => { delays.push(ms); }, random: () => 0.5, baseDelayMs: 1000, maxDelayMs: 1500, maxAttempts: 4 });
  await assert.rejects(client.start({ ...msg, id: 'msg_x' }), e => e instanceof ConversationError && e.status === 503);
  assert.deepEqual(delays, [500, 1000, 1500]); // 0.5 * 1000 * 2^(n-1), capped at 1500
});

test('default message IDs carry 128 random bits as base64url and are unique', async () => {
  const ids = new Set<string>();
  const { client } = setup({ newId: undefined });
  for (let i = 0; i < 3; i++) {const id=(await client.start({sender:'agent',text:`t${i}`})).messageId;assert.ok(typeof id==='string');ids.add(id);}
  assert.equal(ids.size, 3);
  for (const id of ids) assert.match(id, /^msg_[A-Za-z0-9_-]{22}$/);
});

test('a duplicate member name in a response body is an invalid response', async () => {
  const { client } = setup({ authorizedRequest: async () => new Response('{"conversation_id":"cnv_1","conversation_id":"cnv_2","status":"working","responder":"agent"}', { status: 201 }) });
  await assert.rejects(client.start({ ...msg, id: 'msg_w' }), e => e instanceof ConversationError && e.code === 'invalid_response');
});

test('a renewal that lost its connection (AuthFailure transport_error) is retried like a transport failure', async () => {
  let calls = 0;
  const { client, server } = setup({ authorizedRequest: async request => { if (++calls < 3) throw Object.assign(new Error('Auth transport_error'), { code: 'transport_error' }); return server.handle(request); } });
  assert.equal((await client.start({ ...msg, id: 'msg_v' })).conversation_id, 'cnv_1');
  assert.equal(calls, 3);
});

test('malformed waited page cannot fall back to a valid state and JSON errors retain header scope',async()=>{
  const {client,server}=setup();
  server.hooks.failures.push(json({conversation_id:'c1',status:'idle',responder:'agent',events:'bad',cursor:null,has_more:false},201));
  await assert.rejects(client.start({id:'broken_wait',sender:'agent',text:'x'},{wait:1}),{code:'invalid_response'});
  server.hooks.failures.push(json({error:'insufficient_scope'},403,{'www-authenticate':'DPoP error="insufficient_scope", scope="custom:read"'}));
  await assert.rejects(client.read('c1'),{code:'insufficient_scope',scope:'custom:read'});
});

test('URL path append preserves encoded base path and query parameters',async()=>{
  const seen:string[]=[];const client=createConversationClient({endpoint:'https://api.example/a%20b/conversations/?tenant=one%26two',connectionId:'c',issuer:'i',clock:{now:()=>0},store:memoryStore(),authorizedRequest:async request=>{seen.push(request.url);return json({conversation_id:'c1',events:[],cursor:null,has_more:false,status:'idle',responder:'agent'});}});
  await client.read('c1');assert.equal(seen[0],'https://api.example/a%20b/conversations/c1/events?tenant=one%26two');
});
import { parseEventStream } from '../dist/protocol/sse.js';
const eventFrame=(e:{id:string;[key:string]:unknown})=>`id: ${e.id}\ndata: ${JSON.stringify(e)}\n\n`;
const streamResponse=(text: string|undefined,fragment=9999999)=>new Response(new ReadableStream({start(c){const b=new TextEncoder().encode(text);for(let i=0;i<b.length;i+=fragment)c.enqueue(b.slice(i,i+fragment));c.close();}}),{headers:{'content-type':'text/event-stream'}});
const streamEvent=(id: string,type='state')=>({id,type,created_at:'2026-10-22T00:00:00Z',status:'idle',responder:'agent'});

test('SSE fragmentation, UTF-8, CRLF, frame limits and incomplete frames',async()=>{
  const value={...streamEvent('e1','user_requested'),reason:'café ☕'};
  const response=streamResponse(eventFrame(value).replaceAll('\n','\r\n'),1);
  const frames=[];for await(const frame of parseEventStream(expectValue(response.body)))frames.push(frame);
  assert.deepEqual(frames,[{kind:'event',event:value}]);
  await assert.rejects(async()=>{for await(const _ of parseEventStream(expectValue(streamResponse('data: '+ 'x'.repeat(300)).body),{maxFrameBytes:100})){}},{field:'sse.frame.size'});
  const incomplete=[];for await(const frame of parseEventStream(expectValue(streamResponse(eventFrame(value).slice(0,-2)).body)))incomplete.push(frame);assert.deepEqual(incomplete,[]);
});

test('watch reconnect uses Last-Event-ID, clears deltas, deduplicates, and acknowledges only explicit ack',async()=>{
  const seen:Request[]=[],partial:({messageId:string;text:string}|null)[]=[],store=memoryStore();let n=0;
  const e1=streamEvent('e1'),e2={...streamEvent('e2'),status:'closed'};
  const client=createConversationClient({endpoint:EP,connectionId:'c',issuer:'i',store,clock:{now:()=>0},sleep:async()=>{},authorizedRequest:async request=>{seen.push(request);return n++===0?streamResponse(eventFrame(e1)+'event: text-delta\ndata: {"message_id":"m1","text":"unfinished"}\n\n',1):streamResponse(eventFrame(e1)+eventFrame(e2));}});
  const results=[];for await(const item of client.watch('c1',{consumer:'ui',onPartial:value=>partial.push(value)})){results.push(item.event.id);assert.equal(await store.getCheckpoint({connectionId:'c',issuer:'i',endpoint:EP},'c1','ui'),results.length===1?undefined:'e1');await item.ack();}
  assert.deepEqual(results,['e1','e2']);assert.equal(seen[1].headers.get('last-event-id'),'e1');assert.ok(partial.some(value=>value?.text==='unfinished'));assert.equal(partial.at(-1),null);assert.equal(await store.getCheckpoint({connectionId:'c',issuer:'i',endpoint:EP},'c1','ui'),'e2');
});

test('watch handles JSON fallback, explicit history-gap recovery and method-independent authorization hook',async()=>{
  let calls=0;const auth=(scopes:string[])=>({requiredScopes:scopes,grantedScopes:[],missingScopes:scopes,sufficient:false,methods:[{method:'device' as const,scopes}],organization:{name:'Fixture',domain:'fixture.test'}});const client=createConversationClient({endpoint:EP,connectionId:'c',issuer:'i',store:memoryStore(),clock:{now:()=>0},sleep:async()=>{},authorization:async(_id,scopes)=>auth(scopes),authorizedRequest:async()=>++calls===1?json({error:'cursor_expired'},410):json({conversation_id:'c1',events:[{...streamEvent('e1'),status:'closed'}],cursor:'e1',has_more:false,status:'closed',responder:'agent'})});
  const events=[];for await(const item of client.watch('c1',{cursor:'old',onHistoryGap:()=>true}))events.push(item.event.id);assert.deepEqual(events,['e1']);
  assert.deepEqual(await client.authorization({...streamEvent('a','authorization'),scope:'read write'}),auth(['read','write']));
});

test('watch drains JSON has_more immediately beyond reconnect budget, including closed history',async()=>{
  let calls=0,sleeps=0;const client=createConversationClient({endpoint:EP,connectionId:'c',issuer:'i',store:memoryStore(),clock:{now:()=>0},sleep:async()=>{sleeps++;},authorizedRequest:async()=>{calls++;return json({conversation_id:'c1',events:[streamEvent('e'+calls)],cursor:'e'+calls,has_more:calls<8,status:'closed',responder:'agent'});}});
  const items=[];for await(const item of client.watch('c1',{maxReconnects:0}))items.push(item.event.id);assert.equal(items.length,8);assert.equal(sleeps,0);
});

test('watch skips unknown and duplicate events without rewinding durable acks',async()=>{
  const store=memoryStore(),events=[streamEvent('e1'),streamEvent('e2'),streamEvent('e1'),streamEvent('future','new-kind'),{...streamEvent('e3'),status:'closed'}];
  const client=createConversationClient({endpoint:EP,connectionId:'c',issuer:'i',store,clock:{now:()=>0},authorizedRequest:async()=>streamResponse(events.map(eventFrame).join(''))});
  const received=[];for await(const item of client.watch('c1',{consumer:'ui'})){received.push(item.event.id);await item.ack();}assert.deepEqual(received,['e1','e2','e3']);assert.equal(await store.getCheckpoint({connectionId:'c',issuer:'i',endpoint:EP},'c1','ui'),'e3');
});

test('watch reports reconnect exhaustion, and retry/drain backoff is promptly cancellable',async()=>{
  const client=createConversationClient({endpoint:EP,connectionId:'c',issuer:'i',store:memoryStore(),clock:{now:()=>0},authorizedRequest:async()=>streamResponse('')});
  await assert.rejects(async()=>{for await(const _ of client.watch('c1',{maxReconnects:0})){}},{code:'reconnect_exhausted'});
  const abort=new AbortController();let entered: (arg0: AbortSignal) => void;const started=new Promise<AbortSignal>(resolve=>entered=resolve);
  const retrying=createConversationClient({endpoint:EP,connectionId:'c',issuer:'i',store:memoryStore(),clock:{now:()=>0},baseDelayMs:60000,maxDelayMs:60000,random:()=>1,authorizedRequest:async request=>{entered(request.signal);return json({error:'rate_limited'},429,{'retry-after':'60'});}});
  const draining=retrying.drain('c1',{signal:abort.signal});assert.equal((await started).aborted,false);abort.abort();await assert.rejects(draining,{name:'AbortError'});
});

test('watch backoff cancellation releases immediately and JSON fallback has its own byte budget',async()=>{
  const abort=new AbortController();let entered!:()=>void;const waiting=new Promise<void>(resolve=>entered=resolve);
  const client=createConversationClient({endpoint:EP,connectionId:'c',issuer:'i',store:memoryStore(),clock:{now:()=>0},baseDelayMs:60000,maxDelayMs:60000,authorizedRequest:async()=>{entered();return streamResponse('');}});
  const watching=(async()=>{for await(const _ of client.watch('c1',{signal:abort.signal})){} })();await waiting;await new Promise(resolve=>setTimeout(resolve,1));abort.abort();await assert.rejects(watching,{name:'AbortError'});
  const huge=createConversationClient({endpoint:EP,connectionId:'c',issuer:'i',store:memoryStore(),clock:{now:()=>0},authorizedRequest:async()=>new Response(' '.repeat(1048577),{headers:{'content-type':'application/json'}})});
  await assert.rejects(async()=>{for await(const _ of huge.watch('c1')){}},{code:'body_limit'});
  const frames=[];for await(const frame of parseEventStream(expectValue(streamResponse(eventFrame({...streamEvent('closed'),status:'closed'}).replaceAll('\n','\r'),1).body)))frames.push(frame);assert.equal(frames.length,1);
});

test('conversation extension errors preserve bounded domain-qualified header and body details',async()=>{
  const {client,server}=setup();server.hooks.failures.push(json({error:'extension_required',extension:'example.com/gift-wrap'},403,{'www-authenticate':'DPoP error="extension_required", extension="other.example/thing"'}));
  await assert.rejects(client.read('c1'),error=>error instanceof ConversationError&&error.code==='extension_required'&&error.extensions.includes('example.com/gift-wrap')&&error.extensions.includes('other.example/thing'));
});
