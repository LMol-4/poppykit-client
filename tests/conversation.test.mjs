import test from 'node:test';
import assert from 'node:assert/strict';
import { createConversationClient, initialConversationClientState, ConversationError } from '../dist/conversation.js';

const EP = 'https://api.example.com/poppy/conversations';
const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
const memoryStore = () => {
  let state = initialConversationClientState();
  return {
    read: async () => structuredClone(state),
    transaction: async change => { const draft = structuredClone(state); const result = change(draft); state = draft; return structuredClone(result); },
  };
};
const sorted = value => Array.isArray(value) ? value.map(sorted) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(k => [k, sorted(value[k])])) : value;

// Independently written Poppy company fixture (spec 7.2-7.13), with fault hooks.
function company() {
  const byMessage = new Map(); // message id -> { body, conversation, status }
  const conversations = new Map(); // id -> { events: [] }
  const log = [];
  const hooks = { dropResponses: 0, failures: [] };
  let n = 0;
  const addEvent = (conv, event) => conv.events.push({ id: `evt_${++n}`, created_at: '2026-10-19T10:00:00Z', ...event });
  async function handle(request) {
    const url = new URL(request.url);
    log.push(`${request.method} ${url.pathname}${url.search}`);
    if (hooks.failures.length) { const f = hooks.failures.shift(); return f; }
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
        addEvent(conversations.get(conversation), { type: 'message', message: { ...body.message, role: 'user' } });
        entry = { key, target, state: { conversation_id: conversation, status: 'working', responder: 'agent' }, status: target === null ? 201 : 202 };
        byMessage.set(id, entry);
      }
      if (hooks.dropResponses > 0) { hooks.dropResponses--; throw new TypeError('connection reset'); }
      return json(entry.state, entry.status);
    }
    const events = /^\/([^/]+)\/events$/.exec(path);
    if (request.method === 'GET' && events) {
      const conv = conversations.get(events[1]);
      if (!conv) return json({ error: 'conversation_not_found' }, 404);
      const cursor = url.searchParams.get('cursor');
      let from = 0;
      if (cursor === 'evt_gone') return json({ error: 'cursor_expired' }, 410);
      if (cursor) { const i = conv.events.findIndex(e => e.id === cursor); if (i < 0) return json({ error: 'invalid_cursor' }, 400); from = i + 1; }
      const page = conv.events.slice(from, from + 2);
      return json({ conversation_id: events[1], events: page, cursor: page.at(-1)?.id ?? cursor, has_more: from + 2 < conv.events.length, status: 'idle', responder: 'agent' });
    }
    return json({ error: 'invalid_request' }, 400);
  }
  return { handle, log, hooks, conversations, addEvent, byMessage };
}

function setup(overrides = {}) {
  const server = company();
  const sleeps = [];
  const store = memoryStore();
  const client = createConversationClient({
    authorizedRequest: request => server.handle(request), endpoint: EP, connectionId: 'conn1', issuer: 'https://issuer.example.com',
    store, clock: { now: () => Date.parse('2026-10-19T10:00:00Z') }, sleep: async ms => { sleeps.push(ms); },
    newId: (() => { let i = 0; return () => `msg_gen${++i}`; })(), ...overrides,
  });
  return { server, sleeps, store, client };
}
const msg = { sender: 'agent', text: 'hello' };

test('lost first POST response then retry reuses the ID and the company dedupes', async () => {
  const { server, client } = setup({ maxAttempts: 1 });
  server.hooks.dropResponses = 1;
  await assert.rejects(client.start({ ...msg, id: 'msg_a' }), e => e.code === 'network_error');
  const pending = await client.operation('msg_a');
  assert.equal(pending.phase, 'pending'); // persisted before send
  assert.equal(pending.request.message.text, 'hello');
  const state = await client.retry('msg_a');
  assert.equal(state.conversation_id, 'cnv_1');
  assert.equal(server.conversations.size, 1);
  assert.equal(server.conversations.get('cnv_1').events.length, 1);
  assert.equal((await client.operation('msg_a')).phase, 'accepted');
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
  assert.equal(server.conversations.get('cnv_1').events.length, 1);
});

test('outbound content is persisted before the first dispatch', async () => {
  let seen;
  const { client, store } = setup({ authorizedRequest: async () => { seen = (await store.read()).outbound; throw new Error('down'); }, maxAttempts: 1 });
  await assert.rejects(client.send('cnv_9', { ...msg, id: 'msg_c', data: { x: 1 } }));
  assert.equal(seen[0].id, 'msg_c');
  assert.equal(seen[0].target, 'cnv_9');
  assert.deepEqual(seen[0].request.message.data, { x: 1 });
});

test('same ID with different content or target is a local conflict; key order is ignored', async () => {
  const { client, server } = setup();
  await client.start({ id: 'msg_d', sender: 'agent', data: { a: 1, b: [1, 2] }, text: 't' });
  await client.start({ id: 'msg_d', sender: 'agent', text: 't', data: { b: [1, 2], a: 1 } });
  await assert.rejects(client.start({ id: 'msg_d', sender: 'agent', text: 't', data: { a: 1, b: [2, 1] } }), e => e.code === 'message_id_conflict');
  await assert.rejects(client.start({ id: 'msg_d', sender: 'agent', text: 't ', data: { a: 1, b: [1, 2] } }), e => e.code === 'message_id_conflict');
  await assert.rejects(client.send('cnv_1', { id: 'msg_d', sender: 'agent', text: 't', data: { a: 1, b: [1, 2] } }), e => e.code === 'message_id_conflict');
  assert.equal(server.conversations.size, 1);
});

test('unknown extension members are part of the identity', async () => {
  const { client } = setup();
  await client.start({ id: 'msg_e', sender: 'agent', text: 'x', ext: { v: 1 } });
  await assert.rejects(client.start({ id: 'msg_e', sender: 'agent', text: 'x', ext: { v: 2 } }), e => e.code === 'message_id_conflict');
});

test('rejections: definite 4xx is recorded and not resent; 5xx stays retryable', async () => {
  const { client, server } = setup({ maxAttempts: 1 });
  await assert.rejects(client.send('cnv_missing', { ...msg, id: 'msg_f' }), e => e.code === 'conversation_not_found' && e.status === 404);
  const posts = server.log.length;
  assert.equal((await client.operation('msg_f')).phase, 'rejected');
  await assert.rejects(client.retry('msg_f'), e => e.code === 'conversation_not_found');
  assert.equal(server.log.length, posts);
  server.hooks.failures.push(json({ error: 'server_error' }, 503));
  await assert.rejects(client.start({ ...msg, id: 'msg_g' }), e => e.status === 503);
  assert.equal((await client.operation('msg_g')).phase, 'pending');
  assert.equal((await client.retry('msg_g')).conversation_id, 'cnv_1');
  await assert.rejects(client.retry('msg_unknown'), e => e.code === 'unknown_operation');
});

test('company message_id_conflict is definite', async () => {
  const { client, server } = setup();
  server.byMessage.set('msg_h', { key: 'other', target: null });
  await assert.rejects(client.start({ ...msg, id: 'msg_h' }), e => e.code === 'message_id_conflict' && e.status === 409);
  assert.equal((await client.operation('msg_h')).phase, 'rejected');
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
  await assert.rejects(client.start({ ...msg, id: 'msg_j' }), e => e.code === 'rate_limited' && e.retryAfterMs === 3600000);
  assert.deepEqual(sleeps, []);
  assert.equal((await client.operation('msg_j')).phase, 'pending');
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
  await assert.rejects(client.start({ ...msg, id: 'msg_l' }), e => e.code === 'invalid_response');
  assert.equal((await client.operation('msg_l')).phase, 'pending');
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
  await assert.rejects(client.read(conversation_id, { cursor: 'evt_zzz' }), e => e.code === 'invalid_cursor');
  await assert.rejects(client.read('cnv_nope'), e => e.code === 'conversation_not_found');
});

test('read rejects an inconsistent page and retries 429 with Retry-After', async () => {
  const { client, server, sleeps } = setup();
  const { conversation_id } = await client.start({ ...msg, id: 'msg_p' });
  server.hooks.failures.push(json({ conversation_id, events: [], cursor: null, has_more: true, status: 'idle', responder: 'agent' }));
  await assert.rejects(client.read(conversation_id), e => e.code === 'invalid_response');
  server.hooks.failures.push(json({ error: 'rate_limited' }, 429, { 'retry-after': '2' }));
  const page = await client.read(conversation_id, { wait: 5 });
  assert.deepEqual(sleeps, [2000]);
  assert.equal(page.events.length, 1);
  assert.ok(server.log.at(-1).endsWith('wait=5'));
});

test('handoff and close return state; closed conversation error is surfaced', async () => {
  const { client, server } = setup();
  const { conversation_id } = await client.start({ ...msg, id: 'msg_q' });
  server.hooks.failures.push(json({ conversation_id, status: 'queued', responder: 'agent' }, 202));
  assert.equal((await client.handoff(conversation_id)).status, 'queued');
  server.hooks.failures.push(json({ error: 'conversation_closed' }, 409));
  await assert.rejects(client.close(conversation_id), e => e.code === 'conversation_closed');
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
    await assert.rejects(client.send(bad, { ...msg, id: 'msg_v' }), e => e.field === 'conversation_id');
    await assert.rejects(client.read(bad), e => e.field === 'conversation_id');
    await assert.rejects(client.handoff(bad), e => e.field === 'conversation_id');
    await assert.rejects(client.close(bad), e => e.field === 'conversation_id');
    await assert.rejects(client.start({ ...msg, id: 'msg_v' }, { parentConversationId: bad }), e => e.field === 'parent_conversation_id');
  }
  await assert.rejects(client.retry('../x'));
  assert.equal(server.log.length, 0);
  assert.equal((await store.read()).outbound.length, 0);
});

test('drain fails on a has_more page that makes no progress, and caps the page count', async () => {
  const { client, server } = setup();
  const { conversation_id } = await client.start({ ...msg, id: 'msg_s' });
  const stuck = cursor => json({ conversation_id, events: [], cursor, has_more: true, status: 'idle', responder: 'agent' });
  server.hooks.failures.push(stuck(null));
  await assert.rejects(client.drain(conversation_id), e => e.code === 'invalid_response');
  const first = (await client.read(conversation_id)).cursor;
  server.hooks.failures.push(stuck(first));
  await assert.rejects(client.drain(conversation_id, { cursor: first }), e => e.code === 'invalid_response');
  const { client: capped, server: s2 } = setup({ maxPages: 1 });
  const started = await capped.start({ ...msg, id: 'msg_t' });
  for (let i = 0; i < 3; i++) s2.addEvent(s2.conversations.get(started.conversation_id), { type: 'state', status: 'idle', responder: 'agent' });
  await assert.rejects(capped.drain(started.conversation_id), e => e.code === 'too_many_pages');
});

test('token errors from WWW-Authenticate are exposed; unknown company codes become http_error', async () => {
  const { client, server } = setup({ maxAttempts: 1 });
  const challenge = value => new Response('', { status: value.status, headers: { 'www-authenticate': value.header } });
  server.hooks.failures.push(challenge({ status: 401, header: 'DPoP error="invalid_token"' }));
  await assert.rejects(client.read('cnv_1'), e => e.code === 'invalid_token' && e.status === 401);
  server.hooks.failures.push(challenge({ status: 403, header: 'DPoP error="sign_in_required"' }));
  await assert.rejects(client.read('cnv_1'), e => e.code === 'sign_in_required' && e.scope === undefined);
  server.hooks.failures.push(challenge({ status: 403, header: 'DPoP error="insufficient_scope", scope="poppy:read poppy:write"' }));
  await assert.rejects(client.read('cnv_1'), e => e.code === 'insufficient_scope' && e.scope === 'poppy:read poppy:write');
  server.hooks.failures.push(json({ error: 'x'.repeat(5000) }, 400));
  await assert.rejects(client.read('cnv_1'), e => e.code === 'http_error' && e.message.length < 60);
  server.hooks.failures.push(challenge({ status: 403, header: 'DPoP error="made_up"' }));
  await assert.rejects(client.read('cnv_1'), e => e.code === 'http_error');
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
  assert.deepEqual(dpopChallenge('Bearer scope="openid", DPoP error="insufficient_scope", scope="poppy:read poppy:write"'), { error: 'insufficient_scope', scope: 'poppy:read poppy:write' });
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
  const with_ = header => new Response('', { status: 401, headers: { 'www-authenticate': header } });
  server.hooks.failures.push(with_('Bearer scope="openid", DPoP error="insufficient_scope", scope="poppy:read poppy:write"'));
  await assert.rejects(client.read('cnv_1'), e => e.code === 'insufficient_scope' && e.scope === 'poppy:read poppy:write');
  server.hooks.failures.push(with_('Bearer error="invalid_token", DPoP error="use_dpop_nonce"'));
  await assert.rejects(client.read('cnv_1'), e => e.code === 'use_dpop_nonce');
  server.hooks.failures.push(with_('DPoP Error="invalid_token", error_description="x, error=\\"sign_in_required\\""'));
  await assert.rejects(client.read('cnv_1'), e => e.code === 'invalid_token');
  server.hooks.failures.push(with_('@@@ ,,, "'));
  await assert.rejects(client.read('cnv_1'), e => e.code === 'http_error');
});

// ---- J16: consumers, checkpoints, POST wait, pruning ----
const seed = async (client, server, n) => {
  const { conversation_id } = await client.start({ ...msg, id: 'msg_seed' });
  for (let i = 1; i < n; i++) server.addEvent(server.conversations.get(conversation_id), { type: 'state', status: 'idle', responder: 'agent' });
  return conversation_id;
};
const ids = pages => pages.flatMap(p => p.events.map(e => e.id));
const otherClient = (server, store, connectionId = 'conn1') => createConversationClient({ authorizedRequest: r => server.handle(r), endpoint: EP, connectionId, issuer: 'https://issuer.example.com', store, clock: { now: () => 0 }, sleep: async () => {} });

test('retryAfter of a huge integer is Infinity and surfaces as the delay', async () => {
  const { client, server, sleeps } = setup();
  server.hooks.failures.push(json({ error: 'rate_limited' }, 429, { 'retry-after': '9'.repeat(30) }));
  await assert.rejects(client.start({ ...msg, id: 'msg_huge' }), e => e.code === 'rate_limited' && e.retryAfterMs === Infinity);
  assert.deepEqual(sleeps, []);
});

test('consumer checkpoint moves only on ack; reads and the iterator never acknowledge', async () => {
  const { client, server, store } = setup();
  const cid = await seed(client, server, 3);
  const first = await client.read(cid, { consumer: 'worker' });
  assert.equal(first.events.length, 2);
  assert.deepEqual((await store.read()).consumers, []);
  const again = await client.read(cid, { consumer: 'worker' }); // redelivery, not skipping
  assert.deepEqual(ids([again]), ids([first]));
  const seen = []; for await (const e of client.events(cid, { consumer: 'worker' })) seen.push(e.id);
  assert.equal(seen.length, 3);
  assert.deepEqual((await store.read()).consumers, []);
  await client.ack(cid, 'worker', first);
  assert.equal((await store.read()).consumers[0].cursor, first.cursor);
  const next = await client.read(cid, { consumer: 'worker' });
  assert.deepEqual(ids([next]), [seen[2]]);
  assert.ok(server.log.at(-1).includes('cursor=' + first.cursor));
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
  await assert.rejects(client.ack(cid, 'w', explicit), e => e.code === 'invalid_request');
  const page = await client.read(cid, { consumer: 'w' });
  await assert.rejects(client.ack(cid, 'other', page), e => e.code === 'invalid_request');
  await assert.rejects(client.ack(cid, 'w', { ...page }), e => e.code === 'invalid_request');
  await assert.rejects(client.read(cid, { consumer: 'w', cursor: page.cursor }), e => e.code === 'invalid_request');
  await assert.rejects(client.drain(cid, { consumer: 'w', cursor: page.cursor }), e => e.code === 'invalid_request');
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
  await store.transaction(d => { d.consumers[0].cursor = 'evt_gone'; });
  await assert.rejects(client.read(cid, { consumer: 'w' }), e => e.code === 'cursor_expired');
  await assert.rejects(client.read(cid, { consumer: 'w' }), e => e.code === 'cursor_expired'); // never silently restarted
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
  assert.ok(!server.log.at(-1).includes('cursor'));
  server.hooks.failures.push(json(empty));
  await assert.rejects(client.read('cnv_1', { cursor: 'evt_1' }), e => e.code === 'invalid_response');
  server.hooks.failures.push(json({ ...empty, has_more: true }));
  await assert.rejects(client.read('cnv_1'), e => e.code === 'invalid_response');
});

test('POST wait and cursor return a page receipt; a repeat with other parameters does not resend', async () => {
  const { client, server } = setup();
  const { conversation_id } = await client.start({ ...msg, id: 'msg_first' });
  const page = { conversation_id, events: [{ id: 'evt_9', type: 'state', created_at: '2026-10-19T10:00:00Z', status: 'idle', responder: 'agent' }], cursor: 'evt_9', has_more: false, status: 'idle', responder: 'agent' };
  server.hooks.failures.push(json(page, 202));
  const sent = await client.send(conversation_id, { ...msg, id: 'msg_w' }, { wait: 10, cursor: 'evt_1' });
  assert.deepEqual(sent.events, page.events);
  assert.ok(server.log.at(-1).endsWith('/messages?cursor=evt_1&wait=10'));
  const before = server.log.length;
  assert.deepEqual((await client.send(conversation_id, { ...msg, id: 'msg_w' }, { wait: 0 })).events, page.events);
  assert.equal(server.log.length, before);
  server.hooks.failures.push(json(page, 201));
  await client.start({ ...msg, id: 'msg_sw' }, { wait: 3 });
  assert.ok(server.log.at(-1).endsWith('/poppy/conversations?wait=3'));
});

test('POST wait: bad parameters and a non-page body are rejected', async () => {
  const { client, server } = setup();
  await assert.rejects(client.start({ ...msg, id: 'msg_n1' }, { wait: -1 }), e => e.code === 'invalid_request');
  await assert.rejects(client.start({ ...msg, id: 'msg_n2' }, { wait: 1.5 }), e => e.code === 'invalid_request');
  await assert.rejects(client.start({ ...msg, id: 'msg_n3' }, { cursor: 'a&b' }));
  assert.equal(server.log.length, 0);
  server.hooks.failures.push(json({ conversation_id: 'cnv_1', status: 'working', responder: 'agent' }, 201));
  await assert.rejects(client.start({ ...msg, id: 'msg_n4' }, { wait: 2 }), e => e.code === 'invalid_response');
  assert.equal((await client.operation('msg_n4')).phase, 'pending');
});

test('direct_conversation_open surfaces the conversation ID, also on later retry', async () => {
  const { client, server } = setup();
  const cid = await seed(client, server, 1);
  server.hooks.failures.push(json({ error: 'direct_conversation_open', conversation_id: 'cnv_direct' }, 409));
  await assert.rejects(client.send(cid, { ...msg, id: 'msg_d1' }), e => e.code === 'direct_conversation_open' && e.conversationId === 'cnv_direct');
  await assert.rejects(client.retry('msg_d1'), e => e.code === 'direct_conversation_open' && e.conversationId === 'cnv_direct');
  server.hooks.failures.push(json({ error: 'direct_conversation_open', conversation_id: 'bad id' }, 409));
  await assert.rejects(client.handoff(cid), e => e.code === 'http_error' && e.conversationId === undefined);
});

test('close success returns the closed state', async () => {
  const { client, server } = setup();
  const cid = await seed(client, server, 1);
  server.hooks.failures.push(json({ conversation_id: cid, status: 'closed', responder: 'agent' }));
  assert.equal((await client.close(cid)).status, 'closed');
  assert.ok(server.log.at(-1).startsWith('POST') && server.log.at(-1).endsWith(`/${cid}/close`));
});

test('completed outbound records are pruned to about the newest N; pending ones are kept', async () => {
  const { client, server, store } = setup({ keepCompleted: 2 });
  server.hooks.failures.push(json({ error: 'x' }, 500), json({ error: 'x' }, 500), json({ error: 'x' }, 500), json({ error: 'x' }, 500));
  await assert.rejects(client.start({ ...msg, id: 'msg_pend' })); // stays pending
  for (const i of [1, 2, 3, 4]) await client.start({ ...msg, id: `msg_p${i}` });
  // N completed plus the one in flight at prune time
  assert.deepEqual((await store.read()).outbound.map(r => r.id), ['msg_pend', 'msg_p2', 'msg_p3', 'msg_p4']);
  const before = server.byMessage.size;
  await client.start({ ...msg, id: 'msg_p4' }); // recent retry is still deduped locally
  assert.equal(server.byMessage.size, before);
});
