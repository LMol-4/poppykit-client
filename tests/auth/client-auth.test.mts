import { expectValue } from '../../test-support/assertions.mjs';
import type { ClientAuth, ClientAuthOptions, ClientAuthState, IdentitySigner, SignInInput, AuthOutcome, OperationRecord, TrustedInput, SignOutOutcome, ConversationTarget, SignInStart, AssertionRequest } from '../../dist/auth/client-auth.js';
import type { AuthSelection } from '../../dist/auth/store.js';
import type { JsonObject } from '../../dist/protocol/wire.js';
import type { FakeCompany } from './fake-issuer.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { calculateJwkThumbprint, CompactSign } from 'jose';
import { createClientAuth, initialClientAuthState, AuthFailure, createMetadataResolver } from '../../dist/index.js';
import { createFakeCompany, fakeTransport } from './fake-issuer.mjs';
import { SqliteAuthStore } from '../../dist/sqlite.js';
import { PostgresAuthStore } from '../../dist/postgres.js';
import { testPool } from '../../test-support/postgres.mjs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CLIENT_ID = 'https://agent.test/agent.json';
const REDIRECT = 'https://agent.test/oauth/callback';
for (const engine of ['SQLite', ...(process.env.D1_POSTGRES === '1' ? ['Postgres'] : [])]) test(`global auth history pruning uses bounded durable selectors (${engine})`, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'auth-history-')), path = join(dir, 'auth.sqlite');
  const pool = engine === 'Postgres' ? testPool() : undefined;
  const namespace = `${process.env.D1_NAMESPACE ?? 'local'}:${path}`;
  const open = () => pool ? new PostgresAuthStore(pool, namespace) : new SqliteAuthStore(path);
  const store = open(); let second: ReturnType<typeof open> | undefined;
  try {
    const env = await setup(), auth = createClientAuth({ ...env.options, store });
    const initial = await auth.start(env.company.domain);
    const direct = await beginAndApprove(auth, env.company, initial.connection.id);
    const restore = loseTokenResponses(env.transport, env.company);
    const uncertain = await auth.completeSignIn({ callbackUrl: direct.callbackUrl, browserBinding: BROWSER });
    restore(); assert.equal(uncertain.status, 'uncertain');
    const pending = (await auth.beginSignIn(initial.connection.id, { scopes: ['poppy:read'], redirectUri: REDIRECT, browserBinding: BROWSER, force: true })).outcome;
    const starts: string[] = [], completions: string[] = []; let oldestCallback = '';
    for (let i = 0; i < 104; i++) {
      env.clock.t += 2000;
      const started = await auth.start(env.company.domain); starts.push(started.operationId);
      const approved = await beginAndApprove(auth, env.company, started.connection.id);
      if (!oldestCallback) oldestCallback = approved.callbackUrl;
      const completed = await auth.completeSignIn({ callbackUrl: approved.callbackUrl, browserBinding: BROWSER }); completions.push(completed.operationId);
    }
    assert.equal(await auth.operation(starts[0]), null);
    assert.equal(await auth.operation(completions[0]), null);
    assert.equal((await auth.operation(uncertain.operationId))?.status, 'uncertain');
    assert.equal((await auth.operation(pending.operationId))?.status, 'pending');
    second = open(); const restarted = createClientAuth({ ...env.options, store: second });
    assert.equal((await restarted.operation(completions.at(-1)!))?.status, 'completed');
    assert.equal((await restarted.operation(uncertain.operationId))?.status, 'uncertain');
    env.clock.t += 2000;
    await Promise.all([auth.start(env.company.domain), restarted.start(env.company.domain)]);
    const history = await store.read({ issuer: env.company.issuer, history: true });
    assert.equal(Object.values(history.operations).filter(op => op.phase === 'terminal' && op.status !== 'uncertain').length, 101);
    await assert.rejects(restarted.completeSignIn({ callbackUrl: oldestCallback, browserBinding: BROWSER }), { code: 'invalid_callback' });
    assert.equal((await restarted.completeSignIn({ callbackUrl: direct.callbackUrl, browserBinding: BROWSER })).status, 'uncertain');
    assert.equal((await restarted.operation(uncertain.operationId))?.status, 'uncertain');
  } finally { await second?.close(); await store.close(); await pool?.end(); await rm(dir, { recursive: true, force: true }); }
});
test('independently constructed OAuth callbacks accept optional/unknown fields and preserve registered query bindings', async () => {
  const env = await setup(), redirectUri = REDIRECT + '?route=fixed&route=second';
  const auth = createClientAuth({ ...env.options, redirectUris: [redirectUri] });
  const connection = (await auth.start(env.company.domain)).connection;
  for (const error of ['access_denied', 'server_error']) {
    const begun = await auth.beginSignIn(connection.id, { scopes: ['poppy:read'], redirectUri, browserBinding: 'independent-browser-binding-012345', force: true });
    const state = new URL(expectValue(begun.authorizationUrl)).searchParams.get('state')!;
    const callback = new URL(redirectUri);
    for (const [name, value] of Object.entries({ state, iss: env.company.issuer, error, error_description: 'PRIVATE_DETAIL', error_uri: 'https://shop.test/error', unknown: 'ignored' })) callback.searchParams.set(name, value);
    for (const bad of [callback.href.replace('route=fixed', 'route=forged'), callback.href + '&route=forged', callback.href + '&code=extra', callback.href + '&error=duplicate', callback.href + '&iss=duplicate', callback.href.replace(state, 'forged-state')]) {
      await assert.rejects(auth.completeSignIn({ callbackUrl: bad, browserBinding: 'independent-browser-binding-012345' }), { code: 'invalid_callback' });
    }
    await assert.rejects(auth.completeSignIn({ callbackUrl: callback.href, browserBinding: 'wrong-browser' }), { code: 'invalid_callback' });
    const result = await auth.completeSignIn({ callbackUrl: callback.href, browserBinding: 'independent-browser-binding-012345' });
    assert.equal(result.status, error === 'access_denied' ? 'denied' : 'failed');
    assert.ok(!JSON.stringify(result).includes('PRIVATE_DETAIL'));
    assert.deepEqual(await auth.completeSignIn({ callbackUrl: callback.href, browserBinding: 'independent-browser-binding-012345' }), result);
  }
  // A success response built by the independent fake issuer may also carry unknown fields.
  const success = await setup(), started = await success.auth.start(success.company.domain);
  const direct = await beginAndApprove(success.auth, success.company, started.connection.id);
  assert.equal((await success.auth.completeSignIn({ callbackUrl: direct.callbackUrl + '&future_extension=value', browserBinding: BROWSER })).status, 'completed');
});
const EC = { name: 'ECDSA', namedCurve: 'P-256' };
const ES256 = { name: 'ECDSA', hash: 'SHA-256' };

// Strict-JSON store check (INTERFACES v1.1): undefined values are rejected, as a SQLite/JSON store would.
const assertJson = (value:unknown, path = '$') => {
  if (value === undefined) throw new TypeError(`${path}: unsupported undefined`);
  if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) assertJson(v, `${path}.${k}`);
};
function memoryStore(initial = initialClientAuthState()) {
  let state = structuredClone(initial); let chain:Promise<unknown> = Promise.resolve();
  const store = {
    crashNext: false, crashIn: 0, // crashIn = n fails the nth transaction from now
    get raw() { return state; },
    async read() { return structuredClone(state); },
    async pendingOperations(after:string|undefined, limit:number) { return Object.values(state.operations).filter(row => row.phase !== 'terminal' && row.id > (after ?? '')).map(row => row.id).sort().slice(0, limit); },
    transaction<T>(selection:AuthSelection|((draft:ClientAuthState)=>T), change?: (draft:ClientAuthState)=>T) {
      const mutate=typeof selection==='function'?selection:change; assert.ok(mutate);
      const run = chain.then(() => {
        // Simulates the process dying before commit.
        if (store.crashNext) { store.crashNext = false; throw new Error('crash'); }
        if (store.crashIn && --store.crashIn === 0) throw new Error('crash');
        const draft = structuredClone(state); const result = mutate(draft);
        if (result && typeof result === 'object' && 'then' in result && typeof result.then === 'function') throw new Error('async transaction');
        assertJson(draft); state = draft; return structuredClone(result);
      });
      chain = run.catch(() => {}); return run;
    },
  };
  return store;
}
function memorySecrets() {
  const map = new Map<string,string>();
  return { map, async stage(secret:string) { const ref = `sec_${randomUUID()}`; map.set(ref, secret); return ref; }, async read(ref:string) { return map.get(ref) ?? null; }, async remove(ref:string) { map.delete(ref); } };
}
async function makeSigner(kid = 'agent-key-1'):Promise<IdentitySigner & {jwk:JsonObject;privateKey:CryptoKey}> {
  const pair = await crypto.subtle.generateKey(EC, true, ['sign', 'verify']);
  const { kty, crv, x, y } = await crypto.subtle.exportKey('jwk', pair.publicKey);
  assert.ok(kty&&crv&&x&&y); const jwk = { kty, crv, x, y, kid, use: 'sig', alg: 'ES256' };
  return { kid, jwk, privateKey: pair.privateKey, publicJwk: async () => ({ ...jwk }), sign: async (input:Uint8Array) => new Uint8Array(await crypto.subtle.sign(ES256, pair.privateKey, new Uint8Array(input))) };
}
async function setup({ localUserId = 'alice', store = memoryStore(), secrets = memorySecrets(), signer, names = ['shop'], conversationResource, method = 'direct' }: {localUserId?:string;store?:ReturnType<typeof memoryStore>;secrets?:ReturnType<typeof memorySecrets>;signer?:IdentitySigner & {jwk:JsonObject;privateKey?:CryptoKey};names?:string[];conversationResource?:string;method?:string} = {}) {
  signer ??= await makeSigner();
  const clock = { t: 1_790_900_000_000 }; const now = () => clock.t;
  const companies = names.map(name => createFakeCompany({ name, jwks: { keys: [signer.jwk] }, clientId: CLIENT_ID, now, redirectUris: [REDIRECT], conversationResource, method }));
  const transport = fakeTransport(...companies);
  const options: ClientAuthOptions = { namespace: 'demo', localUserId, clientId: CLIENT_ID, redirectUris: [REDIRECT], identity: signer, store, secrets, transport, metadata: createMetadataResolver(transport, { now }), now };
  return { auth: createClientAuth(options), options, company: companies[0], companies, transport, store, secrets, signer, clock };
}
const code = (expected:string) => (error:unknown):error is AuthFailure => error instanceof AuthFailure && error.code === expected;
const tokenForms = (company:FakeCompany) => {
  const forms: URLSearchParams[] = []; const original = company.handle;
  company.handle = async (request, init) => { if (request.url === company.tokenEndpoint) forms.push(new URLSearchParams(await request.clone().text())); return original(request, init); };
  return forms;
};
const conversations = (company:FakeCompany, path = '') => new Request(`${company.endpoint}${path}`, { method: 'POST', body: JSON.stringify({ hello: 'world' }), headers: { 'content-type': 'application/json' } });

test('start creates a signed-out session with verified assertions and a separate DPoP key', async () => {
  const { auth, company, store, secrets, signer } = await setup();
  const outcome = await auth.start(company.domain);
  assert.equal(outcome.status, 'completed');
  assert.deepEqual(Object.keys(outcome.connection).sort(), ['domain', 'generation', 'id', 'issuer', 'organization', 'scopes', 'sessionId', 'status']);
  assert.equal(outcome.connection.status, 'signed_out'); assert.equal(outcome.connection.issuer, company.issuer);
  assert.deepEqual(outcome.connection.scopes, []); assert.ok(company.sessions.has(outcome.connection.sessionId));
  const [client, session] = company.assertions;
  assert.equal(client.kind, 'client'); assert.equal(client.header.typ, 'client-authentication+jwt'); assert.equal(client.header.kid, signer.kid);
  for (const { payload } of [client, session]) {
    assert.equal(payload.aud, company.issuer); assert.equal(typeof payload.aud, 'string');
    assert.ok(payload.exp - payload.iat <= 300 && payload.exp > payload.iat);
    assert.ok(payload.jti.length >= 16);
  }
  assert.notEqual(client.payload.jti, session.payload.jti);
  assert.equal(session.payload.sub, store.raw.identities[company.issuer].userId); assert.notEqual(session.payload.sub, 'alice');
  const [proof] = company.proofs;
  assert.equal(proof.payload.htm, 'POST'); assert.equal(proof.payload.htu, company.tokenEndpoint); assert.equal('ath' in proof.payload, false);
  assert.equal('d' in proof.header.jwk, false);
  assert.notEqual(proof.thumbprint, await calculateJwkThumbprint(signer.jwk));
  const persisted = JSON.stringify(store.raw);
  for (const token of company.tokens.keys()) { assert.equal(persisted.includes(expectValue(token)), false); assert.equal(JSON.stringify(outcome).includes(expectValue(token)), false); }
  assert.equal(persisted.includes('"d"'), false);
  assert.equal([...secrets.map.values()].some(value => company.tokens.has(value)), false, 'Session Tokens stay in memory');
  assert.equal(expectValue(store.raw.operations[outcome.operationId].result).status, 'completed');
  assert.deepEqual(store.raw.owner, { namespace: 'demo', clientId: CLIENT_ID, localUserId: 'alice' });
  assert.deepEqual(await auth.get(outcome.connection.id), outcome.connection);
  assert.deepEqual(await auth.list(), [outcome.connection]);
  assert.deepEqual(await auth.target(outcome.connection.id), { issuer: company.issuer, endpoint: company.endpoint });
});

test('User IDs and DPoP keys are stable per issuer and separate per issuer and local user', async () => {
  const signer = await makeSigner();
  const { auth, companies: [shop, books] } = await setup({ signer, names: ['shop', 'books'] });
  const a = await auth.start(shop.domain); const b = await auth.start(shop.domain); const c = await auth.start(books.domain);
  assert.notEqual(a.connection.id, b.connection.id); assert.notEqual(a.connection.sessionId, b.connection.sessionId);
  const sessionSubs = (company:FakeCompany) => company.assertions.filter(item => item.kind === 'session').map(item => item.payload.sub);
  const [shopSub1, shopSub2] = sessionSubs(shop); const [booksSub] = sessionSubs(books);
  assert.equal(shopSub1, shopSub2); assert.notEqual(shopSub1, booksSub);
  assert.equal(shop.proofs[0].thumbprint, shop.proofs[1].thumbprint); assert.notEqual(shop.proofs[0].thumbprint, books.proofs[0].thumbprint);
  const other = await setup({ localUserId: 'bob', signer });
  await other.auth.start(other.company.domain);
  assert.notEqual(other.company.assertions[1].payload.sub, shopSub1); assert.notEqual(other.company.proofs[0].thumbprint, shop.proofs[0].thumbprint);
  assert.equal(c.connection.issuer, books.issuer);
});

test('the fake issuer rejects wrong audience, lifetime, key and replayed assertions', async () => {
  const { company, signer, clock } = await setup();
  const iat = Math.floor(clock.t / 1000);
  const sign = async (payload:unknown, key:CryptoKey = expectValue(signer.privateKey), kid = signer.kid) => new CompactSign(new TextEncoder().encode(JSON.stringify(payload))).setProtectedHeader({ alg: 'ES256', kid }).sign(key);
  const good = { iss: CLIENT_ID, sub: 'usr_x', aud: company.issuer, iat, exp: iat + 60, jti: 'jti-0123456789abcdef' };
  await company.verifyAssertion(await sign(good), 'session');
  const other = await makeSigner();
  for (const [payload, key] of [
    [{ ...good, jti: 'jti-aud-endpoint-0001', aud: company.tokenEndpoint }],
    [{ ...good, jti: 'jti-aud-array-00000001', aud: [company.issuer] }],
    [{ ...good, jti: 'jti-aud-slash-00000001', aud: `${company.issuer}/` }],
    [{ ...good, jti: 'jti-lifetime-000000001', exp: iat + 301 }],
    [{ ...good, jti: 'jti-wrong-key-00000001' }, other.privateKey],
    [{ ...good, jti: 'short' }],
    [good],
  ] satisfies [unknown,CryptoKey?][]) await assert.rejects(company.verifyAssertion(await sign(payload, key), 'session'), /invalid_grant/);
});

test('signer misconfiguration fails before any token request', async () => {
  const other = await makeSigner();
  const wrongKey = await makeSigner(); wrongKey.sign = other.sign; // publishes one key, signs with another
  const der = await makeSigner(); const derSign = der.sign; der.sign = async input => new Uint8Array([0x30, ...await derSign(input)]);
  const privateJwk = await makeSigner(); privateJwk.publicJwk = async () => ({ ...privateJwk.jwk, d: 'AAAA' });
  const rsa = await makeSigner(); rsa.publicJwk = async () => ({ kty: 'RSA', n: 'AQAB', e: 'AQAB' });
  for (const signer of [wrongKey, der, privateJwk, rsa]) {
    const { auth, company } = await setup({ signer });
    await assert.rejects(auth.start(company.domain), code('invalid_signer'));
    assert.equal(company.requests.filter(item => item.url === company.tokenEndpoint).length, 0);
    assert.deepEqual(await auth.list(), []);
  }
});

test('an identity signer that reuses the DPoP key is refused', async () => {
  const store = memoryStore(); const secrets = memorySecrets();
  const first = await setup({ store, secrets });
  await first.auth.start(first.company.domain);
  // Build an identity signer over the stored DPoP private key and reuse the same state.
  const dpop = JSON.parse(expectValue(secrets.map.get(store.raw.identities[first.company.issuer].dpopKeyRef)));
  const privateKey = await crypto.subtle.importKey('jwk', dpop, EC, false, ['sign']);
  const { kty, crv, x, y } = dpop;
  const signer = { kid: 'reused', jwk: { kty, crv, x, y, kid: 'reused' }, publicJwk: async () => ({ kty, crv, x, y }), sign: async (input:Uint8Array) => new Uint8Array(await crypto.subtle.sign(ES256, privateKey, new Uint8Array(input))) };
  const second = await setup({ store, secrets, signer });
  await assert.rejects(second.auth.start(second.company.domain), code('key_separation'));
  assert.equal(second.company.requests.filter(item => item.url === second.company.tokenEndpoint).length, 0);
});

test('token endpoint nonce challenge is retried once with fresh assertions and proof', { timeout: 10000 }, async () => {
  const { auth, company } = await setup();
  company.behavior.requireNonce = true;
  const outcome = await auth.start(company.domain);
  assert.equal(outcome.status, 'completed');
  assert.equal(company.proofs.length, 2); assert.equal(company.proofs[0].payload.nonce, undefined); assert.equal(company.proofs[1].payload.nonce, company.nonce);
  assert.notEqual(company.proofs[0].payload.jti, company.proofs[1].payload.jti);
  assert.equal(new Set(company.assertions.map(item => item.payload.jti)).size, 4);
  const { auth: again, company: stubborn } = await setup();
  stubborn.behavior.requireNonce = true; stubborn.behavior.rotateNonceEveryTime = true;
  await assert.rejects(again.start(stubborn.domain), code('use_dpop_nonce'));
  assert.equal(stubborn.requests.filter(item => item.url === stubborn.tokenEndpoint).length, 2);
});

test('token responses other than a signed-out DPoP session are rejected without persisting', async () => {
  for (const [override, expected] of [
    [{ token_type: 'Bearer' }, 'unsupported_token_type'],
    [{ signed_in: true }, 'invalid_response'],
    [{ scope: 'poppy:read' }, 'invalid_response'],
    [{ expires_in: 0 }, 'invalid_response'],
    [{ access_token: 7 }, 'invalid_response'],
  ] satisfies [Record<string,unknown>,string][]) {
    const { auth, company, store } = await setup();
    company.behavior.tokenOverride = override;
    await assert.rejects(auth.start(company.domain), code(expected), JSON.stringify(override));
    assert.deepEqual(store.raw.connections, {});
  }
});

test('token endpoint failures surface only a safe code', async () => {
  for (const [status, body, expected] of [
    [401, { error: 'invalid_client', error_description: 'secret-diagnostic' }, 'invalid_client'],
    [400, { error: 'evil<script>' }, 'token_error'],
    [429, { error: 'rate_limited' }, 'rate_limited'],
    [500, 'not json', 'token_error'],
    [302, {}, 'token_error'],
  ] satisfies [number,unknown,string][]) {
    const { auth, company } = await setup();
    company.behavior.tokenError = { status, body };
    const error = await auth.start(company.domain).catch(failure => failure);
    assert.ok(code(expected)(error), `${status} -> ${error.code}`);
    assert.equal(error.message.includes('secret-diagnostic'), false);
  }
  const { auth, company, transport } = await setup();
  transport.fail = true;
  await assert.rejects(auth.start(company.domain), code('discovery_failed'));
});

test('a lost token response is a transport failure and is not retried', async () => {
  const { auth, company, transport } = await setup();
  await auth.start(company.domain);
  const original = transport.fetch;
  let tokenCalls = 0;
  transport.fetch = async (request, options) => { if (request.url === company.tokenEndpoint) { tokenCalls++; throw new Error('socket hang up'); } return original(request, options); };
  await assert.rejects(auth.start(company.domain), code('transport_error'));
  assert.equal(tokenCalls, 1);
});

test('authorizedFetch sends DPoP with a fresh proof bound to method, URL and token, never Bearer', async () => {
  const { auth, company } = await setup();
  const { connection } = await auth.start(company.domain);
  const target = await auth.target(connection.id);
  const response = await auth.authorizedFetch(connection.id, conversations(company, '/cnv_1/messages?x=1'), target);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.body, JSON.stringify({ hello: 'world' })); assert.equal(body.session_id, connection.sessionId);
  const proof = company.proofs.at(-1);
  assert.equal(expectValue(proof).payload.htu, `${company.endpoint}/cnv_1/messages`); assert.equal(expectValue(proof).payload.htm, 'POST'); assert.ok(expectValue(proof).payload.ath);
  assert.equal(expectValue(proof).thumbprint, company.proofs[0].thumbprint);
  const resourceCalls = company.requests.filter(item => item.url.startsWith(company.endpoint));
  assert.ok(resourceCalls.every(item => expectValue(item.authorization).startsWith('DPoP ')));
  await auth.authorizedFetch(connection.id, new Request(company.endpoint), target, []);
  assert.notEqual(expectValue(company.proofs.at(-1)).payload.jti, expectValue(proof).payload.jti);
});

test('authorizedFetch adds a long poll\'s wait to the transport timeout, so a 30 s read is not aborted', async () => {
  const { auth, company, transport } = await setup();
  const { connection } = await auth.start(company.domain);
  const target = await auth.target(connection.id);
  const seen:unknown[] = []; const original = transport.fetch;
  transport.fetch = (request, options) => { if (request.url.startsWith(company.endpoint)) seen.push(options?.waitMs); return original(request, options); };
  for (const query of ['/cnv_1/events?wait=30', '/cnv_1/messages?cursor=evt_1&wait=10', '/cnv_1/events?wait=86400', '/cnv_1/events', '/cnv_1/events?wait=-5', '/cnv_1/events?wait=1e3'])
    assert.equal((await auth.authorizedFetch(connection.id, conversations(company, query), target)).status, 200, query);
  assert.deepEqual(seen, [30_000, 10_000, 300_000, 0, 0, 0]);
});

test('authorizedFetch refuses foreign targets, URLs and handles before sending anything', async () => {
  const { auth, company, transport } = await setup();
  const { connection } = await auth.start(company.domain);
  const target = await auth.target(connection.id);
  const before = transport.calls;
  for (const [id, request, wanted, expected, scopes] of [
    [connection.id, conversations(company), { ...target, endpoint: `https://api.${company.domain}/other` }, 'invalid_target'],
    [connection.id, conversations(company), { ...target, issuer: `${company.issuer}/` }, 'invalid_target'],
    [connection.id, conversations(company), { ...target, resource: company.endpoint }, 'invalid_target'],
    [connection.id, new Request(`${company.endpoint}-evil`), target, 'invalid_target'],
    [connection.id, new Request(`https://evil.test/poppy/conversations`), target, 'invalid_target'],
    [connection.id, new Request(`${company.endpoint}/x#frag`), target, 'invalid_target'],
    [connection.id, new Request(`${company.endpoint.replace('https', 'http')}/x`), target, 'invalid_target'],
    [connection.id, conversations(company), target, 'insufficient_scope', ['poppy:read']],
    ['__proto__', conversations(company), target, 'unknown_connection'],
    ['con_missing', conversations(company), target, 'unknown_connection'],
  ] satisfies [string,Request,ConversationTarget,string,string[]?][]) await assert.rejects(auth.authorizedFetch(id, request, wanted, scopes), code(expected), `${id} ${request.url} ${expected}`);
  assert.equal(transport.calls, before);
  assert.equal(await auth.get('__proto__'), null); assert.equal(await auth.get('constructor'), null);
  await assert.rejects(auth.target('toString'), code('unknown_connection'));
});

test('resource nonce challenge retries once with the body intact', { timeout: 10000 }, async () => {
  const { auth, company } = await setup();
  const { connection } = await auth.start(company.domain);
  const target = await auth.target(connection.id);
  company.behavior.requireNonce = true;
  const response = await auth.authorizedFetch(connection.id, conversations(company), target);
  assert.equal(response.status, 200); assert.equal((await response.json()).body, JSON.stringify({ hello: 'world' }));
  assert.equal(expectValue(company.proofs.at(-1)).payload.nonce, company.nonce);
  company.behavior.rotateNonceEveryTime = true;
  const resourceCalls = () => company.requests.filter(item => item.url.startsWith(company.endpoint)).length;
  const before = resourceCalls();
  const rejected = await auth.authorizedFetch(connection.id, conversations(company), target);
  assert.equal(rejected.status, 401); assert.match(expectValue(rejected.headers.get('www-authenticate')), /use_dpop_nonce/);
  assert.equal(resourceCalls() - before, 2);
});

test('invalid_token renews the signed-out session once and retries', { timeout: 10000 }, async () => {
  const { auth, company } = await setup();
  const { connection } = await auth.start(company.domain);
  const target = await auth.target(connection.id);
  company.tokens.clear();
  const response = await auth.authorizedFetch(connection.id, conversations(company), target);
  assert.equal(response.status, 200); assert.equal((await response.json()).session_id, connection.sessionId);
  const renewal = company.assertions.at(-1);
  assert.equal(expectValue(renewal).kind, 'session');
  assert.equal(company.tokens.size, 1);
  // A resource that keeps rejecting gets one renewal, then the 401 is returned as-is.
  company.behavior.resourceHandler = () => new Response(null, { status: 401, headers: { 'www-authenticate': 'DPoP error="invalid_token"' } });
  const tokenCalls = () => company.requests.filter(item => item.url === company.tokenEndpoint).length;
  const before = tokenCalls();
  const rejected = await auth.authorizedFetch(connection.id, conversations(company), target);
  assert.equal(rejected.status, 401); assert.equal(tokenCalls() - before, 1);
});

test('expired credentials renew before dispatch; an idle-expired signed-out Session is replaced by a new one', async () => {
  const { auth, company, clock, store, secrets } = await setup();
  const { connection } = await auth.start(company.domain);
  const target = await auth.target(connection.id);
  const tokenCalls = () => company.requests.filter(item => item.url === company.tokenEndpoint).length;
  clock.t += 3600_000;
  assert.equal((await auth.authorizedFetch(connection.id, conversations(company), target)).status, 200);
  assert.equal(tokenCalls(), 2);
  const extra = await auth.renew(connection.id, { resource: 'https://api.shop.test/other' });
  const oldRefs = Object.values(store.raw.connections[connection.id].slots).map(slot => slot.secretRef);
  assert.equal(oldRefs.length, 2); assert.equal(extra.status, 'completed');
  const forms = tokenForms(company);
  clock.t += 25 * 3600_000; // past the issuer's 24 h idle limit
  const response = await auth.authorizedFetch(connection.id, conversations(company), target);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.deepEqual(forms.map(form => [form.get('grant_type'), form.get('session_id')]), [['urn:ietf:params:oauth:grant-type:jwt-bearer', connection.sessionId], ['urn:ietf:params:oauth:grant-type:jwt-bearer', null]]);
  const current = store.raw.connections[connection.id];
  assert.notEqual(current.sessionId, connection.sessionId); assert.equal(body.session_id, current.sessionId); assert.equal(body.account, null);
  assert.deepEqual([current.status, current.generation, current.grantId], ['signed_out', connection.generation, null]);
  // The ended Session's credentials are gone, for every resource.
  assert.deepEqual(Object.keys(current.slots), [JSON.stringify([current.sessionId, null])]);
  for (const ref of oldRefs) assert.equal(secrets.map.has(ref), false);
  assert.equal(expectValue((await auth.get(connection.id))).sessionId, current.sessionId);
});

test('a refused replacement Session surfaces its error and keeps the slots', async () => {
  const { auth, company, clock, store } = await setup();
  const { connection } = await auth.start(company.domain);
  const target = await auth.target(connection.id);
  clock.t += 25 * 3600_000;
  let calls = 0; const original = company.handle;
  company.handle = async (request, init) => request.url === company.tokenEndpoint && ++calls === 2 ? new Response('{"error":"invalid_client"}', { status: 401 }) : original(request, init);
  const before = structuredClone(store.raw.connections[connection.id]);
  await assert.rejects(auth.authorizedFetch(connection.id, conversations(company), target), code('invalid_client'));
  assert.deepEqual(store.raw.connections[connection.id], before);
  // Any other refusal of the renewal is not a reason to start a new Session.
  calls = 0;
  company.handle = async (request, init) => request.url === company.tokenEndpoint && ++calls ? new Response('{"error":"invalid_grant"}', { status: 400 }) : original(request, init);
  await assert.rejects(auth.renew(connection.id), code('invalid_grant'));
  assert.equal(calls, 1);
});

test('application errors and transport failures are not retried', async () => {
  const { auth, company, transport } = await setup();
  const { connection } = await auth.start(company.domain);
  const target = await auth.target(connection.id);
  let calls = 0;
  company.behavior.resourceHandler = () => { calls++; return new Response('{"error":"server_error"}', { status: 500 }); };
  assert.equal((await auth.authorizedFetch(connection.id, conversations(company), target)).status, 500);
  assert.equal(calls, 1);
  transport.fail = true; const before = transport.calls;
  await assert.rejects(auth.authorizedFetch(connection.id, conversations(company), target), { name: 'TransportError' });
  assert.equal(transport.calls - before, 1);
});

test('state is bound to one namespace owner', async () => {
  const store = memoryStore(); const secrets = memorySecrets(); const signer = await makeSigner();
  const alice = await setup({ store, secrets, signer });
  const { connection } = await alice.auth.start(alice.company.domain);
  const bob = await setup({ store, secrets, signer, localUserId: 'bob' });
  await assert.rejects(bob.auth.start(bob.company.domain), code('owner_mismatch'));
  await assert.rejects(bob.auth.get(connection.id), code('owner_mismatch'));
  assert.equal(expectValue(store.raw.owner).localUserId, 'alice');
  assert.throws(() => createClientAuth({ ...alice.options, clientId: 'http://agent.test/agent.json' }), code('invalid_options'));
  assert.throws(() => createClientAuth({ ...alice.options, localUserId: '' }), code('invalid_options'));
});

test('a reset between token issuance and activation does not attach the session', async () => {
  const { auth, company, store, secrets } = await setup();
  await auth.start(company.domain);
  const transaction = store.transaction.bind(store);
  let reset = false;
  const originalFetch = company.handle;
  company.handle = async (request, options) => { const response = await originalFetch(request, options); if (request.url === company.tokenEndpoint && !reset) { reset = true; await transaction(state => { Object.assign(state, initialClientAuthState(), { owner: state.owner }); }); } return response; };
  await assert.rejects(auth.start(company.domain), code('state_changed'));
  assert.deepEqual(store.raw.connections, {});
  // The fenced-out session token lived in memory only, so nothing was persisted for it.
  assert.equal([...secrets.map.values()].filter(value => company.tokens.has(value)).length, 0);
});

test('a renewal answered for a different session is rejected and leaves the slots unchanged', async () => {
  const { auth, company, clock, store } = await setup();
  const { connection } = await auth.start(company.domain);
  const target = await auth.target(connection.id);
  clock.t += 3600_000;
  const slots = structuredClone(store.raw.connections[connection.id].slots);
  company.behavior.tokenOverride = { session_id: 'ses_someone_else' };
  await assert.rejects(auth.authorizedFetch(connection.id, conversations(company), target), code('invalid_response'));
  assert.deepEqual(store.raw.connections[connection.id].slots, slots);
});

test('a corrupted DPoP key fails as missing_key without quoting the secret', async () => {
  const { auth, company, store, secrets } = await setup();
  const { connection } = await auth.start(company.domain);
  const target = await auth.target(connection.id);
  const ref = store.raw.identities[company.issuer].dpopKeyRef;
  for (const corrupt of ['{"d":"SECRET-PREFIX', 'null', JSON.stringify({ ...JSON.parse(expectValue(secrets.map.get(ref))), d: 'SECRET-PREFIX' })]) {
    secrets.map.set(ref, corrupt);
    const error = await auth.authorizedFetch(connection.id, conversations(company), target).catch(failure => failure);
    assert.ok(code('missing_key')(error), corrupt); assert.equal(error.message.includes('SECRET'), false);
  }
});

test('token expiry counts from before dispatch', async () => {
  const { auth, company, clock, store } = await setup();
  const original = company.handle;
  company.handle = async (request, options) => { if (request.url === company.tokenEndpoint) clock.t += 50_000; return original(request, options); };
  const sentAt = clock.t;
  const { connection } = await auth.start(company.domain);
  assert.equal(Object.values(store.raw.connections[connection.id].slots)[0].expiresAt, sentAt + 3600_000);
});

// Direct Sign-In (spec 4.4-4.5)
const BROWSER = 'browser-session-0123456789abcdef';
const OTHER_BROWSER = 'another-browser-0123456789abcdef';
const exchanges = (company:FakeCompany) => company.requests.filter(item => item.url === company.tokenEndpoint).length;
async function beginAndApprove(auth:ClientAuth, company:FakeCompany, connectionId:string, { scopes = ['poppy:read'], account = 'acct_1', approve, deny, browserBinding = BROWSER, requiredExistingScopes }: {scopes?:string[];account?:string;approve?:string[]|null;deny?:boolean;browserBinding?:string;requiredExistingScopes?:string[]} = {}) {
  const { outcome, authorizationUrl } = await auth.beginSignIn(connectionId, { scopes, redirectUri: REDIRECT, browserBinding, force: true, requiredExistingScopes });
  assert.equal(outcome.status, 'pending'); assert.equal(outcome.nextAction, 'wait'); assert.ok(authorizationUrl);
  return { begun: outcome, authorizationUrl, callbackUrl: company.authorize(authorizationUrl, { account, approve, deny }) };
}
async function signIn(auth:ClientAuth, company:FakeCompany, connectionId:string, options:{scopes?:string[];account?:string;approve?:string[]|null;deny?:boolean;browserBinding?:string;requiredExistingScopes?:string[]} = {}) {
  const { callbackUrl } = await beginAndApprove(auth, company, connectionId, options);
  return auth.completeSignIn({ callbackUrl, browserBinding: options.browserBinding ?? BROWSER });
}

test('Direct Sign-In isolates two users with two connections each', async () => {
  const signer = await makeSigner();
  const alice = await setup({ signer }); const bob = await setup({ signer, localUserId: 'bob' });
  const accounts:{user:Awaited<ReturnType<typeof setup>>;id:string;account:string;sessionId:string|null}[] = [];
  for (const [user, account] of ([[alice, 'acct_alice_personal'], [alice, 'acct_alice_business'], [bob, 'acct_bob_1'], [bob, 'acct_bob_2']] satisfies [typeof alice,string][])) {
    const { connection } = await user.auth.start(user.company.domain);
    const outcome = await signIn(user.auth, user.company, connection.id, { scopes: ['poppy:read', 'poppy:write'], account });
    assert.equal(outcome.status, 'completed'); assert.equal(outcome.connection.status, 'signed_in');
    assert.deepEqual(outcome.connection.scopes, ['poppy:read', 'poppy:write']); assert.equal(outcome.connection.sessionId, connection.sessionId);
    accounts.push({ user, id: connection.id, account, sessionId: connection.sessionId });
  }
  for (const { user, id, account, sessionId } of accounts) {
    const response = await user.auth.authorizedFetch(id, conversations(user.company), await user.auth.target(id), ['poppy:write']);
    const body = await response.json();
    assert.equal(body.account, account); assert.equal(body.session_id, sessionId);
  }
  assert.equal((await alice.auth.list()).length, 2); assert.equal((await bob.auth.list()).length, 2);
  assert.equal(await alice.auth.get(accounts[2].id), null);
  for (const user of [alice, bob]) {
    const persisted = JSON.stringify(user.store.raw);
    for (const secret of [...user.company.tokens.keys(), ...user.company.grants.keys(), ...user.company.codes.keys(), BROWSER]) assert.equal(persisted.includes(expectValue(secret)), false);
    assert.equal(Object.keys(user.store.raw.grants).length, 2);
  }
  // A callback for Bob's sign-in is unknown to Alice's namespace.
  const { connection } = await bob.auth.start(bob.company.domain);
  const { callbackUrl } = await beginAndApprove(bob.auth, bob.company, connection.id);
  await assert.rejects(alice.auth.completeSignIn({ callbackUrl, browserBinding: BROWSER }), code('invalid_callback'));
});

test('Direct Sign-In after the Session idle-expired binds to a replacement Session and succeeds', async () => {
  const { auth, company, store, clock } = await setup();
  const { connection } = await auth.start(company.domain);
  // A fresh credential proves a live Session: beginSignIn sends nothing.
  const sent = exchanges(company);
  await auth.beginSignIn(connection.id, { scopes: ['poppy:read'], redirectUri: REDIRECT, browserBinding: BROWSER });
  assert.equal(exchanges(company), sent);
  clock.t += 25 * 3600_000;
  const forms = tokenForms(company);
  const outcome = await signIn(auth, company, connection.id);
  assert.deepEqual([outcome.status, outcome.connection.status], ['completed', 'signed_in']);
  const sessionId = store.raw.connections[connection.id].sessionId;
  assert.notEqual(sessionId, connection.sessionId); assert.equal(outcome.connection.sessionId, sessionId);
  assert.deepEqual(forms.map(form => [form.get('grant_type'), form.get('session_id')]), [
    ['urn:ietf:params:oauth:grant-type:jwt-bearer', connection.sessionId], ['urn:ietf:params:oauth:grant-type:jwt-bearer', null], ['authorization_code', sessionId]]);
  assert.equal(expectValue(company.sessions.get(sessionId)).account, 'acct_1');
});

test('Direct Sign-In after both the Session and the Account Token ended binds to a new signed-out Session', async () => {
  const { auth, company, store, clock, id, sessionId } = await signedIn();
  clock.t += 25 * 3600_000;
  for (const grant of company.grants.values()) grant.revoked = true;
  const forms = tokenForms(company);
  const outcome = await signIn(auth, company, id);
  assert.deepEqual([outcome.status, outcome.connection.status], ['completed', 'signed_in']);
  const current = store.raw.connections[id].sessionId;
  assert.notEqual(current, sessionId);
  assert.deepEqual(forms.map(form => [form.get('grant_type'), form.get('session_id')]), [
    ['refresh_token', sessionId], ['urn:ietf:params:oauth:grant-type:jwt-bearer', sessionId], ['urn:ietf:params:oauth:grant-type:jwt-bearer', null], ['authorization_code', current]]);
});

test('the authorization request and code exchange carry PKCE, state, issuer and session', async () => {
  const { auth, company, store } = await setup();
  const { connection } = await auth.start(company.domain);
  let exchange!:URLSearchParams;
  const original = company.handle;
  company.handle = async (request, options) => { if (request.url === company.tokenEndpoint) exchange = new URLSearchParams(await request.clone().text()); return original(request, options); };
  const { authorizationUrl, callbackUrl } = await beginAndApprove(auth, company, connection.id, { scopes: ['poppy:read', 'poppy:write'] });
  const url = new URL(authorizationUrl);
  assert.equal(url.origin + url.pathname, company.authorizationEndpoint);
  assert.equal(url.searchParams.get('client_id'), CLIENT_ID); assert.equal(url.searchParams.get('redirect_uri'), REDIRECT);
  assert.equal(url.searchParams.get('scope'), 'poppy:read poppy:write'); assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(expectValue(url.searchParams.get('state')).length >= 43);
  assert.equal(JSON.stringify(store.raw).includes(expectValue(url.searchParams.get('state'))), false);
  await auth.completeSignIn({ callbackUrl, browserBinding: BROWSER });
  assert.equal(expectValue(exchange).get('grant_type'), 'authorization_code'); assert.equal(expectValue(exchange).get('session_id'), connection.sessionId);
  assert.equal(expectValue(exchange).get('redirect_uri'), REDIRECT); assert.equal(expectValue(exchange).get('client_id'), CLIENT_ID);
  assert.equal(expectValue(exchange).has('assertion'), false); assert.ok(expectValue(exchange).get('client_assertion'));
  assert.equal(expectValue(company.proofs.at(-1)).thumbprint, company.proofs[0].thumbprint);
});

test('beginSignIn rejects bad input before creating an operation', async () => {
  const { auth, company, store, options } = await setup();
  const { connection } = await auth.start(company.domain);
  const good = { scopes: ['poppy:read'], redirectUri: REDIRECT, browserBinding: BROWSER };
  for (const [input, expected] of [
    [{ ...good, scopes: [] }, 'invalid_scope'],
    [{ ...good, scopes: ['poppy:read', 'poppy:read'] }, 'invalid_scope'],
    [{ ...good, scopes: ['admin'] }, 'invalid_scope'],
    [{ ...good, scopes: 'poppy:read' }, 'invalid_scope'],
    [{ ...good, redirectUri: 'https://agent.test/oauth/callback/' }, 'invalid_redirect'],
    [{ ...good, redirectUri: 'https://evil.test/cb' }, 'invalid_redirect'],
    [{ ...good, browserBinding: 'short' }, 'invalid_binding'],
    [undefined, 'invalid_scope'],
  ] satisfies [unknown,string][]) {
    // @ts-expect-error Deliberately malformed input must reach SDK validation.
    await assert.rejects(auth.beginSignIn(connection.id, input), code(expected), JSON.stringify(input));
  }
  await assert.rejects(auth.beginSignIn('con_missing', good), code('unknown_connection'));
  const operations = Object.keys(store.raw.operations).length;
  delete expectValue(store.raw.connections[connection.id].metadata.document.auth).direct;
  const resolve = options.metadata.resolveCompany;
  options.metadata.resolveCompany = async domain => { const fresh = structuredClone(await resolve(domain)); delete expectValue(fresh.document.auth).direct; return fresh; };
  await assert.rejects(auth.beginSignIn(connection.id, good), code('direct_unavailable'));
  assert.equal(Object.keys(store.raw.operations).length, operations);
});

test('wrong callbacks leave the operation untouched; duplicates return the recorded result', async () => {
  const { auth, company } = await setup();
  const { connection } = await auth.start(company.domain);
  const { begun, callbackUrl } = await beginAndApprove(auth, company, connection.id);
  const tweak = (change:(url:URL)=>void) => { const url = new URL(callbackUrl); change(url); return url.href; };
  for (const [url, browserBinding] of [
    [callbackUrl, OTHER_BROWSER],
    [tweak(url => url.searchParams.set('iss', `${company.issuer}/`)), BROWSER],
    [tweak(url => url.searchParams.delete('iss')), BROWSER],
    [tweak(url => url.searchParams.set('state', 'forged-state-value')), BROWSER],
    [tweak(url => url.searchParams.append('code', 'second')), BROWSER],
    [tweak(url => { url.pathname = '/oauth/other'; }), BROWSER],
    [tweak(url => { url.host = 'evil.test'; }), BROWSER],
    [tweak(url => { url.hash = 'x'; }), BROWSER],
    [tweak(url => url.searchParams.set('error', 'access_denied')), BROWSER],
    [tweak(url => url.searchParams.delete('code')), BROWSER],
    ['not a url', BROWSER],
  ]) await assert.rejects(auth.completeSignIn({ callbackUrl: url, browserBinding }), code('invalid_callback'), url);
  assert.equal(exchanges(company), 1);
  assert.equal(expectValue((await auth.operation(begun.operationId))).status, 'pending');
  const done = await auth.completeSignIn({ callbackUrl, browserBinding: BROWSER });
  assert.equal(done.status, 'completed'); assert.equal(exchanges(company), 2);
  const again = await auth.completeSignIn({ callbackUrl, browserBinding: BROWSER });
  assert.deepEqual(again, done); assert.deepEqual(await auth.operation(begun.operationId), done);
  assert.equal(exchanges(company), 2);
  // Even after completion, another browser learns nothing.
  await assert.rejects(auth.completeSignIn({ callbackUrl, browserBinding: OTHER_BROWSER }), code('invalid_callback'));
  assert.equal(await auth.operation('op_missing'), null);
});

test('concurrent callbacks exchange the code exactly once', async () => {
  const { auth, company } = await setup();
  const { connection } = await auth.start(company.domain);
  const { callbackUrl } = await beginAndApprove(auth, company, connection.id);
  const results = await Promise.all([1, 2, 3].map(() => auth.completeSignIn({ callbackUrl, browserBinding: BROWSER })));
  assert.equal(exchanges(company), 2);
  assert.equal(results.filter(item => item.status === 'completed').length, 1);
  assert.ok(results.every(item => item.status === 'completed' || (item.status === 'pending' && item.nextAction === 'wait')));
});

test('denied, cancelled and expired sign-ins are terminal and keep the signed-out session', async () => {
  const { auth, company, clock, store, secrets } = await setup();
  const { connection } = await auth.start(company.domain);
  const slots = structuredClone(store.raw.connections[connection.id].slots);
  const denied = await signIn(auth, company, connection.id, { deny: true });
  assert.equal(denied.status, 'denied'); assert.equal(denied.error, 'access_denied'); assert.equal(denied.connection.status, 'signed_out');
  const cancel = await beginAndApprove(auth, company, connection.id);
  assert.equal((await auth.cancelSignIn(cancel.begun.operationId)).status, 'cancelled');
  assert.equal((await auth.completeSignIn({ callbackUrl: cancel.callbackUrl, browserBinding: BROWSER })).status, 'cancelled');
  await assert.rejects(auth.cancelSignIn('op_missing'), code('unknown_operation'));
  const late = await beginAndApprove(auth, company, connection.id);
  clock.t += 10 * 60_000;
  const expired = await auth.completeSignIn({ callbackUrl: late.callbackUrl, browserBinding: BROWSER });
  assert.equal(expired.status, 'expired'); assert.equal(expired.nextAction, 'sign_in');
  const stale = await beginAndApprove(auth, company, connection.id);
  clock.t += 10 * 60_000;
  assert.deepEqual((await auth.recover()).map(item => [item.operationId, item.status]), [[stale.begun.operationId, 'expired']]);
  assert.equal(exchanges(company), 1);
  assert.deepEqual(store.raw.connections[connection.id].slots, slots);
  assert.equal(store.raw.connections[connection.id].status, 'signed_out');
  // Every terminal sign-in removed its verifier; only the DPoP key remains (Session Tokens are memory-only).
  assert.equal(secrets.map.size, 1);
});

test('partial consent keeps the previous grant and parks the new Account Token for revocation', async () => {
  const { auth, company, store, secrets } = await setup();
  const { connection } = await auth.start(company.domain);
  const first = await signIn(auth, company, connection.id, { scopes: ['poppy:read'] });
  assert.equal(first.status, 'completed');
  const before = structuredClone(store.raw.connections[connection.id]);
  const partial = await signIn(auth, company, connection.id, { scopes: ['poppy:read', 'poppy:write'], approve: ['poppy:write'] });
  assert.equal(partial.status, 'failed'); assert.equal(partial.error, 'replacement_rejected');
  assert.deepEqual(partial.missingScopes, ['poppy:read']); assert.deepEqual(partial.connection.scopes, ['poppy:read']);
  assert.deepEqual(store.raw.connections[connection.id], before);
  const [cleanup] = Object.values(store.raw.cleanup);
  assert.equal(cleanup.status, 'pending'); assert.equal(cleanup.revocationEndpoint, `${company.issuer}/revoke`);
  assert.equal(secrets.map.get(cleanup.secretRef), [...company.grants.keys()].at(-1));
  assert.equal((await auth.authorizedFetch(connection.id, conversations(company), await auth.target(connection.id), ['poppy:read'])).status, 200);
  // The parked token is revoked on request while the connection stays signed in.
  const cleaned = await auth.retryCleanup(connection.id);
  assert.deepEqual([cleaned.cleanup, cleaned.connection.status], ['complete', 'signed_in']);
  assert.deepEqual(company.revocations.map(item => item.token), [[...company.grants.keys()].at(-1)]);
  assert.deepEqual(store.raw.cleanup, {}); assert.equal(secrets.map.has(cleanup.secretRef), false);
  // First-time partial consent retains useful access.
  const other = await auth.start(company.domain);
  const none = await signIn(auth, company, other.connection.id, { scopes: ['poppy:read', 'poppy:write'], approve: ['poppy:write'] });
  assert.deepEqual([none.status, none.missingScopes, none.connection.status], ['completed', ['poppy:read'], 'signed_in']);
  assert.deepEqual(none.grantedScopes, ['poppy:write']);
});

test('a scope upgrade replaces the grant and parks the old one; old slots stop being selectable', async () => {
  const { auth, company, store, secrets } = await setup();
  const { connection } = await auth.start(company.domain);
  await signIn(auth, company, connection.id, { scopes: ['poppy:read'] });
  const oldGrant = store.raw.connections[connection.id].grantId;
  const oldSlots = Object.values(store.raw.connections[connection.id].slots).map(slot => slot.secretRef);
  const upgraded = await signIn(auth, company, connection.id, { scopes: ['poppy:read', 'poppy:write'] });
  assert.equal(upgraded.status, 'completed'); assert.deepEqual(upgraded.connection.scopes, ['poppy:read', 'poppy:write']);
  const record = store.raw.connections[connection.id];
  assert.notEqual(record.grantId, oldGrant); assert.equal(store.raw.grants[expectValue(oldGrant)], undefined);
  assert.deepEqual(Object.keys(store.raw.cleanup), [`cln_${oldGrant}`]);
  assert.equal(Object.keys(record.slots).length, 1);
  assert.ok(oldSlots.every(ref => !secrets.map.has(ref)));
});

test('failed replacement keeps the old connection; a different account on the same session is refused', async () => {
  const { auth, company } = await setup();
  const old = await auth.start(company.domain);
  await signIn(auth, company, old.connection.id, { account: 'acct_a', scopes: ['poppy:read'] });
  const oldAccount = async () => (await (await auth.authorizedFetch(old.connection.id, conversations(company), await auth.target(old.connection.id), ['poppy:read'])).json()).account;
  // Same session, different account: the Company refuses and nothing changes locally.
  const mismatch = await signIn(auth, company, old.connection.id, { account: 'acct_b', scopes: ['poppy:read'] });
  assert.deepEqual([mismatch.status, mismatch.error, mismatch.connection.status], ['failed', 'account_mismatch', 'signed_in']);
  assert.equal(await oldAccount(), 'acct_a');
  const candidate = await auth.start(company.domain);
  assert.equal((await signIn(auth, company, candidate.connection.id, { account: 'acct_b', deny: true })).status, 'denied');
  assert.equal(await oldAccount(), 'acct_a');
  const replaced = await signIn(auth, company, candidate.connection.id, { account: 'acct_b', scopes: ['poppy:read'] });
  assert.equal(replaced.status, 'completed'); assert.equal(await oldAccount(), 'acct_a');
});

test('token responses that are not a usable signed-in grant fail and park any Account Token', async () => {
  for (const [override, expected, parked] of [
    [{ token_type: 'Bearer' }, 'unsupported_token_type', 1],
    [{ signed_in: false }, 'invalid_response', 1],
    [{ session_id: 'ses_other' }, 'invalid_response', 1],
    [{ scope: 'poppy:read poppy:write' }, 'invalid_response', 1],
    [{ refresh_token: undefined }, 'invalid_response', 0],
  ] satisfies [Record<string,unknown>,string,number][]) {
    const { auth, company, store } = await setup();
    const { connection } = await auth.start(company.domain);
    company.behavior.tokenOverride = override;
    const outcome = await signIn(auth, company, connection.id);
    assert.deepEqual([outcome.status, outcome.error, outcome.connection.status], ['failed', expected, 'signed_out'], JSON.stringify(override));
    assert.deepEqual(store.raw.grants, {});
    assert.equal(Object.keys(store.raw.cleanup).length, parked, JSON.stringify(override));
  }
});

test('a lost exchange response is uncertain and the code is never resent', async () => {
  const { auth, company, transport, store } = await setup();
  const { connection } = await auth.start(company.domain);
  const slots = structuredClone(store.raw.connections[connection.id].slots);
  const { begun, callbackUrl } = await beginAndApprove(auth, company, connection.id);
  const original = transport.fetch;
  transport.fetch = async (request, options) => {
    const response = await original(request, options);
    if (request.url === company.tokenEndpoint) throw new Error('socket hang up');
    return response;
  };
  const lost = await auth.completeSignIn({ callbackUrl, browserBinding: BROWSER });
  assert.deepEqual([lost.status, lost.error, lost.nextAction], ['uncertain', 'lost_response', 'sign_in']);
  transport.fetch = original;
  assert.deepEqual(await auth.completeSignIn({ callbackUrl, browserBinding: BROWSER }), lost);
  assert.deepEqual(await auth.operation(begun.operationId), lost);
  assert.equal(exchanges(company), 2);
  assert.deepEqual(store.raw.connections[connection.id].slots, slots); assert.equal(store.raw.connections[connection.id].status, 'signed_out');
  assert.equal((await auth.authorizedFetch(connection.id, conversations(company), await auth.target(connection.id))).status, 200);
  // A definite rejection is a failure, not uncertainty.
  const reused = await beginAndApprove(auth, company, connection.id);
  expectValue(company.codes.get(new URL(reused.callbackUrl).searchParams.get('code'))).used = true;
  const rejected = await auth.completeSignIn({ callbackUrl: reused.callbackUrl, browserBinding: BROWSER });
  assert.deepEqual([rejected.status, rejected.error], ['failed', 'invalid_grant']);
});

test('a crash during activation recovers as uncertain without replaying the code', async () => {
  const store = memoryStore(); const secrets = memorySecrets();
  const first = await setup({ store, secrets });
  const { connection } = await first.auth.start(first.company.domain);
  const slots = structuredClone(store.raw.connections[connection.id].slots);
  const { begun, callbackUrl } = await beginAndApprove(first.auth, first.company, connection.id);
  const original = first.company.handle;
  first.company.handle = async (request, options) => { const response = await original(request, options); if (request.url === first.company.tokenEndpoint) store.crashNext = true; return response; };
  await assert.rejects(first.auth.completeSignIn({ callbackUrl, browserBinding: BROWSER }), /crash/);
  // Restart: a new client over the same durable state.
  const restarted = createClientAuth({ ...first.options });
  assert.equal(expectValue((await restarted.operation(begun.operationId))).status, 'pending');
  const recovered = await restarted.recover();
  assert.deepEqual(recovered.map(item => [item.operationId, item.status, item.nextAction]), [[begun.operationId, 'uncertain', 'sign_in']]);
  assert.deepEqual(await restarted.recover(), []);
  assert.equal((await restarted.completeSignIn({ callbackUrl, browserBinding: BROWSER })).status, 'uncertain');
  assert.equal(exchanges(first.company), 2);
  assert.deepEqual(store.raw.grants, {}); assert.deepEqual(store.raw.connections[connection.id].slots, slots);
  // The staged Account Token exists but is unreachable from state.
  const staged = [...secrets.map].filter(([, value]) => first.company.grants.has(value)).map(([ref]) => ref);
  assert.equal(staged.length, 1); assert.equal(JSON.stringify(store.raw).includes(staged[0]), false);
});

test('a secret store failure after the exchange is reported as uncertain', async () => {
  const { auth, company, secrets, store } = await setup();
  const { connection } = await auth.start(company.domain);
  const { callbackUrl } = await beginAndApprove(auth, company, connection.id);
  const stage = secrets.stage;
  secrets.stage = async secret => { if (company.grants.has(secret)) throw new Error('disk full'); return stage(secret); };
  const outcome = await auth.completeSignIn({ callbackUrl, browserBinding: BROWSER });
  assert.deepEqual([outcome.status, outcome.error], ['uncertain', 'storage_error']);
  assert.deepEqual(store.raw.grants, {}); assert.deepEqual(store.raw.cleanup, {});
});

test("recovery leaves another invocation's live exchange intact", async () => {
  const { auth, company, options, store } = await setup();
  const { connection } = await auth.start(company.domain);
  const { callbackUrl } = await beginAndApprove(auth, company, connection.id);
  const original = company.handle;
  company.handle = async (request, init) => { const response = await original(request, init); if (request.url === company.tokenEndpoint) await createClientAuth(options).recover(); return response; };
  const outcome = await auth.completeSignIn({ callbackUrl, browserBinding: BROWSER });
  assert.equal(outcome.status, 'completed');
  assert.equal(store.raw.connections[connection.id].status, 'signed_in');
  assert.equal(Object.keys(store.raw.cleanup).length, 0);
});

test('sign-in requests the conversation resource so the signed-in token works there', async () => {
  const { auth, company, store } = await setup({ conversationResource: 'https://api.shop.test/poppy' });
  const { connection } = await auth.start(company.domain);
  const target = await auth.target(connection.id);
  assert.equal(target.resource, 'https://api.shop.test/poppy');
  const { authorizationUrl, callbackUrl } = await beginAndApprove(auth, company, connection.id);
  assert.equal(new URL(authorizationUrl).searchParams.get('resource'), target.resource);
  assert.equal((await auth.completeSignIn({ callbackUrl, browserBinding: BROWSER })).status, 'completed');
  assert.deepEqual(Object.keys(store.raw.connections[connection.id].slots), [JSON.stringify([connection.sessionId, target.resource])]);
  const body = await (await auth.authorizedFetch(connection.id, conversations(company), target, ['poppy:read'])).json();
  assert.equal(body.account, 'acct_1');
});

async function signedIn(options:Parameters<typeof setup>[0] = {}) {
  const context = await setup(options);
  const { connection } = await context.auth.start(context.company.domain);
  assert.equal((await signIn(context.auth, context.company, connection.id, { scopes: ['poppy:read', 'poppy:write'] })).status, 'completed');
  return { ...context, id: connection.id, sessionId: connection.sessionId, target: await context.auth.target(connection.id) };
}
const grantOf = (store:{raw:ClientAuthState}, id:string) => store.raw.grants[expectValue(store.raw.connections[id].grantId)];
const loseTokenResponses = (transport:ReturnType<typeof fakeTransport>, company:FakeCompany) => {
  const original = transport.fetch;
  transport.fetch = async (request, init) => { const response = await original(request, init); if (request.url === company.tokenEndpoint) throw new Error('socket hang up'); return response; };
  return () => { transport.fetch = original; };
};

test('refresh rotates the Account Token once for parallel requests and keeps other resources\' slots', async () => {
  const { auth, company, store, secrets, clock, id, sessionId, target } = await signedIn();
  const forms = tokenForms(company);
  const other = 'https://api.shop.test/other';
  const extra = await auth.renew(id, { resource: other, scopes: ['poppy:read'] });
  assert.deepEqual([extra.status, extra.connection.status], ['completed', 'signed_in']);
  assert.deepEqual([forms[0].get('grant_type'), forms[0].get('resource'), forms[0].get('scope'), forms[0].get('session_id')], ['refresh_token', other, 'poppy:read', sessionId]);
  assert.equal(forms[0].has('assertion'), false); assert.ok(forms[0].get('client_assertion'));
  const before = structuredClone(store.raw);
  const grant = grantOf({ raw: before }, id);
  const oldToken = secrets.map.get(grant.secretRef);
  const otherKey = JSON.stringify([sessionId, other]), defaultKey = JSON.stringify([sessionId, null]);
  clock.t += 3600_000;
  const responses = await Promise.all([1, 2, 3, 4].map(() => auth.authorizedFetch(id, conversations(company), target, ['poppy:write'])));
  assert.deepEqual(responses.map(response => response.status), [200, 200, 200, 200]);
  assert.equal(forms.length, 2, 'one refresh for four parallel requests');
  assert.equal(forms[1].get('refresh_token'), oldToken); assert.equal(forms[1].has('resource'), false); assert.equal(forms[1].has('scope'), false);
  const after = grantOf(store, id);
  assert.notEqual(after.secretRef, grant.secretRef); assert.equal(secrets.map.has(grant.secretRef), false);
  assert.equal(expectValue(company.grants.get(expectValue(secrets.map.get(after.secretRef)))).rotated, false);
  assert.deepEqual([after.operationId, after.generation, after.status], [null, grant.generation + 1, 'active']);
  const slots = store.raw.connections[id].slots;
  assert.deepEqual(Object.keys(slots).sort(), [defaultKey, otherKey].sort());
  assert.deepEqual(slots[otherKey], before.connections[id].slots[otherKey]);
  assert.equal(secrets.map.has(before.connections[id].slots[defaultKey].secretRef), false);
  // Completed renewals do not accumulate.
  assert.equal(Object.values(store.raw.operations).filter(op => op.kind === 'renew').length, 1);
});

test('terminal start and sign-in operations are pruned beyond a bound; uncertain and pending ones stay', async () => {
  const { auth, company, transport, store, clock, id } = await signedIn();
  const signedInOp = expectValue(Object.values(store.raw.operations).find(op => op.kind === 'sign_in')).id;
  const { callbackUrl } = await beginAndApprove(auth, company, id);
  const restore = loseTokenResponses(transport, company);
  const uncertain = await auth.completeSignIn({ callbackUrl, browserBinding: BROWSER });
  restore();
  assert.equal(uncertain.status, 'uncertain');
  const { outcome: pending } = await auth.beginSignIn(id, { scopes: ['poppy:read'], redirectUri: REDIRECT, browserBinding: BROWSER, force: true });
  const starts = [];
  for (let i = 0; i < 103; i++) { clock.t += 2000; starts.push((await auth.start(company.domain)).operationId); } // paced under the discovery fetch limit
  const kept = Object.values(store.raw.operations).filter(op => op.kind !== 'renew');
  assert.equal(kept.filter(op => op.phase === 'terminal' && op.status !== 'uncertain').length, 101, 'the bound, plus the operation just added');
  assert.equal(await auth.operation(signedInOp), null); assert.equal(await auth.operation(starts[0]), null);
  assert.equal(expectValue((await auth.operation(expectValue(starts.at(-1))))).status, 'completed');
  assert.equal(expectValue((await auth.operation(uncertain.operationId))).status, 'uncertain');
  assert.equal(expectValue((await auth.operation(pending.operationId))).status, 'pending');
  assert.equal((await auth.signOut(id)).cleanup, 'uncertain', 'pruning never hides an uncertain exchange');
});

test('one rotation per grant: a second process gets the pending operation', async () => {
  const { auth, company, options, id } = await signedIn();
  const second = createClientAuth(options);
  let inner:AuthOutcome | undefined; const original = company.handle;
  company.handle = async (request, init) => { if (request.url === company.tokenEndpoint && !inner) inner = await second.renew(id); return original(request, init); };
  const outcome = await auth.renew(id);
  assert.equal(outcome.status, 'completed');
  assert.deepEqual([expectValue(inner).status, expectValue(inner).nextAction, expectValue(inner).operationId], ['pending', 'wait', outcome.operationId]);
  assert.equal(exchanges(company), 3);
  assert.equal((await second.renew(id)).status, 'completed');
});

test('renew validates input and a definite refusal releases the grant', async () => {
  const { auth, company, store, id } = await signedIn();
  for (const [input, expected] of [[{ scopes: ['admin'] }, 'invalid_scope'], [{ scopes: [] }, 'invalid_scope'], [{ scopes: 'poppy:read' }, 'invalid_scope'], [{ resource: 'not a url' }, 'invalid_target']] satisfies [unknown,string][]) {
    // @ts-expect-error Deliberately malformed renewal input must reach SDK validation.
    await assert.rejects(auth.renew(id, input), code(expected), JSON.stringify(input));
  }
  await assert.rejects(auth.renew('con_missing'), code('unknown_connection'));
  assert.equal(exchanges(company), 2);
  company.behavior.tokenError = { status: 400, body: { error: 'invalid_session', error_description: 'secret-diagnostic' } };
  const refused = await auth.renew(id);
  assert.deepEqual([refused.status, refused.error, refused.connection.status], ['failed', 'invalid_session', 'signed_in']);
  assert.equal(JSON.stringify(refused).includes('secret-diagnostic'), false);
  assert.deepEqual([grantOf(store, id).operationId, grantOf(store, id).status], [null, 'active']);
  company.behavior.tokenError = null;
  assert.equal((await auth.renew(id)).status, 'completed');
  // A signed-out connection renews with its assertion and cannot ask for account scopes.
  const { connection } = await auth.start(company.domain);
  const slot = Object.values(store.raw.connections[connection.id].slots)[0];
  assert.equal((await auth.renew(connection.id)).status, 'completed');
  assert.notEqual(Object.values(store.raw.connections[connection.id].slots)[0].secretRef, slot.secretRef);
  await assert.rejects(auth.renew(connection.id, { scopes: ['poppy:read'] }), code('invalid_scope'));
});

test('an idle-expired signed-in Session is replaced by refreshing without session_id, never by a new sign-in', async () => {
  const { auth, company, store, secrets, clock, id, sessionId, target } = await signedIn();
  const forms = tokenForms(company);
  const grant = grantOf(store, id), oldToken = secrets.map.get(grant.secretRef);
  const oldSlots = Object.values(store.raw.connections[id].slots).map(slot => slot.secretRef);
  const codes = company.codes.size;
  clock.t += 25 * 3600_000; // past the issuer's 24 h idle limit
  const response = await auth.authorizedFetch(id, conversations(company), target, ['poppy:write']);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.deepEqual(forms.map(form => [form.get('grant_type'), form.get('session_id'), form.get('refresh_token')]), [['refresh_token', sessionId, oldToken], ['refresh_token', null, oldToken]]);
  const current = store.raw.connections[id];
  assert.notEqual(current.sessionId, sessionId);
  assert.deepEqual([body.session_id, body.account, current.status], [current.sessionId, 'acct_1', 'signed_in']);
  assert.equal(expectValue(company.sessions.get(current.sessionId)).account, 'acct_1', 'the new Session is bound to the same account');
  assert.deepEqual(Object.keys(current.slots), [JSON.stringify([current.sessionId, null])]);
  for (const ref of oldSlots) assert.equal(secrets.map.has(ref), false);
  const after = grantOf(store, id);
  assert.deepEqual([after.status, after.operationId, after.generation], ['active', null, grant.generation + 1]);
  assert.notEqual(secrets.map.get(after.secretRef), oldToken);
  assert.equal(company.codes.size, codes, 'no sign-in was started');
});

test('replacement-Session refresh: only a definite invalid_session retries, and a lost answer is never resent', async () => {
  const { auth, company, clock, id } = await signedIn();
  clock.t += 25 * 3600_000;
  // A 5xx is not a definite refusal: the Account Token may have been used, so nothing is retried.
  company.behavior.tokenError = { status: 500, body: { error: 'invalid_session' } };
  const forms = tokenForms(company);
  assert.deepEqual([(await auth.renew(id)).status, forms.length], ['uncertain', 1]);
  const other = await signedIn();
  other.clock.t += 25 * 3600_000;
  let calls = 0; const original = other.transport.fetch;
  other.transport.fetch = async (request, init) => { const response = await original(request, init); if (request.url === other.company.tokenEndpoint && ++calls === 2) throw new Error('socket hang up'); return response; };
  const lost = await other.auth.renew(other.id);
  assert.deepEqual([lost.status, lost.error, lost.connection.status, lost.connection.sessionId, calls], ['uncertain', 'lost_response', 'uncertain', other.sessionId, 2]);
  await assert.rejects(other.auth.renew(other.id), code('grant_uncertain'));
  assert.equal(calls, 2);
  // A replacement answered for the ended Session is malformed.
  const third = await signedIn();
  third.clock.t += 25 * 3600_000;
  third.company.behavior.tokenOverride = { session_id: third.sessionId };
  const bad = await third.auth.renew(third.id);
  assert.deepEqual([bad.status, bad.error, third.store.raw.connections[third.id].sessionId], ['failed', 'invalid_response', third.sessionId]);
});

test('a lost rotation response is uncertain; the old Account Token is never resent', async () => {
  const { auth, company, transport, store, secrets, clock, id, target } = await signedIn();
  const oldToken = secrets.map.get(grantOf(store, id).secretRef);
  const restore = loseTokenResponses(transport, company);
  const lost = await auth.renew(id);
  restore();
  assert.deepEqual([lost.status, lost.error, lost.nextAction, lost.connection.status], ['uncertain', 'lost_response', 'sign_in', 'uncertain']);
  assert.equal(expectValue(company.grants.get(expectValue(oldToken))).rotated, true, 'the issuer did rotate');
  const sent = exchanges(company);
  await assert.rejects(auth.renew(id), code('grant_uncertain'));
  clock.t += 3600_000;
  await assert.rejects(auth.authorizedFetch(id, conversations(company), target, ['poppy:read']), code('grant_uncertain'));
  assert.equal(exchanges(company), sent);
  // Only a fresh sign-in recovers; it retires the uncertain grant.
  const fresh = await signIn(auth, company, id, { scopes: ['poppy:read'], requiredExistingScopes: ['poppy:read'] });
  assert.deepEqual([fresh.status, fresh.connection.status], ['completed', 'signed_in']);
  assert.equal(Object.values(store.raw.cleanup).length, 1);
  // Revoking the token we hold cannot prove the unseen successor is gone.
  const out = await auth.signOut(id);
  assert.deepEqual([out.connection.status, out.cleanup], ['disconnected', 'uncertain']);
  assert.equal(company.revocations.length, 2); assert.ok(company.revocations.some(item => item.token === oldToken));
});

test('presenting an already-rotated Account Token revokes the grant; the session continues signed out', async () => {
  const { auth, company, transport, store, secrets, options, id, target } = await signedIn();
  // A copy of the state from before the rotation, as a process that missed it would hold.
  const staleStore = memoryStore(store.raw); const staleSecrets = memorySecrets();
  for (const [ref, value] of secrets.map) staleSecrets.map.set(ref, value);
  const restore = loseTokenResponses(transport, company);
  assert.equal((await auth.renew(id)).status, 'uncertain');
  restore();
  const stale = createClientAuth({ ...options, store: staleStore, secrets: staleSecrets });
  const reused = await stale.renew(id);
  assert.deepEqual([reused.status, reused.error, reused.connection.status, reused.connection.scopes], ['failed', 'invalid_grant', 'signed_out', []]);
  assert.ok([...company.grants.values()].every(grant => grant.revoked), 'reuse revoked the successor too');
  assert.deepEqual(staleStore.raw.grants, {}); assert.deepEqual(staleStore.raw.connections[id].slots, {});
  const codes = company.codes.size;
  const response = await stale.authorizedFetch(id, conversations(company), target);
  assert.equal(response.status, 200); assert.equal((await response.json()).account, null);
  await assert.rejects(stale.authorizedFetch(id, conversations(company), target, ['poppy:read']), code('insufficient_scope'));
  assert.equal(company.codes.size, codes, 'no sign-in was started');
  assert.equal((await stale.renew(id)).connection.status, 'signed_out');
});

test('sign-out disconnects first, revokes with a client assertion and never signs in again', async () => {
  const { auth, company, store, secrets, id, target } = await signedIn();
  const refreshToken = secrets.map.get(grantOf(store, id).secretRef);
  const generation = store.raw.connections[id].generation;
  const out = await auth.signOut(id);
  assert.deepEqual([out.connection.status, out.cleanup, out.connection.generation, out.connection.scopes], ['disconnected', 'complete', generation + 1, []]);
  assert.deepEqual(company.revocations, [{ token: refreshToken, hint: 'refresh_token', dpop: false }]);
  const assertion = company.assertions.at(-1);
  assert.deepEqual([expectValue(assertion).kind, expectValue(assertion).payload.aud, expectValue(assertion).payload.sub], ['client', company.issuer, CLIENT_ID]);
  assert.deepEqual(store.raw.grants, {}); assert.deepEqual(store.raw.cleanup, {}); assert.deepEqual(store.raw.connections[id].slots, {});
  assert.equal(secrets.map.size, 1, 'only the DPoP key remains');
  await assert.rejects(auth.authorizedFetch(id, conversations(company), target), code('disconnected'));
  await assert.rejects(auth.renew(id), code('disconnected'));
  await assert.rejects(auth.beginSignIn(id, { scopes: ['poppy:read'], redirectUri: REDIRECT, browserBinding: BROWSER }), code('sign_in_unavailable'));
  assert.deepEqual(await auth.recover(), []);
  const again = await auth.signOut(id);
  assert.deepEqual(again, out); assert.equal(company.revocations.length, 1);
  await assert.rejects(auth.signOut('con_missing'), code('unknown_connection'));
});

test('sign-out cancels a pending sign-in; its late callback cannot connect', async () => {
  const { auth, company } = await setup();
  const { connection } = await auth.start(company.domain);
  const { begun, callbackUrl } = await beginAndApprove(auth, company, connection.id);
  assert.equal((await auth.signOut(connection.id)).cleanup, 'complete');
  assert.equal(expectValue((await auth.operation(begun.operationId))).status, 'cancelled');
  assert.equal((await auth.completeSignIn({ callbackUrl, browserBinding: BROWSER })).status, 'cancelled');
  assert.equal(exchanges(company), 1);
});

test('revocation failure leaves the connection disconnected with cleanup pending until retry', async () => {
  const { auth, company, transport, store, secrets, id } = await signedIn();
  company.behavior.revokeStatus = 503;
  const out = await auth.signOut(id);
  assert.deepEqual([out.connection.status, out.cleanup], ['disconnected', 'pending']);
  const [parked] = Object.values(store.raw.cleanup);
  assert.equal(parked.status, 'pending'); assert.ok(secrets.map.has(parked.secretRef));
  transport.fail = true;
  assert.equal((await auth.retryCleanup(id)).cleanup, 'pending');
  transport.fail = false; company.behavior.revokeStatus = 200;
  const done = await auth.retryCleanup(id);
  assert.deepEqual([done.connection.status, done.cleanup], ['disconnected', 'complete']);
  assert.equal(company.revocations.length, 2); assert.equal(secrets.map.has(parked.secretRef), false);
  // A parked token whose secret was lost can never be revoked; that is uncertain, not complete.
  const other = await signedIn();
  const ref = grantOf(other.store, other.id).secretRef;
  other.company.behavior.revokeStatus = 503;
  await other.auth.signOut(other.id);
  other.secrets.map.delete(ref);
  assert.equal((await other.auth.retryCleanup(other.id)).cleanup, 'uncertain');
});

test('sign-out during a refresh wins; the late rotated token is parked and revoked', async () => {
  const { auth, company, store, secrets, id } = await signedIn();
  let during!:SignOutOutcome; const original = company.handle;
  company.handle = async (request, init) => { const response = await original(request, init); if (request.url === company.tokenEndpoint && !during) during = await auth.signOut(id); return response; };
  const late = await auth.renew(id);
  assert.deepEqual([late.status, late.error, late.connection.status], ['failed', 'state_changed', 'disconnected']);
  assert.deepEqual([expectValue(during).connection.status, expectValue(during).cleanup], ['disconnected', 'pending']);
  const [parked] = Object.values(store.raw.cleanup);
  assert.ok(company.grants.has(expectValue(secrets.map.get(parked.secretRef))), 'the rotated token awaits revocation');
  assert.deepEqual(store.raw.connections[id].slots, {});
  assert.equal((await auth.retryCleanup(id)).cleanup, 'complete');
  assert.equal(secrets.map.size, 1);
});

test('sign-out during a code exchange wins; the late grant cannot activate', async () => {
  const { auth, company, store, secrets } = await setup();
  const { connection } = await auth.start(company.domain);
  const { callbackUrl } = await beginAndApprove(auth, company, connection.id);
  let during: SignOutOutcome|null|undefined; const original = company.handle;
  company.handle = async (request, init) => { const response = await original(request, init); if (request.url === company.tokenEndpoint && !during) during = await auth.signOut(connection.id); return response; };
  const outcome = await auth.completeSignIn({ callbackUrl, browserBinding: BROWSER });
  assert.deepEqual([outcome.status, outcome.error, outcome.connection.status], ['failed', 'state_changed', 'disconnected']);
  assert.equal(expectValue(during).cleanup, 'pending');
  assert.deepEqual(store.raw.grants, {}); assert.equal(Object.keys(store.raw.cleanup).length, 1);
  assert.equal((await auth.retryCleanup(connection.id)).cleanup, 'complete');
  assert.equal(secrets.map.size, 1);
});

test('a Session replaced during a code exchange wins; the late grant cannot activate', async () => {
  const { auth, company, store, clock } = await setup();
  const { connection } = await auth.start(company.domain);
  const { callbackUrl } = await beginAndApprove(auth, company, connection.id);
  let during!:AuthOutcome;let raced=false; const original = company.handle;
  company.handle = async (request, init) => {
    const response = await original(request, init);
    // The answer arrives after the old Session ended and a renewal replaced it (flag first: the renewal comes through here too).
    if (request.url === company.tokenEndpoint && !raced) { raced = true; clock.t += 25 * 3600_000; during = await auth.renew(connection.id); }
    return response;
  };
  const outcome = await auth.completeSignIn({ callbackUrl, browserBinding: BROWSER });
  assert.equal(expectValue(during).status, 'completed'); assert.notEqual(expectValue(during).connection.sessionId, connection.sessionId);
  assert.deepEqual([outcome.status, outcome.error, outcome.connection.status], ['failed', 'state_changed', 'signed_out']);
  assert.deepEqual(store.raw.grants, {}); assert.equal(Object.keys(store.raw.cleanup).length, 1, 'the late grant is parked for revocation');
  assert.equal(store.raw.connections[connection.id].sessionId, expectValue(during).connection.sessionId);
});

test('a crash after the refresh response: staged finishes on recovery, unstaged is uncertain', async () => {
  for (const [crashIn, expected] of [[1, 'uncertain'], [2, 'completed']] satisfies [number,string][]) {
    const store = memoryStore(); const secrets = memorySecrets();
    const { auth, company, options, id, target } = await signedIn({ store, secrets });
    const original = company.handle;
    company.handle = async (request, init) => { const response = await original(request, init); if (request.url === company.tokenEndpoint) store.crashIn = crashIn; return response; };
    await assert.rejects(auth.renew(id), /crash/);
    company.handle = original;
    const [operation] = Object.values(store.raw.operations).filter(op => op.kind === 'renew');
    assert.equal(operation.phase, crashIn === 1 ? 'dispatched' : 'staged');
    const restarted = createClientAuth(options);
    const recovered = await restarted.recover();
    assert.deepEqual(recovered.map(item => [item.operationId, item.status]), [[operation.id, expected]]);
    assert.equal(exchanges(company), 3, 'recovery never refreshes again');
    if (expected === 'completed') {
      assert.equal(grantOf(store, id).secretRef, expectValue(operation.staged).refreshRef);
      assert.equal((await restarted.authorizedFetch(id, conversations(company), target, ['poppy:read'])).status, 200);
    } else {
      assert.deepEqual([grantOf(store, id).status, store.raw.connections[id].status], ['uncertain', 'uncertain']);
    }
  }
});

test('a non-OAuth refresh answer after the issuer rotated is uncertain and never resent', async () => {
  for (const reply of [
    () => new Response('<html>Bad Gateway</html>', { status: 502 }),
    () => new Response(JSON.stringify({ error: 'server_error' }), { status: 500, headers: { 'content-type': 'application/json' } }),
    () => new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 503, headers: { 'content-type': 'application/json' } }),
    () => new Response(JSON.stringify({ error: 'proxy_said_no' }), { status: 400, headers: { 'content-type': 'application/json' } }),
  ]) {
    const { auth, company, store, secrets, id } = await signedIn();
    const oldToken = secrets.map.get(grantOf(store, id).secretRef);
    const original = company.handle;
    company.handle = async (request, init) => { const response = await original(request, init); return request.url === company.tokenEndpoint ? reply() : response; };
    const outcome = await auth.renew(id);
    assert.deepEqual([outcome.status, outcome.error, outcome.connection.status], ['uncertain', 'lost_response', 'uncertain'], String(reply()));
    assert.equal(expectValue(company.grants.get(expectValue(oldToken))).rotated, true);
    await assert.rejects(auth.renew(id), code('grant_uncertain'));
    assert.equal(exchanges(company), 3, 'no second refresh');
  }
});

test('a secret store read failure releases the refresh claim before anything is sent', async () => {
  const { auth, company, store, secrets, id } = await signedIn();
  const read = secrets.read;
  secrets.read = async ref => { if (ref === grantOf(store, id).secretRef) throw new Error('vault locked'); return read(ref); };
  const outcome = await auth.renew(id);
  assert.deepEqual([outcome.status, outcome.error, outcome.connection.status], ['failed', 'storage_error', 'signed_in']);
  assert.deepEqual([grantOf(store, id).operationId, grantOf(store, id).status], [null, 'active']);
  assert.equal(exchanges(company), 2);
  secrets.read = read;
  assert.equal((await auth.renew(id)).status, 'completed');
});

test('a crash before the refresh is sent recovers as failed and keeps the grant usable', async () => {
  const store = memoryStore(); const secrets = memorySecrets();
  const { auth, company, options, id } = await signedIn({ store, secrets });
  const read = secrets.read;
  secrets.read = async ref => { if (ref === grantOf(store, id).secretRef) store.crashIn = 1; return read(ref); };
  await assert.rejects(auth.renew(id), /crash/);
  secrets.read = read;
  const [operation] = Object.values(store.raw.operations).filter(op => op.kind === 'renew');
  assert.equal(operation.phase, 'prepared');
  const restarted = createClientAuth(options);
  assert.deepEqual((await restarted.recover()).map(item => [item.operationId, item.status, item.error]), [[operation.id, 'failed', 'interrupted']]);
  assert.deepEqual([grantOf(store, id).operationId, grantOf(store, id).status, store.raw.connections[id].status], [null, 'active', 'signed_in']);
  assert.equal(exchanges(company), 2, 'nothing was sent');
  assert.equal((await restarted.renew(id)).status, 'completed');
});

test('a 5xx or garbled code exchange answer is uncertain and the code is not resent', async () => {
  for (const reply of [
    () => new Response('<html>Bad Gateway</html>', { status: 502 }),
    () => new Response('{"access_token": tok', { status: 200, headers: { 'content-type': 'application/json' } }),
    () => new Response(JSON.stringify({ access_token: 'tok_x', token_type: 'DPoP', expires_in: -1, scope: 'poppy:read', session_id: 'ses_x', signed_in: true }), { status: 200, headers: { 'content-type': 'application/json' } }),
  ]) {
    const { auth, company, store } = await setup();
    const { connection } = await auth.start(company.domain);
    const { callbackUrl } = await beginAndApprove(auth, company, connection.id);
    const original = company.handle;
    company.handle = async (request, init) => { const response = await original(request, init); return request.url === company.tokenEndpoint ? reply() : response; };
    const outcome = await auth.completeSignIn({ callbackUrl, browserBinding: BROWSER });
    assert.deepEqual([outcome.status, outcome.error, outcome.connection.status], ['uncertain', 'lost_response', 'signed_out']);
    assert.deepEqual(await auth.completeSignIn({ callbackUrl, browserBinding: BROWSER }), outcome);
    assert.equal(exchanges(company), 2, 'exactly one exchange');
    assert.deepEqual(store.raw.grants, {});
  }
});

// Another process settles the prepared refresh while this one reads the Account Token.
async function interruptedRefresh(interrupt:'recover'|'signOut') {
  {
    const { auth, company, store, secrets, options, id } = await signedIn();
    // A failed revocation keeps the Account Token's secret, so only the phase guard can stop the send.
    company.behavior.revokeStatus = 503;
    const read = secrets.read;
    secrets.read = async ref => {
      if (ref === grantOf(store, id)?.secretRef) { secrets.read = read; const other = createClientAuth(options); await (interrupt === 'recover' ? other.recover() : other.signOut(id)); }
      return read(ref);
    };
    const sent = exchanges(company);
    const outcome = await auth.renew(id);
    assert.equal(exchanges(company), sent + (interrupt === 'recover' ? 1 : 0));
    if (interrupt === 'recover') {
      assert.equal(outcome.status, 'completed');
      assert.deepEqual([grantOf(store, id).operationId, grantOf(store, id).status, store.raw.connections[id].status], [null, 'active', 'signed_in']);
      assert.equal((await auth.renew(id)).status, 'completed');
    } else {
      assert.deepEqual([outcome.status, outcome.connection.status], ['cancelled', 'disconnected']);
      assert.equal(store.raw.connections[id].status, 'disconnected');
    }
  }
}
test('a live refresh survives recovery before dispatch', () => interruptedRefresh('recover'));
test('a refresh that sign-out cancelled before dispatch is never sent', () => interruptedRefresh('signOut'));

test('connection exposes the verified organization, including a domain that differs from the lookup', async () => {
  const { auth, company } = await setup();
  const { connection } = await auth.start(company.domain);
  assert.deepEqual(connection.organization, { name: 'shop', domain: company.domain });
  assert.deepEqual(expectValue((await auth.get(connection.id))).organization, connection.organization);
});

test('after a restart the memory-only Session Token is renewed, not read from the SecretStore', async () => {
  const { auth, options, company, store, secrets } = await setup();
  const { connection } = await auth.start(company.domain);
  const restarted = createClientAuth(options);
  const response = await restarted.authorizedFetch(connection.id, conversations(company), await restarted.target(connection.id));
  assert.equal(response.status, 200);
  assert.equal([...secrets.map.values()].some(value => company.tokens.has(value)), false);
  assert.equal(JSON.stringify(store.raw).includes(expectValue([...company.tokens.keys()][0])), false);
});

test('a rate-limited signed-out renewal surfaces retryAfterMs, is not retried and blocks the next request; auth errors are not masked', async () => {
  const { auth, company, clock } = await setup();
  const { connection } = await auth.start(company.domain);
  const target = await auth.target(connection.id);
  clock.t += 3_600_000;
  const handle = company.handle; let tokenRequests = 0;
  company.handle = async (request, init) => {
    if (request.url !== company.tokenEndpoint) return handle(request, init);
    tokenRequests++; return new Response('{"error":"rate_limited"}', { status: 429, headers: { 'retry-after': '30' } });
  };
  await assert.rejects(auth.authorizedFetch(connection.id, conversations(company), target), error => error instanceof AuthFailure && error.retryAfterMs === 30000);
  assert.equal(tokenRequests, 1);
  clock.t += 30_000; // the wait is over
  company.handle = async (request, init) => request.url === company.tokenEndpoint ? new Response('{"error":"invalid_client"}', { status: 401 }) : handle(request, init);
  await assert.rejects(auth.authorizedFetch(connection.id, conversations(company), target), error => error instanceof AuthFailure && error.retryAfterMs === undefined);
});

test('duplicate member names in a token response are rejected', async () => {
  const { auth, company } = await setup();
  const handle = company.handle;
  company.handle = async (request, init) => {
    const response = await handle(request, init);
    if (request.url !== company.tokenEndpoint) return response;
    return new Response((await response.text()).replace(/^\{/, '{"scope":"","scope":"x",'), { status: 200, headers: response.headers });
  };
  await assert.rejects(auth.start(company.domain), code('invalid_response'));
});

test('a rate-limited signed-in refresh surfaces retryAfterMs and no token request is sent before it elapses', async () => {
  const { auth, company, clock, id, target } = await signedIn();
  clock.t += 25 * 3600_000;
  const handle = company.handle; let tokenRequests = 0;
  company.handle = async (request, init) => {
    if (request.url !== company.tokenEndpoint) return handle(request, init);
    tokenRequests++; return new Response('{"error":"rate_limited"}', { status: 429, headers: { 'retry-after': '30' } });
  };
  await assert.rejects(auth.authorizedFetch(id, conversations(company), target), error => error instanceof AuthFailure && error.retryAfterMs === 30000);
  assert.equal(tokenRequests, 1);
  clock.t += 10_000;
  await assert.rejects(auth.authorizedFetch(id, conversations(company), target), error => error instanceof AuthFailure && error.code === 'rate_limited' && error.retryAfterMs === 20000);
  assert.equal(tokenRequests, 1, 'no token request during the wait');
  assert.equal(expectValue((await auth.get(id))).status, 'signed_in', 'a 429 is a definite rejection and leaves the grant usable');
  company.handle = handle; clock.t += 20_000;
  assert.equal((await auth.authorizedFetch(id, conversations(company), target)).status, 200);
});

test('public renew() returns retryAfterMs and sends no token request inside the Retry-After window', async () => {
  const { auth, company, clock, id } = await signedIn();
  const handle = company.handle; let tokenRequests = 0;
  company.handle = async (request, init) => {
    if (request.url !== company.tokenEndpoint) return handle(request, init);
    tokenRequests++; return new Response('{"error":"rate_limited"}', { status: 429, headers: { 'retry-after': '30' } });
  };
  const outcome = await auth.renew(id);
  assert.equal(outcome.status, 'failed'); assert.equal(outcome.retryAfterMs, 30000);
  clock.t += 10_000;
  await assert.rejects(auth.renew(id), error => error instanceof AuthFailure && error.code === 'rate_limited' && error.retryAfterMs === 20000);
  assert.equal(tokenRequests, 1, 'no token request during the wait');
  company.handle = handle; clock.t += 20_000;
  assert.equal((await auth.renew(id)).status, 'completed');
});

test('inside a Retry-After window renew() still reports disconnected, not rate_limited', async () => {
  const { auth, company, id } = await signedIn();
  const handle = company.handle;
  company.handle = async (request, init) => request.url === company.tokenEndpoint ? new Response('{"error":"rate_limited"}', { status: 429, headers: { 'retry-after': '30' } }) : handle(request, init);
  assert.equal((await auth.renew(id)).retryAfterMs, 30000);
  await auth.signOut(id);
  await assert.rejects(auth.renew(id), error => error instanceof AuthFailure && error.code === 'disconnected');
});

test('a signed-out renew() with scopes reports invalid_scope inside a Retry-After window', async () => {
  const { auth, company, clock } = await setup();
  const { connection } = await auth.start(company.domain);
  clock.t += 3_600_000;
  const handle = company.handle;
  company.handle = async (request, init) => request.url === company.tokenEndpoint ? new Response('{"error":"rate_limited"}', { status: 429, headers: { 'retry-after': '30' } }) : handle(request, init);
  await assert.rejects(auth.renew(connection.id), error => error instanceof AuthFailure && error.retryAfterMs === 30000);
  await assert.rejects(auth.renew(connection.id, { scopes: ['x'] }), error => error instanceof AuthFailure && error.code === 'invalid_scope');
});

test('a huge Retry-After survives restart without truncation', async () => {
  const { auth, company, clock, id, options, store } = await signedIn();
  const handle = company.handle;
  company.handle = async (request, init) => request.url === company.tokenEndpoint ? new Response('{"error":"rate_limited"}', { status: 429, headers: { 'retry-after': '9'.repeat(30) } }) : handle(request, init);
  assert.ok(expectValue((await auth.renew(id)).retryAfterMs) > 3_600_000);
  assert.equal(store.raw.connections[id].notBefore, (BigInt(clock.t) + BigInt('9'.repeat(30)) * 1000n).toString());
  company.handle = handle; clock.t += 3_600_000;
  await assert.rejects(createClientAuth(options).renew(id), error => error instanceof AuthFailure && error.code === 'rate_limited' && expectValue(error.retryAfterMs) > 3_600_000);
});

test('a host SecretStore ref that looks like a memory ref still reaches the host store', async () => {
  const secrets = memorySecrets(); const stage = secrets.stage;
  secrets.stage = async secret => { const ref = `mem:${await stage(secret)}`; secrets.map.set(ref, expectValue(secrets.map.get(ref.slice(4)))); return ref; };
  const { auth, company, store } = await setup({ secrets });
  const { connection } = await auth.start(company.domain);
  const key = store.raw.identities[company.issuer].dpopKeyRef;
  assert.ok(key.startsWith('mem:'));
  const response = await auth.authorizedFetch(connection.id, conversations(company), await auth.target(connection.id));
  assert.equal(response.status, 200);
});

for (const method of ['device', 'mediated'] as const) {
  test(`${method}-only company supports conversation challenges, partial grants, upgrades and renewal`, async () => {
    const env = await setup({ method }); const { company, clock, store } = env;
    env.options.trustedInput = { collect: async () => ({ password: 'private-password' }) };
    const auth = createClientAuth(env.options), { connection } = await auth.start(company.domain);
    const requirement = await auth.authorization(connection.id, ['poppy:read', 'poppy:write']);
    assert.deepEqual(requirement.methods, [{ method, scopes: ['poppy:read', 'poppy:write'] }]);
    assert.deepEqual(requirement.missingScopes, ['poppy:read', 'poppy:write']);
    company.signInBehavior.scopes = ['poppy:read'];
    let begun = await auth.beginSignIn(connection.id, { method, scopes: requirement.requiredScopes });
    let result = begun.outcome;
    if (method === 'device') { clock.t += 5000; result = await createClientAuth(env.options).continueSignIn(result.operationId); }
    assert.deepEqual([result.status, result.grantedScopes, result.missingScopes], ['completed', ['poppy:read'], ['poppy:write']]);
    let oldGrant = store.raw.connections[connection.id].grantId;
    assert.equal((await auth.authorization(connection.id, ['poppy:read'])).sufficient, true);
    assert.equal((await auth.beginSignIn(connection.id, { method, scopes: ['poppy:read'] })).outcome.status, 'completed');
    begun = await auth.beginSignIn(connection.id, { method, scopes: ['poppy:read', 'poppy:write'] }); result = begun.outcome;
    if (method === 'device') { clock.t += 5000; result = await auth.continueSignIn(result.operationId); }
    assert.equal(result.status, 'completed'); assert.deepEqual(result.missingScopes, ['poppy:write']);
    assert.notEqual(store.raw.connections[connection.id].grantId, oldGrant, 'partial replacement preserving all old access activates');
    oldGrant = store.raw.connections[connection.id].grantId;
    company.signInBehavior.scopes = ['poppy:write'];
    begun = await auth.beginSignIn(connection.id, { method, scopes: ['poppy:read', 'poppy:write'] }); result = begun.outcome;
    if (method === 'device') { clock.t += 5000; result = await auth.continueSignIn(result.operationId); }
    assert.equal(result.error, 'replacement_rejected'); assert.equal(store.raw.connections[connection.id].grantId, oldGrant);
    begun = await auth.beginSignIn(connection.id, { method, scopes: ['poppy:read', 'poppy:write'], requiredExistingScopes: [] }); result = begun.outcome;
    if (method === 'device') { clock.t += 5000; result = await auth.continueSignIn(result.operationId); }
    assert.deepEqual([result.status, result.connection.scopes], ['completed', ['poppy:write']], 'explicit replacement, never a union');
    assert.equal((await auth.renew(connection.id)).status, 'completed');
    assert.equal((await auth.signOut(connection.id)).connection.status, 'disconnected');
    assert.equal(JSON.stringify(store.raw).includes('private-password'), false);
  });
  for (const terminal of ['denial', 'expiry', 'cancel', 'malformed']) test(`${method} ${terminal} is terminal and disposes private inputs`, async () => {
    const env = await setup({ method }), input = { password: 'private-password' };
    env.options.trustedInput = { collect: async () => input };
    env.company.signInBehavior.codeRequired = true;
    if (terminal === 'denial') env.company.signInBehavior.status = 'access_denied';
    if (terminal === 'malformed') {
      const handle = env.company.handle;
      env.company.handle = async (request, options) => request.url === `${env.company.issuer}/${method === 'device' ? 'device' : 'sign-in'}` ? new Response('{}', { status: 200 }) : handle(request, options);
    }
    let auth = createClientAuth(env.options), { connection } = await auth.start(env.company.domain);
    let { outcome } = await auth.beginSignIn(connection.id, { method, scopes: ['poppy:read'] });
    auth = createClientAuth(env.options);
    if (terminal === 'cancel') outcome = await auth.cancelSignIn(outcome.operationId);
    if (terminal === 'expiry') { env.clock.t += 601_000; await auth.recover(); outcome = await auth.continueSignIn(outcome.operationId); }
    if (terminal === 'denial' && method === 'device') { env.clock.t += 5000; outcome = await auth.continueSignIn(outcome.operationId); }
    assert.equal(outcome.status, { denial: 'denied', expiry: 'expired', cancel: 'cancelled', malformed: method === 'device' ? 'uncertain' : 'failed' }[terminal]);
    if (method === 'mediated') assert.deepEqual(input, {}, 'trusted input object cleared on every terminal path');
    assert.equal(JSON.stringify(env.store.raw).includes('private-password'), false);
    assert.equal([...env.secrets.map.values()].some(value => env.company.devices.has(value)), false, 'terminal device code removed');
  });
}

test('Device pending/slowdown and exact Retry-After deadline survive restart', async () => {
  const env = await setup({ method: 'device' }), { connection } = await env.auth.start(env.company.domain);
  const { outcome } = await env.auth.beginSignIn(connection.id, { method: 'device', scopes: ['poppy:read'] });
  const count = exchanges(env.company);
  assert.equal((await env.auth.continueSignIn(outcome.operationId)).retryAfterMs, 5000); assert.equal(exchanges(env.company), count);
  env.company.signInBehavior.status = 'slow_down'; env.clock.t += 5000;
  assert.equal((await env.auth.continueSignIn(outcome.operationId)).retryAfterMs, 10000);
  const auth = createClientAuth(env.options);
  env.clock.t += 9000; assert.equal((await auth.continueSignIn(outcome.operationId)).retryAfterMs, 1000);
  env.company.signInBehavior.status = 'authorization_pending'; env.clock.t += 1000;
  assert.equal((await auth.continueSignIn(outcome.operationId)).status, 'pending');
  env.company.signInBehavior.status = 'approved'; env.clock.t += 10000;
  assert.equal((await auth.continueSignIn(outcome.operationId)).status, 'completed');
});

test('Mediated challenge uses correlated operation/session; wrong-code attempts end without retaining credentials', async () => {
  const env = await setup({ method: 'mediated' }), inputs:Record<string,string>[] = [], prompts:Parameters<TrustedInput["collect"]>[0][] = [];
  env.company.signInBehavior.codeRequired = true;
  env.options.trustedInput = { collect: async request => { prompts.push(request); const values:Record<string,string> = request.challenge ? { code: 'wrong-code' } : { password: 'password-secret' }; inputs.push(values); return values; } };
  let auth = createClientAuth(env.options); const { connection } = await auth.start(env.company.domain);
  let { outcome } = await auth.beginSignIn(connection.id, { method: 'mediated', scopes: ['poppy:read'] });
  const id = outcome.operationId;
  auth = createClientAuth(env.options);
  for (let i = 0; i < 3; i++) outcome = await auth.continueSignIn(id);
  assert.equal(outcome.status, 'denied', JSON.stringify(outcome)); assert.equal(prompts.length, 4);
  assert.ok(prompts.slice(1).every(prompt => prompt.operationId === id && expectValue(prompt.challenge).id === expectValue(prompts[1].challenge).id));
  assert.ok(inputs.every(value => !Object.keys(value).length));
  assert.equal(JSON.stringify(env.store.raw).includes('password-secret'), false);
  assert.equal(JSON.stringify(outcome).includes('wrong-code'), false);
});

test('anonymous sign-in creates regular connection/session and discards its ephemeral identity/key', async () => {
  const env = await setup(), { auth, company, store, secrets } = env;
  const anonymous = await auth.start(company.domain, { anonymous: true });
  const old = structuredClone(store.raw.connections[anonymous.connection.id]);
  assert.deepEqual(store.raw.identities, {});
  const begun = await auth.beginSignIn(old.id, { scopes: ['poppy:read'], redirectUri: REDIRECT, browserBinding: BROWSER });
  assert.notEqual(begun.outcome.connection.id, old.id); assert.notEqual(begun.outcome.connection.sessionId, old.sessionId);
  assert.notEqual(store.raw.identities[company.issuer].userId, old.userId);
  assert.equal(secrets.map.has(old.dpopKeyRef), false); assert.equal(expectValue((await auth.get(old.id))).status, 'disconnected');
  const callbackUrl = company.authorize(expectValue(begun.authorizationUrl), { account: 'acct_1' });
  assert.equal((await auth.completeSignIn({ callbackUrl, browserBinding: BROWSER })).status, 'completed');
});

for (const method of ['direct', 'device', 'mediated'] as const) test(`${method} staged sign-in survives activation failure and renews its memory-only Session Token after restart`, async () => {
  const env = await setup({ method }); env.options.trustedInput = { collect: async () => ({ password: 'private-password' }) };
  const auth = createClientAuth(env.options), { connection } = await auth.start(env.company.domain);
  let operationId: string, complete;
  if (method === 'direct') { const begun = await beginAndApprove(auth, env.company, connection.id); operationId = begun.begun.operationId; complete = () => auth.completeSignIn({ callbackUrl: begun.callbackUrl, browserBinding: BROWSER }); }
  else if (method === 'device') { const begun = await auth.beginSignIn(connection.id, { method, scopes: ['poppy:read'] }); operationId = begun.outcome.operationId; env.clock.t += 5000; complete = () => auth.continueSignIn(operationId); }
  else complete = async () => (await auth.beginSignIn(connection.id, { method, scopes: ['poppy:read'] })).outcome;
  const stage = env.secrets.stage;
  env.secrets.stage = async secret => {
    const ref = await stage(secret);
    if (env.company.grants.has(secret)) { assert.deepEqual(await createClientAuth(env.options).recover(), [], 'live owner remains alive through secret staging'); env.store.crashIn = 2; }
    return ref;
  };
  await assert.rejects(complete(), /crash/);
  const operation = Object.values(env.store.raw.operations).find(row => row.phase === 'staged'); assert.ok(operation);
  operationId ??= operation.id;
  env.secrets.stage = stage;
  const restart = createClientAuth(env.options), recovered = await restart.recover();
  assert.deepEqual(recovered.map(result => [result.operationId, result.status]), [[operationId, 'completed']]);
  const count = exchanges(env.company);
  assert.equal((await restart.authorizedFetch(connection.id, conversations(env.company), await restart.target(connection.id), ['poppy:read'])).status, 200);
  assert.equal(exchanges(env.company), count + 1, 'durable Account Token renews vanished memory token');
});

test('Mediated cancel while awaiting trusted input prevents credential dispatch and clears input', async () => {
  const env = await setup({ method: 'mediated' }); let deliver!:(values:Record<string,string>)=>void,requested!:(id:string)=>void;
  const ready = new Promise<string>(resolve => { requested = resolve; });
  env.options.trustedInput = { collect: async request => { requested(request.operationId); return new Promise<Record<string,string>>(resolve => { deliver = resolve; }); } };
  const auth = createClientAuth(env.options), { connection } = await auth.start(env.company.domain);
  const active = auth.beginSignIn(connection.id, { method: 'mediated', scopes: ['poppy:read'] }), operationId = await ready;
  assert.equal((await auth.cancelSignIn(operationId)).status, 'cancelled');
  const credentials = { password: 'must-not-send' }; expectValue(deliver)(credentials);
  assert.equal((await active).outcome.status, 'cancelled'); assert.deepEqual(credentials, {});
  assert.equal(env.company.requests.filter(request => request.url.startsWith(`${env.company.issuer}/sign-in`)).length, 0);
});

for (const body of ['<html>rate limited</html>', '{"error":"invalid_grant"}']) test(`Mediated ${body.startsWith('<') ? 'HTML 429' : '503 after grant'} keeps Retry-After across restart`, async () => {
  const env = await setup({ method: 'mediated' }); env.options.trustedInput = { collect: async () => ({ password: 'private-password' }) };
  const auth = createClientAuth(env.options), { connection } = await auth.start(env.company.domain), handle = env.company.handle;
  env.company.handle = async (request, options) => {
    const result = await handle(request, options);
    return request.url === `${env.company.issuer}/sign-in` ? new Response(body, { status: body.startsWith('<') ? 429 : 503, headers: { 'retry-after': '7200' } }) : result;
  };
  const { outcome } = await auth.beginSignIn(connection.id, { method: 'mediated', scopes: ['poppy:read'] });
  assert.equal(outcome.status, body.startsWith('<') ? 'failed' : 'uncertain');
  env.company.handle = handle; env.clock.t += 3600000;
  await assert.rejects(createClientAuth(env.options).renew(connection.id), error => error instanceof AuthFailure && error.code === 'rate_limited' && error.retryAfterMs === 3600000);
});

test('Mediated rejects cross-operation challenge substitution and redacts thrown trusted input errors', async () => {
  const env = await setup({ method: 'mediated' }); env.company.signInBehavior.codeRequired = true;
  env.options.trustedInput = { collect: async ({ challenge }):Promise<Record<string,string>> => challenge ? { code: 'wrong' } : { password: 'private-password' } };
  const auth = createClientAuth(env.options), { connection } = await auth.start(env.company.domain);
  const first = await auth.beginSignIn(connection.id, { method: 'mediated', scopes: ['poppy:read'] }), handle = env.company.handle;
  env.company.handle = async (request, options) => {
    const result = await handle(request, options);
    if (!request.url.includes('/sign-in/')) return result;
    const body = await result.json(); body.sign_in_id = 'another-operation'; return new Response(JSON.stringify(body));
  };
  assert.equal((await auth.continueSignIn(first.outcome.operationId)).error, 'invalid_response');
  expectValue(env.options.trustedInput).collect = async () => { throw new Error('password-must-not-escape'); };
  const failed = await auth.beginSignIn(connection.id, { method: 'mediated', scopes: ['poppy:read'] });
  assert.equal(failed.outcome.error, 'input_unavailable'); assert.equal(JSON.stringify(failed).includes('password-must-not-escape'), false);
});

test('Direct rejects insecure, cross-domain and response-parameter registered callbacks before creating work', async () => {
  const env = await setup(), { connection } = await env.auth.start(env.company.domain), count = Object.keys(env.store.raw.operations).length;
  for (const redirectUri of ['http://agent.test/cb', 'https://user@agent.test/cb', 'https://sub.agent.test/cb', 'https://agent.test/cb#fragment', 'https://agent.test/cb?state=reserved']) {
    await assert.rejects(createClientAuth({ ...env.options, redirectUris: [redirectUri] }).beginSignIn(connection.id, { scopes: ['poppy:read'], redirectUri, browserBinding: BROWSER }), code('invalid_redirect'));
  }
  assert.equal(Object.keys(env.store.raw.operations).length, count);
});

test('existing connection metadata is refreshed, but changed saved endpoints never receive credentials', async () => {
  const env = await setup(), { connection } = await env.auth.start(env.company.domain), resolve = env.options.metadata.resolveCompany;
  const before = structuredClone(env.store.raw.connections[connection.id]);
  env.options.metadata.resolveCompany = async domain => { const fresh = structuredClone(await resolve(domain)); expectValue(expectValue(fresh.document.auth).direct).scopes = ['poppy:write']; return fresh; };
  assert.deepEqual((await env.auth.authorization(connection.id, ['poppy:write'])).methods[0].scopes, ['poppy:write']);
  env.options.metadata.resolveCompany = async domain => { const fresh = structuredClone(await resolve(domain)); expectValue(fresh.authorization).token_endpoint += '/new'; return fresh; };
  const count = exchanges(env.company);
  await assert.rejects(env.auth.renew(connection.id), code('metadata_changed'));
  assert.equal(exchanges(env.company), count); assert.equal(expectValue(env.store.raw.connections[connection.id].metadata.authorization).token_endpoint, expectValue(before.metadata.authorization).token_endpoint);
});

test('provider assertions use derived identity; mixed anonymous never calls stable provider identity or signer', async () => {
  const env = await setup(); let identityCalls = 0; const requests = [];
  const options:ClientAuthOptions = { ...env.options, providerIdentity: { identity: async () => { identityCalls++; return { clientId: CLIENT_ID, userId: 'provider-derived-user' }; } },
    assertions: { assert: async request => {
      requests.push(request); assert.deepEqual(Object.keys(request).sort(), ['issuer', 'operationId', 'purpose']);
      const iat = Math.floor(env.clock.t / 1000), assertion = await new CompactSign(new TextEncoder().encode(JSON.stringify({ iss: CLIENT_ID, sub: request.purpose === 'session' ? 'provider-derived-user' : CLIENT_ID, aud: request.issuer, iat, exp: iat + 60, jti: randomUUID() }))).setProtectedHeader({ typ: request.purpose === 'session' ? 'JWT' : 'client-authentication+jwt', alg: 'ES256', kid: env.signer.kid }).sign(expectValue(env.signer.privateKey));
      return { assertion, expiresAt: iat + 60 };
    } } };
  const auth = createClientAuth(options), regular = await auth.start(env.company.domain);
  assert.equal(env.store.raw.connections[regular.connection.id].userId, 'provider-derived-user');
  const count = requests.length, anonymous = await auth.start(env.company.domain, { anonymous: true });
  assert.equal(identityCalls, 1); assert.equal(requests.length, count);
  assert.notEqual(env.store.raw.connections[anonymous.connection.id].userId, 'provider-derived-user');
  await assert.rejects(createClientAuth({ ...options, identity: undefined }).start(env.company.domain, { anonymous: true }), code('anonymous_unavailable'));
});

test('provider freshness tolerates bounded clock skew and classifies failures in session and browser paths', async t => {
  const cases = [
    { name: 'server one second ahead', remaining: 61, expected: undefined },
    { name: 'exact freshness horizon', remaining: 90, expected: undefined },
    { name: 'beyond horizon', remaining: 90.001, expected: 'provider_clock_skew' },
    { name: 'expired at current time', remaining: 0, expected: 'provider_assertion_expired' },
    { name: 'already expired', remaining: -1, expected: 'provider_assertion_expired' },
    { name: 'nonfinite expiry', remaining: NaN, expected: 'provider_invalid_response' },
    { name: 'missing assertion', remaining: 60, empty: true, expected: 'provider_invalid_response' },
  ];
  for (const path of ['session', 'browser']) for (const row of cases) await t.test(path + ': ' + row.name, async () => {
    const env = await setup(), resolve = env.options.metadata.resolveCompany;
    env.options.metadata.resolveCompany = async domain => { const metadata = await resolve(domain); metadata.document.web = { browser_session_endpoint: 'https://' + env.company.domain + '/join' }; return metadata; };
    const first = path === 'browser' ? await env.auth.start(env.company.domain) : undefined;
    const assertions = { async assert(request: AssertionRequest) {
      const iat = Math.floor(env.clock.t / 1000), exp = iat + row.remaining;
      const assertion = await new CompactSign(new TextEncoder().encode(JSON.stringify({ iss: CLIENT_ID, sub: request.purpose === 'client-authentication' ? CLIENT_ID : 'provider-user', aud: request.issuer, iat: exp - 60, exp, jti: randomUUID() }))).setProtectedHeader({ typ: request.purpose === 'session' ? 'JWT' : 'client-authentication+jwt', alg: 'ES256', kid: env.signer.kid }).sign(expectValue(env.signer.privateKey));
      return { assertion: row.empty ? '' : assertion, expiresAt: exp };
    } };
    const auth = createClientAuth({ ...env.options, assertions, providerIdentity: { identity: async () => ({ clientId: CLIENT_ID, userId: 'provider-user' }) } });
    let posted = false;
    const action = () => path === 'session' ? auth.start(env.company.domain) : auth.joinBrowser(expectValue(first).connection.id, 'https://' + env.company.domain + '/home', { kind: 'agent-controlled', async postForm() { posted = true; } });
    if (row.expected) await assert.rejects(action, { code: row.expected }); else await action();
    if (path === 'browser') assert.equal(posted, !row.expected);
  });
  for (const [failure, expected] of [['unauthorized','provider_unauthorized'],['rate_limited','provider_rate_limited'],['timeout','provider_network_error'],['invalid_response','provider_invalid_response'],['unavailable','provider_unavailable']]) await t.test('safe failure: ' + failure, async () => {
    const env = await setup();
    const auth = createClientAuth({ ...env.options, providerIdentity: { identity: async () => { throw Object.assign(new Error('PRIVATE_CREDENTIAL'), { code: failure }); } }, assertions: { assert: async () => { throw new Error('not reached'); } } });
    await assert.rejects(auth.start(env.company.domain), error => { assert.equal((error as AuthFailure).code, expected); assert.ok(!String(error).includes('PRIVATE')); return true; });
  });
});

test('a narrow Session Token renews from a sufficient grant without another sign-in', async () => {
  const { auth, company, id, target } = await signedIn();
  await auth.renew(id, { scopes: ['poppy:read'] });
  assert.equal((await auth.authorizedFetch(id, conversations(company), target, ['poppy:write'])).status, 200);
});

for (const method of ['direct', 'device', 'mediated'] as const) test(`${method} cancellation during remote exchange fences late grant into durable cleanup`, async () => {
  const env = await setup({ method }); env.options.trustedInput = { collect: async () => ({ password: 'private-password' }) };
  const auth = createClientAuth(env.options), { connection } = await auth.start(env.company.domain);
  let operationId!:string, run!:()=>Promise<AuthOutcome>;
  if (method === 'direct') { const begun = await beginAndApprove(auth, env.company, connection.id); operationId = begun.begun.operationId; run = () => auth.completeSignIn({ callbackUrl: begun.callbackUrl, browserBinding: BROWSER }); }
  else if (method === 'device') { const begun = await auth.beginSignIn(connection.id, { method, scopes: ['poppy:read'] }); operationId = begun.outcome.operationId; env.clock.t += 5000; run = () => auth.continueSignIn(operationId); }
  else run = async () => (await auth.beginSignIn(connection.id, { method, scopes: ['poppy:read'] })).outcome;
  const handle = env.company.handle; let deliver!:()=>void,waiting!:()=>void; const ready = new Promise<void>(resolve => { waiting = resolve; });
  env.company.handle = async (request, options) => {
    const response = await handle(request, options);
    if (request.url === (method === 'mediated' ? `${env.company.issuer}/sign-in` : env.company.tokenEndpoint)) {
      operationId ??= expectValue(Object.values(env.store.raw.operations).find(record => record.phase === 'dispatched')).id;
      waiting(); await new Promise<void>(resolve => { deliver = resolve; });
    }
    return response;
  };
  const active = run(); await ready; assert.equal((await auth.cancelSignIn(operationId)).status, 'cancelled');
  assert.deepEqual(await createClientAuth(env.options).recover(), [], 'cancellation leaves live remote owner recoverable');
  expectValue(deliver)(); const result = await active; assert.equal(result.status, 'cancelled');
  assert.equal(expectValue((await auth.get(connection.id))).status, 'signed_out'); assert.equal(Object.keys(env.store.raw.grants).length, 0);
  assert.equal(Object.values(env.store.raw.cleanup).length, 1); assert.equal((await auth.retryCleanup(connection.id)).cleanup, 'complete');
});

test('Device rejects phishing links before exposing codes and persists a server polling deadline', async () => {
  const env = await setup({ method: 'device' }), { connection } = await env.auth.start(env.company.domain), handle = env.company.handle;
  env.company.handle = async (request, options) => {
    const result = await handle(request, options);
    if (request.url !== `${env.company.issuer}/device`) return result;
    const body = await result.json(); body.verification_uri = 'https://unrelated.test/approve'; return new Response(JSON.stringify(body));
  };
  const denied = await env.auth.beginSignIn(connection.id, { method: 'device', scopes: ['poppy:read'] }); assert.equal(denied.device, undefined);
  env.company.handle = handle;
  const { outcome } = await env.auth.beginSignIn(connection.id, { method: 'device', scopes: ['poppy:read'] }); env.clock.t += 5000;
  env.company.handle = async (request, options) => request.url === env.company.tokenEndpoint ? new Response('HTML', { status: 429, headers: { 'retry-after': '7200' } }) : handle(request, options);
  assert.equal((await env.auth.continueSignIn(outcome.operationId)).retryAfterMs, 7200000);
  const count = exchanges(env.company); env.clock.t += 1000;
  assert.equal((await createClientAuth(env.options).continueSignIn(outcome.operationId)).retryAfterMs, 7199000);
  assert.equal(exchanges(env.company), count);
});

for (const method of ['device', 'mediated'] as const) test(`${method} cancellation cannot reopen after a late pending/challenge response`, async () => {
  const env = await setup({ method }); let inputCalls = 0;
  env.options.trustedInput = { collect: async () => { inputCalls++; return { password: 'private-password' }; } };
  env.company.signInBehavior.codeRequired = true; env.company.signInBehavior.status = 'authorization_pending';
  const auth = createClientAuth(env.options), { connection } = await auth.start(env.company.domain);
  let operationId!:string,run!:()=>Promise<AuthOutcome>;
  if (method === 'device') { const begun = await auth.beginSignIn(connection.id, { method, scopes: ['poppy:read'] }); operationId = begun.outcome.operationId; env.clock.t += 5000; run = () => auth.continueSignIn(operationId); }
  else run = async () => (await auth.beginSignIn(connection.id, { method, scopes: ['poppy:read'] })).outcome;
  const handle = env.company.handle; let deliver!:()=>void,waiting!:()=>void; const ready = new Promise<void>(resolve => { waiting = resolve; });
  env.company.handle = async (request, options) => {
    const response = await handle(request, options);
    if (request.url === (method === 'device' ? env.company.tokenEndpoint : `${env.company.issuer}/sign-in`)) {
      operationId ??= expectValue(Object.values(env.store.raw.operations).find(record => record.phase === 'dispatched')).id;
      waiting(); await new Promise<void>(resolve => { deliver = resolve; });
    }
    return response;
  };
  const active = run(); await ready; await auth.cancelSignIn(operationId); expectValue(deliver)();
  assert.equal((await active).status, 'cancelled'); const count = env.company.requests.length;
  assert.equal((await createClientAuth(env.options).continueSignIn(operationId)).status, 'cancelled');
  assert.equal(env.company.requests.length, count); assert.equal(inputCalls, method === 'mediated' ? 1 : 0);
  assert.equal(env.store.raw.operations[operationId].phase, 'terminal');
});

test('canceling Device authorization disposes its late device code and exposes no approval link', async () => {
  const env = await setup({ method: 'device' }), { connection } = await env.auth.start(env.company.domain), handle = env.company.handle;
  let operationId!:string,deliver!:()=>void,waiting!:()=>void; const ready = new Promise<void>(resolve => { waiting = resolve; });
  env.company.handle = async (request, options) => {
    const response = await handle(request, options);
    if (request.url === `${env.company.issuer}/device`) {
      operationId = expectValue(Object.values(env.store.raw.operations).find(record => record.phase === 'dispatched')).id;
      waiting(); await new Promise<void>(resolve => { deliver = resolve; });
    }
    return response;
  };
  const active = env.auth.beginSignIn(connection.id, { method: 'device', scopes: ['poppy:read'] }); await ready;
  await env.auth.cancelSignIn(expectValue(operationId)); expectValue(deliver)(); const result = await active;
  assert.equal(result.outcome.status, 'cancelled'); assert.equal(result.device, undefined);
  assert.equal([...env.secrets.map.values()].some(value => env.company.devices.has(value)), false);
});

test('Mediated one-time code approval resumes after restart without resending credentials', async () => {
  const env = await setup({ method: 'mediated' }), prompts: { operationId: string; issuer: string; organization: { name: string; domain: string; }; fields: { name: string; label: string; secret: boolean; }[]; challenge?: { id: string; sentTo: string; expiresAt: number; }; }[] = [];
  env.company.signInBehavior.codeRequired = true;
  env.options.trustedInput = { collect: async (request):Promise<Record<string,string>> => { prompts.push(request); return request.challenge ? { code: '123456' } : { password: 'private-password' }; } };
  const auth = createClientAuth(env.options), { connection } = await auth.start(env.company.domain);
  const { outcome } = await auth.beginSignIn(connection.id, { method: 'mediated', scopes: ['poppy:read'] });
  assert.equal(outcome.status, 'pending');
  assert.equal((await createClientAuth(env.options).continueSignIn(outcome.operationId)).status, 'completed');
  assert.deepEqual(prompts.map(prompt => prompt.fields.map(field => field.name)), [['password'], ['code']]);
});

test('different full issuers sharing a host keep identities, keys and credentials isolated', async () => {
  const env = await setup(), first = env.company, second = createFakeCompany({ name: 'shop', issuerPath: '/other', jwks: { keys: [env.signer.jwk] }, clientId: CLIENT_ID, now: expectValue(env.options.now), redirectUris: [REDIRECT] });
  let current = first;
  env.options.metadata.resolveCompany = async () => ({
    document: await (await current.handle(new Request(`https://${current.domain}/.well-known/poppy.json`))).json(),
    authorization: await (await current.handle(new Request(`https://auth.shop.test/.well-known/oauth-authorization-server${new URL(current.issuer).pathname}`))).json(),
    url: `https://shop.test/.well-known/poppy.json`,
  });
  env.transport.fetch = (request, options) => current.handle(request, options);
  const auth = createClientAuth(env.options), a = await auth.start(first.domain); current = second;
  const b = await auth.start(second.domain);
  const one = env.store.raw.identities[first.issuer], two = env.store.raw.identities[second.issuer];
  assert.notEqual(one.userId, two.userId); assert.notEqual(one.dpopKeyRef, two.dpopKeyRef);
  assert.notEqual(a.connection.issuer, b.connection.issuer);
  const count = second.requests.length;
  await assert.rejects(auth.renew(a.connection.id), code('metadata_changed'));
  assert.equal(second.requests.filter(request => request.url === second.tokenEndpoint).length, 1, 'first issuer credential never sent to second');
  assert.ok(second.requests.length >= count, 'metadata refresh is allowed');
  current = first; assert.equal((await auth.renew(a.connection.id)).status, 'completed');
});

test('conversation Retry-After survives restart without dispatching early', async () => {
  const env = await signedIn();
  env.company.behavior.resourceHandler = async () => new Response('company rate limit', { status: 429, headers: { 'retry-after': '7200' } });
  assert.equal((await env.auth.authorizedFetch(env.id, conversations(env.company), env.target)).status, 429);
  const count = env.company.requests.length; env.clock.t += 3600000;
  await assert.rejects(createClientAuth(env.options).authorizedFetch(env.id, conversations(env.company), env.target), error => error instanceof AuthFailure && error.code === 'rate_limited' && error.retryAfterMs === 3600000);
  assert.equal(env.company.requests.filter(request => request.url === env.company.endpoint).length, 1);
  assert.ok(env.company.requests.length >= count);
});

test('revocation Retry-After persists with its cleanup item across restart', async () => {
  const env = await signedIn(), handle = env.company.handle;
  let calls = 0;
  env.company.handle = async (request, options) => {
    if (request.url === `${env.company.issuer}/revoke`) { calls++; return new Response('HTML', { status: 503, headers: { 'retry-after': '7200' } }); }
    return handle(request, options);
  };
  assert.equal((await env.auth.signOut(env.id)).cleanup, 'pending'); assert.equal(calls, 1);
  assert.equal(expectValue((await env.auth.get(env.id))).status, 'disconnected');
  await assert.rejects(env.auth.authorizedFetch(env.id, conversations(env.company), env.target), code('disconnected'));
  env.clock.t += 3600000; assert.equal((await createClientAuth(env.options).retryCleanup(env.id)).cleanup, 'pending'); assert.equal(calls, 1);
  env.company.handle = handle; env.clock.t += 3600000;
  assert.equal((await createClientAuth(env.options).retryCleanup(env.id)).cleanup, 'complete');
});

import { createConversationClient,ConversationError } from '../../dist/conversation.js';
import { MemoryConversationStore } from '../../dist/memory.js';
test('real auth lifecycle selects streaming, cancels nonce failures and sends fresh DPoP',async()=>{
  const env=await setup(),{connection}=await env.auth.start(env.company.domain);let streams=0,canceled=0;const proofs:(string|null)[]=[];
  env.company.behavior.requireNonce=true;
  env.company.behavior.resourceHandler=()=>new Response('id: final\ndata: {"id":"final","created_at":"2026-10-22T00:00:00Z","type":"state","status":"closed","responder":"agent"}\n\n',{headers:{'content-type':'text/event-stream'}});
  env.transport.stream=async (request: Request) =>{streams++;proofs.push(request.headers.get('dpop'));const response=await env.transport.fetch(request);if(response.status===401)return new Response(new ReadableStream({cancel(){canceled++;}}),{status:401,headers:response.headers});return response;};
  const target=await env.auth.target(connection.id),store=new MemoryConversationStore();
  const client=createConversationClient({...target,connectionId:connection.id,store,clock:{now:()=>env.clock.t},authorizedRequest:request=>env.auth.authorizedFetch(connection.id,request,target)});
  const events=[];for await(const item of client.watch('c1'))events.push(item.event.id);
  assert.deepEqual(events,['final']);assert.equal(streams,2);assert.equal(canceled,1);assert.notEqual(proofs[0],proofs[1]);
});
for(const method of ['device','mediated'] as const)test(`conversation errors use real ${method}-only authorization lifecycle`,async()=>{
  const env=await setup({method});env.options.trustedInput={collect:async()=>({password:'private-password'})};const auth=createClientAuth(env.options),{connection}=await auth.start(env.company.domain),target=await auth.target(connection.id);
  env.company.behavior.resourceHandler=(_request,bound)=>bound.account?Response.json({conversation_id:'c1',events:[],cursor:null,has_more:false,status:'idle',responder:'agent'}):Response.json({error:'sign_in_required'},{status:403,headers:{'www-authenticate':'DPoP error="sign_in_required", scope="poppy:read"'}});
  const client=createConversationClient({...target,connectionId:connection.id,store:new MemoryConversationStore(),clock:{now:()=>env.clock.t},authorizedRequest:request=>auth.authorizedFetch(connection.id,request,target),authorization:(id,scopes)=>auth.authorization(id,scopes)});
  let error:unknown;try{await client.read('c1');}catch(value){error=value;}assert.ok(error instanceof ConversationError);const requirement=await client.authorization(error);assert.deepEqual(requirement.methods,[{method,scopes:['poppy:read','poppy:write']}]);assert.deepEqual(requirement.requiredScopes,['poppy:read']);
  const begun=await auth.beginSignIn(connection.id,{method,scopes:requirement.requiredScopes});if(method==='device'){env.clock.t+=5000;await auth.continueSignIn(begun.outcome.operationId);}assert.equal((await client.read('c1')).conversation_id,'c1');
});
