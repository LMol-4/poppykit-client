import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { calculateJwkThumbprint, CompactSign } from 'jose';
import { createClientAuth, initialClientAuthState, AuthFailure, createMetadataResolver } from '../../dist/index.js';
import { createFakeCompany, fakeTransport } from './fake-issuer.mjs';

const CLIENT_ID = 'https://agent.test/agent.json';
const EC = { name: 'ECDSA', namedCurve: 'P-256' };
const ES256 = { name: 'ECDSA', hash: 'SHA-256' };

function memoryStore(initial = initialClientAuthState()) {
  let state = structuredClone(initial); let chain = Promise.resolve();
  return {
    get raw() { return state; },
    async read() { return structuredClone(state); },
    transaction(change) {
      const run = chain.then(() => {
        const draft = structuredClone(state); const result = change(draft);
        if (result && typeof result.then === 'function') throw new Error('async transaction');
        state = draft; return structuredClone(result);
      });
      chain = run.catch(() => {}); return run;
    },
  };
}
function memorySecrets() {
  const map = new Map();
  return { map, async stage(secret) { const ref = `sec_${randomUUID()}`; map.set(ref, secret); return ref; }, async read(ref) { return map.get(ref) ?? null; }, async remove(ref) { map.delete(ref); } };
}
async function makeSigner(kid = 'agent-key-1') {
  const pair = await crypto.subtle.generateKey(EC, true, ['sign', 'verify']);
  const { kty, crv, x, y } = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const jwk = { kty, crv, x, y, kid, use: 'sig', alg: 'ES256' };
  return { kid, jwk, privateKey: pair.privateKey, publicJwk: async () => ({ ...jwk }), sign: async input => new Uint8Array(await crypto.subtle.sign(ES256, pair.privateKey, input)) };
}
async function setup({ localUserId = 'alice', store = memoryStore(), secrets = memorySecrets(), signer, names = ['shop'] } = {}) {
  signer ??= await makeSigner();
  const clock = { t: 1_790_900_000_000 }; const now = () => clock.t;
  const companies = names.map(name => createFakeCompany({ name, jwks: { keys: [signer.jwk] }, clientId: CLIENT_ID, now }));
  const transport = fakeTransport(...companies);
  const options = { namespace: 'demo', localUserId, clientId: CLIENT_ID, redirectUris: [], identity: signer, store, secrets, transport, metadata: createMetadataResolver(transport, { now }), now };
  return { auth: createClientAuth(options), options, company: companies[0], companies, transport, store, secrets, signer, clock };
}
const code = expected => error => error instanceof AuthFailure && error.code === expected;
const conversations = (company, path = '') => new Request(`${company.endpoint}${path}`, { method: 'POST', body: JSON.stringify({ hello: 'world' }), headers: { 'content-type': 'application/json' } });

test('start creates a signed-out session with verified assertions and a separate DPoP key', async () => {
  const { auth, company, store, secrets, signer } = await setup();
  const outcome = await auth.start(company.domain);
  assert.equal(outcome.status, 'completed');
  assert.deepEqual(Object.keys(outcome.connection).sort(), ['domain', 'generation', 'id', 'issuer', 'scopes', 'sessionId', 'status']);
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
  for (const token of company.tokens.keys()) { assert.equal(persisted.includes(token), false); assert.equal(JSON.stringify(outcome).includes(token), false); }
  assert.equal(persisted.includes('"d"'), false);
  assert.ok([...secrets.map.values()].some(value => company.tokens.has(value)));
  assert.equal(store.raw.operations[outcome.operationId].result.status, 'completed');
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
  const sessionSubs = company => company.assertions.filter(item => item.kind === 'session').map(item => item.payload.sub);
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
  const sign = async (payload, key = signer.privateKey, kid = signer.kid) => new CompactSign(new TextEncoder().encode(JSON.stringify(payload))).setProtectedHeader({ alg: 'ES256', kid }).sign(key);
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
  ]) await assert.rejects(company.verifyAssertion(await sign(payload, key), 'session'), /invalid_grant/);
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
  const dpop = JSON.parse(secrets.map.get(store.raw.identities[first.company.issuer].dpopKeyRef));
  const privateKey = await crypto.subtle.importKey('jwk', dpop, EC, false, ['sign']);
  const { kty, crv, x, y } = dpop;
  const signer = { kid: 'reused', jwk: { kty, crv, x, y, kid: 'reused' }, publicJwk: async () => ({ kty, crv, x, y }), sign: async input => new Uint8Array(await crypto.subtle.sign(ES256, privateKey, input)) };
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
  ]) {
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
  ]) {
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
  assert.equal(proof.payload.htu, `${company.endpoint}/cnv_1/messages`); assert.equal(proof.payload.htm, 'POST'); assert.ok(proof.payload.ath);
  assert.equal(proof.thumbprint, company.proofs[0].thumbprint);
  const resourceCalls = company.requests.filter(item => item.url.startsWith(company.endpoint));
  assert.ok(resourceCalls.every(item => item.authorization.startsWith('DPoP ')));
  await auth.authorizedFetch(connection.id, new Request(company.endpoint), target, []);
  assert.notEqual(company.proofs.at(-1).payload.jti, proof.payload.jti);
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
  ]) await assert.rejects(auth.authorizedFetch(id, request, wanted, scopes), code(expected), `${id} ${request.url} ${expected}`);
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
  assert.equal(company.proofs.at(-1).payload.nonce, company.nonce);
  company.behavior.rotateNonceEveryTime = true;
  const resourceCalls = () => company.requests.filter(item => item.url.startsWith(company.endpoint)).length;
  const before = resourceCalls();
  const rejected = await auth.authorizedFetch(connection.id, conversations(company), target);
  assert.equal(rejected.status, 401); assert.match(rejected.headers.get('www-authenticate'), /use_dpop_nonce/);
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
  assert.equal(renewal.kind, 'session');
  assert.equal(company.tokens.size, 1);
  // A resource that keeps rejecting gets one renewal, then the 401 is returned as-is.
  company.behavior.resourceHandler = () => new Response(null, { status: 401, headers: { 'www-authenticate': 'DPoP error="invalid_token"' } });
  const tokenCalls = () => company.requests.filter(item => item.url === company.tokenEndpoint).length;
  const before = tokenCalls();
  const rejected = await auth.authorizedFetch(connection.id, conversations(company), target);
  assert.equal(rejected.status, 401); assert.equal(tokenCalls() - before, 1);
});

test('expired credentials renew before dispatch; ended sessions surface invalid_session', async () => {
  const { auth, company, clock, store } = await setup();
  const { connection } = await auth.start(company.domain);
  const target = await auth.target(connection.id);
  const tokenCalls = () => company.requests.filter(item => item.url === company.tokenEndpoint).length;
  clock.t += 3600_000;
  assert.equal((await auth.authorizedFetch(connection.id, conversations(company), target)).status, 200);
  assert.equal(tokenCalls(), 2);
  clock.t += 3600_000; company.sessions.clear();
  const slots = structuredClone(store.raw.connections[connection.id].slots);
  await assert.rejects(auth.authorizedFetch(connection.id, conversations(company), target), code('invalid_session'));
  assert.deepEqual(store.raw.connections[connection.id].slots, slots);
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
  assert.equal(store.raw.owner.localUserId, 'alice');
  assert.throws(() => createClientAuth({ ...alice.options, clientId: 'http://agent.test/agent.json' }), code('invalid_options'));
  assert.throws(() => createClientAuth({ ...alice.options, localUserId: '' }), code('invalid_options'));
});

test('a reset between token issuance and activation does not attach the session', async () => {
  const { auth, company, store } = await setup();
  await auth.start(company.domain);
  const transaction = store.transaction.bind(store);
  let reset = false;
  const originalFetch = company.handle;
  company.handle = async (request, options) => { const response = await originalFetch(request, options); if (request.url === company.tokenEndpoint && !reset) { reset = true; await transaction(state => { Object.assign(state, initialClientAuthState(), { owner: state.owner }); }); } return response; };
  await assert.rejects(auth.start(company.domain), code('state_changed'));
  assert.deepEqual(store.raw.connections, {});
});
