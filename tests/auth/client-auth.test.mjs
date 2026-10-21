import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { calculateJwkThumbprint, CompactSign } from 'jose';
import { createClientAuth, initialClientAuthState, AuthFailure, createMetadataResolver } from '../../dist/index.js';
import { createFakeCompany, fakeTransport } from './fake-issuer.mjs';

const CLIENT_ID = 'https://agent.test/agent.json';
const REDIRECT = 'https://agent.test/oauth/callback';
const EC = { name: 'ECDSA', namedCurve: 'P-256' };
const ES256 = { name: 'ECDSA', hash: 'SHA-256' };

function memoryStore(initial = initialClientAuthState()) {
  let state = structuredClone(initial); let chain = Promise.resolve();
  const store = {
    crashNext: false, crashIn: 0, // crashIn = n fails the nth transaction from now
    get raw() { return state; },
    async read() { return structuredClone(state); },
    transaction(change) {
      const run = chain.then(() => {
        // Simulates the process dying before commit.
        if (store.crashNext) { store.crashNext = false; throw new Error('crash'); }
        if (store.crashIn && --store.crashIn === 0) throw new Error('crash');
        const draft = structuredClone(state); const result = change(draft);
        if (result && typeof result.then === 'function') throw new Error('async transaction');
        state = draft; return structuredClone(result);
      });
      chain = run.catch(() => {}); return run;
    },
  };
  return store;
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
async function setup({ localUserId = 'alice', store = memoryStore(), secrets = memorySecrets(), signer, names = ['shop'], conversationResource } = {}) {
  signer ??= await makeSigner();
  const clock = { t: 1_790_900_000_000 }; const now = () => clock.t;
  const companies = names.map(name => createFakeCompany({ name, jwks: { keys: [signer.jwk] }, clientId: CLIENT_ID, now, redirectUris: [REDIRECT], conversationResource }));
  const transport = fakeTransport(...companies);
  const options = { namespace: 'demo', localUserId, clientId: CLIENT_ID, redirectUris: [REDIRECT], identity: signer, store, secrets, transport, metadata: createMetadataResolver(transport, { now }), now };
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
  const { auth, company, store, secrets } = await setup();
  await auth.start(company.domain);
  const transaction = store.transaction.bind(store);
  let reset = false;
  const originalFetch = company.handle;
  company.handle = async (request, options) => { const response = await originalFetch(request, options); if (request.url === company.tokenEndpoint && !reset) { reset = true; await transaction(state => { Object.assign(state, initialClientAuthState(), { owner: state.owner }); }); } return response; };
  await assert.rejects(auth.start(company.domain), code('state_changed'));
  assert.deepEqual(store.raw.connections, {});
  // The fenced-out session token was never referenced, so it is removed rather than orphaned.
  assert.equal([...secrets.map.values()].filter(value => company.tokens.has(value)).length, 1);
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
  for (const corrupt of ['{"d":"SECRET-PREFIX', 'null', JSON.stringify({ ...JSON.parse(secrets.map.get(ref)), d: 'SECRET-PREFIX' })]) {
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
const exchanges = company => company.requests.filter(item => item.url === company.tokenEndpoint).length;
async function beginAndApprove(auth, company, connectionId, { scopes = ['poppy:read'], account = 'acct_1', approve, deny, browserBinding = BROWSER } = {}) {
  const { outcome, authorizationUrl } = await auth.beginSignIn(connectionId, { scopes, redirectUri: REDIRECT, browserBinding });
  assert.equal(outcome.status, 'pending'); assert.equal(outcome.nextAction, 'wait');
  return { begun: outcome, authorizationUrl, callbackUrl: company.authorize(authorizationUrl, { account, approve, deny }) };
}
async function signIn(auth, company, connectionId, options = {}) {
  const { callbackUrl } = await beginAndApprove(auth, company, connectionId, options);
  return auth.completeSignIn({ callbackUrl, browserBinding: options.browserBinding ?? BROWSER });
}

test('Direct Sign-In isolates two users with two connections each', async () => {
  const signer = await makeSigner();
  const alice = await setup({ signer }); const bob = await setup({ signer, localUserId: 'bob' });
  const accounts = [];
  for (const [user, account] of [[alice, 'acct_alice_personal'], [alice, 'acct_alice_business'], [bob, 'acct_bob_1'], [bob, 'acct_bob_2']]) {
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
    for (const secret of [...user.company.tokens.keys(), ...user.company.grants.keys(), ...user.company.codes.keys(), BROWSER]) assert.equal(persisted.includes(secret), false);
    assert.equal(Object.keys(user.store.raw.grants).length, 2);
  }
  // A callback for Bob's sign-in is unknown to Alice's namespace.
  const { connection } = await bob.auth.start(bob.company.domain);
  const { callbackUrl } = await beginAndApprove(bob.auth, bob.company, connection.id);
  await assert.rejects(alice.auth.completeSignIn({ callbackUrl, browserBinding: BROWSER }), code('invalid_callback'));
});

test('the authorization request and code exchange carry PKCE, state, issuer and session', async () => {
  const { auth, company, store } = await setup();
  const { connection } = await auth.start(company.domain);
  let exchange;
  const original = company.handle;
  company.handle = async (request, options) => { if (request.url === company.tokenEndpoint) exchange = new URLSearchParams(await request.clone().text()); return original(request, options); };
  const { authorizationUrl, callbackUrl } = await beginAndApprove(auth, company, connection.id, { scopes: ['poppy:read', 'poppy:write'] });
  const url = new URL(authorizationUrl);
  assert.equal(url.origin + url.pathname, company.authorizationEndpoint);
  assert.equal(url.searchParams.get('client_id'), CLIENT_ID); assert.equal(url.searchParams.get('redirect_uri'), REDIRECT);
  assert.equal(url.searchParams.get('scope'), 'poppy:read poppy:write'); assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(url.searchParams.get('state').length >= 43);
  assert.equal(JSON.stringify(store.raw).includes(url.searchParams.get('state')), false);
  await auth.completeSignIn({ callbackUrl, browserBinding: BROWSER });
  assert.equal(exchange.get('grant_type'), 'authorization_code'); assert.equal(exchange.get('session_id'), connection.sessionId);
  assert.equal(exchange.get('redirect_uri'), REDIRECT); assert.equal(exchange.get('client_id'), CLIENT_ID);
  assert.equal(exchange.has('assertion'), false); assert.ok(exchange.get('client_assertion'));
  assert.equal(company.proofs.at(-1).thumbprint, company.proofs[0].thumbprint);
});

test('beginSignIn rejects bad input before creating an operation', async () => {
  const { auth, company, store } = await setup();
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
  ]) await assert.rejects(auth.beginSignIn(connection.id, input), code(expected), JSON.stringify(input));
  await assert.rejects(auth.beginSignIn('con_missing', good), code('unknown_connection'));
  const operations = Object.keys(store.raw.operations).length;
  delete store.raw.connections[connection.id].metadata.document.auth.direct;
  await assert.rejects(auth.beginSignIn(connection.id, good), code('direct_unavailable'));
  assert.equal(Object.keys(store.raw.operations).length, operations);
});

test('wrong callbacks leave the operation untouched; duplicates return the recorded result', async () => {
  const { auth, company } = await setup();
  const { connection } = await auth.start(company.domain);
  const { begun, callbackUrl } = await beginAndApprove(auth, company, connection.id);
  const tweak = change => { const url = new URL(callbackUrl); change(url); return url.href; };
  for (const [url, browserBinding] of [
    [callbackUrl, OTHER_BROWSER],
    [tweak(url => url.searchParams.set('iss', `${company.issuer}/`)), BROWSER],
    [tweak(url => url.searchParams.delete('iss')), BROWSER],
    [tweak(url => url.searchParams.set('state', 'forged-state-value')), BROWSER],
    [tweak(url => url.searchParams.append('code', 'second')), BROWSER],
    [tweak(url => url.searchParams.set('extra', '1')), BROWSER],
    [tweak(url => { url.pathname = '/oauth/other'; }), BROWSER],
    [tweak(url => { url.host = 'evil.test'; }), BROWSER],
    [tweak(url => { url.hash = 'x'; }), BROWSER],
    [tweak(url => url.searchParams.set('error', 'access_denied')), BROWSER],
    [tweak(url => url.searchParams.delete('code')), BROWSER],
    ['not a url', BROWSER],
  ]) await assert.rejects(auth.completeSignIn({ callbackUrl: url, browserBinding }), code('invalid_callback'), url);
  assert.equal(exchanges(company), 1);
  assert.equal((await auth.operation(begun.operationId)).status, 'pending');
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
  // Every terminal sign-in removed its verifier; only the DPoP key and session token remain.
  assert.equal(secrets.map.size, 2);
});

test('partial consent keeps the previous grant and parks the new Account Token for revocation', async () => {
  const { auth, company, store, secrets } = await setup();
  const { connection } = await auth.start(company.domain);
  const first = await signIn(auth, company, connection.id, { scopes: ['poppy:read'] });
  assert.equal(first.status, 'completed');
  const before = structuredClone(store.raw.connections[connection.id]);
  const partial = await signIn(auth, company, connection.id, { scopes: ['poppy:read', 'poppy:write'], approve: ['poppy:read'] });
  assert.equal(partial.status, 'failed'); assert.equal(partial.error, 'insufficient_scope');
  assert.deepEqual(partial.missingScopes, ['poppy:write']); assert.deepEqual(partial.connection.scopes, ['poppy:read']);
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
  // A signed-out connection that gets partial consent stays signed out.
  const other = await auth.start(company.domain);
  const none = await signIn(auth, company, other.connection.id, { scopes: ['poppy:read', 'poppy:write'], approve: ['poppy:write'] });
  assert.deepEqual([none.status, none.missingScopes, none.connection.status], ['failed', ['poppy:read'], 'signed_out']);
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
  assert.notEqual(record.grantId, oldGrant); assert.equal(store.raw.grants[oldGrant], undefined);
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
    [{ expires_in: -1 }, 'invalid_response', 0],
  ]) {
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
  company.codes.get(new URL(reused.callbackUrl).searchParams.get('code')).used = true;
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
  assert.equal((await restarted.operation(begun.operationId)).status, 'pending');
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

test('recovery during an in-flight exchange wins; the late grant is parked, not activated', async () => {
  const { auth, company, options, store } = await setup();
  const { connection } = await auth.start(company.domain);
  const { callbackUrl } = await beginAndApprove(auth, company, connection.id);
  const original = company.handle;
  company.handle = async (request, init) => { const response = await original(request, init); if (request.url === company.tokenEndpoint) await createClientAuth(options).recover(); return response; };
  const outcome = await auth.completeSignIn({ callbackUrl, browserBinding: BROWSER });
  assert.equal(outcome.status, 'uncertain');
  assert.equal(store.raw.connections[connection.id].status, 'signed_out'); assert.deepEqual(store.raw.grants, {});
  assert.equal(Object.keys(store.raw.cleanup).length, 1);
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

async function signedIn(options = {}) {
  const context = await setup(options);
  const { connection } = await context.auth.start(context.company.domain);
  assert.equal((await signIn(context.auth, context.company, connection.id, { scopes: ['poppy:read', 'poppy:write'] })).status, 'completed');
  return { ...context, id: connection.id, sessionId: connection.sessionId, target: await context.auth.target(connection.id) };
}
const tokenForms = company => {
  const forms = []; const original = company.handle;
  company.handle = async (request, init) => { if (request.url === company.tokenEndpoint) forms.push(new URLSearchParams(await request.clone().text())); return original(request, init); };
  return forms;
};
const grantOf = (store, id) => store.raw.grants[store.raw.connections[id].grantId];
const loseTokenResponses = (transport, company) => {
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
  assert.equal(company.grants.get(secrets.map.get(after.secretRef)).rotated, false);
  assert.deepEqual([after.operationId, after.generation, after.status], [null, grant.generation + 1, 'active']);
  const slots = store.raw.connections[id].slots;
  assert.deepEqual(Object.keys(slots).sort(), [defaultKey, otherKey].sort());
  assert.deepEqual(slots[otherKey], before.connections[id].slots[otherKey]);
  assert.equal(secrets.map.has(before.connections[id].slots[defaultKey].secretRef), false);
  // Completed renewals do not accumulate.
  assert.equal(Object.values(store.raw.operations).filter(op => op.kind === 'renew').length, 1);
});

test('one rotation per grant: a second process gets the pending operation', async () => {
  const { auth, company, options, id } = await signedIn();
  const second = createClientAuth(options);
  let inner; const original = company.handle;
  company.handle = async (request, init) => { if (request.url === company.tokenEndpoint && !inner) inner = await second.renew(id); return original(request, init); };
  const outcome = await auth.renew(id);
  assert.equal(outcome.status, 'completed');
  assert.deepEqual([inner.status, inner.nextAction, inner.operationId], ['pending', 'wait', outcome.operationId]);
  assert.equal(exchanges(company), 3);
  assert.equal((await second.renew(id)).status, 'completed');
});

test('renew validates input and a definite refusal releases the grant', async () => {
  const { auth, company, store, id } = await signedIn();
  for (const [input, expected] of [[{ scopes: ['admin'] }, 'invalid_scope'], [{ scopes: [] }, 'invalid_scope'], [{ scopes: 'poppy:read' }, 'invalid_scope'], [{ resource: 'not a url' }, 'invalid_target']]) {
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

test('a lost rotation response is uncertain; the old Account Token is never resent', async () => {
  const { auth, company, transport, store, secrets, clock, id, target } = await signedIn();
  const oldToken = secrets.map.get(grantOf(store, id).secretRef);
  const restore = loseTokenResponses(transport, company);
  const lost = await auth.renew(id);
  restore();
  assert.deepEqual([lost.status, lost.error, lost.nextAction, lost.connection.status], ['uncertain', 'lost_response', 'sign_in', 'uncertain']);
  assert.equal(company.grants.get(oldToken).rotated, true, 'the issuer did rotate');
  const sent = exchanges(company);
  await assert.rejects(auth.renew(id), code('grant_uncertain'));
  clock.t += 3600_000;
  await assert.rejects(auth.authorizedFetch(id, conversations(company), target, ['poppy:read']), code('grant_uncertain'));
  assert.equal(exchanges(company), sent);
  // Only a fresh sign-in recovers; it retires the uncertain grant.
  const fresh = await signIn(auth, company, id, { scopes: ['poppy:read'] });
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
  assert.deepEqual([assertion.kind, assertion.payload.aud, assertion.payload.sub], ['client', company.issuer, CLIENT_ID]);
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
  assert.equal((await auth.operation(begun.operationId)).status, 'cancelled');
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
  let during; const original = company.handle;
  company.handle = async (request, init) => { const response = await original(request, init); if (request.url === company.tokenEndpoint && !during) during = await auth.signOut(id); return response; };
  const late = await auth.renew(id);
  assert.deepEqual([late.status, late.error, late.connection.status], ['failed', 'state_changed', 'disconnected']);
  assert.deepEqual([during.connection.status, during.cleanup], ['disconnected', 'pending']);
  const [parked] = Object.values(store.raw.cleanup);
  assert.ok(company.grants.has(secrets.map.get(parked.secretRef)), 'the rotated token awaits revocation');
  assert.deepEqual(store.raw.connections[id].slots, {});
  assert.equal((await auth.retryCleanup(id)).cleanup, 'complete');
  assert.equal(secrets.map.size, 1);
});

test('sign-out during a code exchange wins; the late grant cannot activate', async () => {
  const { auth, company, store, secrets } = await setup();
  const { connection } = await auth.start(company.domain);
  const { callbackUrl } = await beginAndApprove(auth, company, connection.id);
  let during; const original = company.handle;
  company.handle = async (request, init) => { const response = await original(request, init); if (request.url === company.tokenEndpoint && !during) during = await auth.signOut(connection.id); return response; };
  const outcome = await auth.completeSignIn({ callbackUrl, browserBinding: BROWSER });
  assert.deepEqual([outcome.status, outcome.error, outcome.connection.status], ['failed', 'state_changed', 'disconnected']);
  assert.equal(during.cleanup, 'pending');
  assert.deepEqual(store.raw.grants, {}); assert.equal(Object.keys(store.raw.cleanup).length, 1);
  assert.equal((await auth.retryCleanup(connection.id)).cleanup, 'complete');
  assert.equal(secrets.map.size, 1);
});

test('a crash after the refresh response: staged finishes on recovery, unstaged is uncertain', async () => {
  for (const [crashIn, expected] of [[1, 'uncertain'], [2, 'completed']]) {
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
      assert.equal(grantOf(store, id).secretRef, operation.staged.refreshRef);
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
    assert.equal(company.grants.get(oldToken).rotated, true);
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
