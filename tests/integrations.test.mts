import type {AuthStore,SecretStore} from '../dist/auth/client-auth.js';
import type {HttpTransport} from '../dist/network/transport.js';
import type {PoppyDocument} from '../dist/network/discovery.js';
import type {AgentBrowserController} from '../dist/integrations.js';
import { expectValue, publicEcJwk } from '../test-support/assertions.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, createHash } from 'node:crypto';
import { compactVerify, decodeJwt, decodeProtectedHeader, importJWK } from 'jose';
import { createClientAuth, initialClientAuthState, createMetadataResolver, createNodeTransport, type ApiTarget } from '../dist/index.js';
import { createFakeCompany } from './auth/fake-issuer.mjs';

const CLIENT = 'https://agent.test/agent.json', OPENAPI = 'https://shop.test/openapi.json', BASE = 'https://shop.test/v1';
const MCP = 'https://shop.test/mcp', OTHER = 'https://shop.test/other-mcp', SECURE = 'https://shop.test/secure-mcp';
async function fixture() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = { ...await publicEcJwk(pair.publicKey), kid: 'agent-key', alg: 'ES256', use: 'sig' };
  const identity = { kid: 'agent-key', publicJwk: async () => jwk, sign: async (input:Uint8Array) => new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new Uint8Array(input))) };
  let state = initialClientAuthState(); const secretRows = new Map<string,string>(), calls:{url:string;authorization:string|null;dpop:string|null;mode?:string}[] = [], issued: (string|null)[] = [], apiRequests:{request:Request;token:string;resource:string|null}[] = [];
  const store:AuthStore = { async read() { return structuredClone(state); }, async transaction(selection, mutate) { const draft = structuredClone(state), result = mutate(draft); state = draft; return structuredClone(result); }, async pendingOperations() { return []; } };
  const secrets:SecretStore = { async stage(value) { const id = randomUUID(); secretRows.set(id, value); return id; }, async read(id) { return secretRows.get(id) ?? null; }, async remove(id) { secretRows.delete(id); } };
  const now = () => 1790900000000;
  const company = createFakeCompany({ jwks: { keys: [jwk] }, clientId: CLIENT, now, redirectUris: ['https://agent.test/callback'] });
  const env:{company:typeof company;calls:typeof calls;issued:typeof issued;apiRequests:typeof apiRequests;metadataOverride:unknown;resourceReply:((request:Request)=>Response)|null;mutateDocument:((document:PoppyDocument)=>void)|null} = { company, calls, issued, apiRequests, metadataOverride: null, resourceReply: null, mutateDocument: null };
  const transport:HttpTransport = { async fetch(request,options) {
    calls.push({ url: request.url, authorization: request.headers.get('authorization'), dpop: request.headers.get('dpop'), mode: options?.mode });
    if (request.url.includes('/.well-known/oauth-protected-resource')) {
      assert.equal(request.headers.get('authorization'), null); assert.equal(request.headers.get('cookie'), null);
      const resource = `https://shop.test${new URL(request.url).pathname.replace('/.well-known/oauth-protected-resource', '')}`;
      return Response.json(env.metadataOverride ?? { resource, authorization_servers: [company.issuer], ...(resource === SECURE ? { dpop_signing_alg_values_supported: ['ES256'] } : {}) });
    }
    if (request.url === company.tokenEndpoint) {
      const form = new URLSearchParams(await request.clone().text()); issued.push(form.get('resource'));
      const response = await company.handle(request, options); if (response.status !== 200) return response;
      const value = await response.json();
      if ([MCP, OTHER].includes(form.get('resource')??'')) value.token_type = 'Bearer';
      return Response.json(value);
    }
    if (request.url === 'https://shop.test/.well-known/poppy.json') {
      const response = await company.handle(request, options), doc = await response.json();
      doc.apis = [{ type: 'openapi', url: OPENAPI, description: 'API description', resource: BASE }, ...[MCP, OTHER, SECURE].map(url => ({ type: 'mcp', url, description: 'MCP' }))];
      doc.web = { browser_session_endpoint: 'https://shop.test/browser-session' }; doc.feedback = { endpoint: 'https://shop.test/feedback' };
      env.mutateDocument?.(doc); return Response.json(doc);
    }
    if (request.url === 'https://evil.test/.well-known/poppy.json') throw new Error('Unknown unverified company');
    if (request.url.startsWith(BASE) || [MCP, OTHER, SECURE, 'https://shop.test/feedback'].includes(request.url)) {
      const header = expectValue(request.headers.get('authorization')), token = expectValue(header.split(' ')[1]), record = company.tokens.get(token);
      assert.ok(record, 'only real lifecycle-issued tokens');
      if (request.url.startsWith(BASE)) assert.equal(record.resource, BASE);
      else if ([MCP, OTHER, SECURE].includes(request.url)) assert.equal(record.resource, request.url);
      if (expectValue(header).startsWith('DPoP ')) {
        const jwt = expectValue(request.headers.get('dpop')), h = decodeProtectedHeader(jwt);
        await compactVerify(jwt, await importJWK(expectValue(h.jwk), 'ES256'));
        const claims = decodeJwt(jwt); assert.equal(claims.htm, request.method); assert.equal(claims.htu, request.url.split('?')[0]); assert.equal(claims.ath, createHash('sha256').update(token).digest('base64url'));
      } else { assert.ok([MCP, OTHER].includes(request.url)); assert.equal(request.headers.get('dpop'), null); }
      assert.equal(request.headers.get('cookie'), null); assert.equal(request.redirect, 'error');
      apiRequests.push({ request, token, resource: record.resource });
      return env.resourceReply ? env.resourceReply(request) : request.url.endsWith('/feedback') ? new Response(null, { status: 202 }) : Response.json({ ok: true });
    }
    return company.handle(request, options);
  } };
  const metadata = createMetadataResolver(transport, { now });
  const auth = createClientAuth({ namespace: 'integration', localUserId: 'one-user', clientId: CLIENT, redirectUris: ['https://agent.test/callback'], identity, store, secrets, transport, metadata, now });
  const result = await auth.start(company.domain); assert.equal(result.status, 'completed');
  return { ...env, auth, connection: result.connection, metadata, setMetadata(value:unknown) { env.metadataOverride = value; }, setReply(value:((request:Request)=>Response)|null) { env.resourceReply = value; }, setDocument(value:((document:PoppyDocument)=>void)|null) { env.mutateDocument = value; }, raw: () => state };
}

test('CLI-style trusted API client uses final OpenAPI method/URL and isolated MCP resource schemes', async () => {
  const env = await fixture(), id = env.connection.id;
  const openapi = await env.auth.apiTarget(id, OPENAPI, BASE), mcp = await env.auth.apiTarget(id, MCP), other = await env.auth.apiTarget(id, OTHER), secure = await env.auth.apiTarget(id, SECURE);
  assert.equal(openapi.apiUrl, OPENAPI); assert.equal(openapi.endpoint, BASE);
  assert.deepEqual([mcp.scheme, other.scheme, secure.scheme], ['Bearer', 'Bearer', 'DPoP']);
  // An existing client calls this closure only after it has selected the final operation URL and method.
  const fetchHook = (target: ApiTarget ) => (request: Request ) => env.auth.apiFetch(id, request, target);
  await fetchHook(openapi)(new Request(`${BASE}/records`, { method: 'PATCH', headers: { cookie: 'do-not-forward=1' }, body: '{}' }));
  await fetchHook(mcp)(new Request(MCP, { method: 'POST', body: '{}' }));
  await fetchHook(other)(new Request(OTHER, { method: 'POST', body: '{}' }));
  await fetchHook(secure)(new Request(SECURE, { method: 'POST', body: '{}' }));
  await fetchHook(mcp)(new Request(MCP, { method: 'DELETE' }));
  assert.deepEqual(env.issued, [null, BASE, MCP, OTHER, SECURE]);
  assert.notEqual(env.apiRequests[1].token, env.apiRequests[2].token); assert.equal(env.apiRequests[1].token, env.apiRequests[4].token);
  const jsonResult = JSON.stringify({ targets: [openapi, mcp], status: 'complete' });
  for (const { token } of env.apiRequests) assert.equal(jsonResult.includes(token), false);
  for (const call of env.calls.filter(call => call.mode === 'discovery')) assert.equal(call.authorization, null);
});

test('hostile descriptions and forged final destinations never receive API credentials', async () => {
  const env = await fixture(), id = env.connection.id, target = await env.auth.apiTarget(id, OPENAPI, BASE);
  await assert.rejects(env.auth.apiTarget(id, OPENAPI), { code: 'invalid_target' });
  await assert.rejects(env.auth.apiTarget(id, OPENAPI, 'https://evil.test/v1'), { code: 'invalid_target' });
  await assert.rejects(env.auth.apiFetch(id, new Request('https://evil.test/v1'), target), { code: 'invalid_target' });
  await assert.rejects(env.auth.apiFetch(id, new Request(`${BASE}/records`), { ...target, resource: MCP }), { code: 'invalid_target' });
  const mcp = await env.auth.apiTarget(id, MCP);
  for (const url of [OTHER, `${MCP}/other`, `${MCP}?other=1`]) await assert.rejects(env.auth.apiFetch(id, new Request(url), mcp), { code: 'invalid_target' });
  assert.equal(env.apiRequests.length, 0); assert.deepEqual(env.issued, [null]);
  assert.equal(env.calls.some(call => call.url.startsWith('https://evil.test/v1') && call.authorization), false);
});

test('signed-in MCP acquisition rotates through J2 and sign-out revokes every resource slot', async () => {
  const env = await fixture(), id = env.connection.id, binding = 'trusted-human-browser-binding-012345';
  const begin = await env.auth.beginSignIn(id, { scopes: ['orders:read'], redirectUri: 'https://agent.test/callback', browserBinding: binding });
  const callbackUrl = env.company.authorize(expectValue(begin.authorizationUrl), { account: 'account', approve: ['orders:read'] });
  assert.equal((await env.auth.completeSignIn({ callbackUrl, browserBinding: binding })).status, 'completed');
  const a = await env.auth.apiTarget(id, MCP), b = await env.auth.apiTarget(id, SECURE);
  await env.auth.apiFetch(id, new Request(MCP, { method: 'POST' }), a, ['orders:read']);
  await env.auth.apiFetch(id, new Request(SECURE, { method: 'POST' }), b, ['orders:read']);
  assert.deepEqual(env.apiRequests.map(item => expectValue(item.request.headers.get('authorization')).split(' ')[0]), ['Bearer', 'DPoP']);
  assert.notEqual(env.apiRequests[0].token, env.apiRequests[1].token);
  assert.equal((await env.auth.signOut(id)).cleanup, 'complete');
  assert.deepEqual(env.raw().connections[id].slots, {});
  await assert.rejects(env.auth.apiFetch(id, new Request(MCP), a), { code: 'disconnected' });
});

test('successful Account Token rotation stages its successor without another fallible metadata fetch', async () => {
  const env = await fixture(), id = env.connection.id, binding = 'trusted-human-browser-binding-012345';
  const begin = await env.auth.beginSignIn(id, { scopes: ['orders:read'], redirectUri: 'https://agent.test/callback', browserBinding: binding });
  await env.auth.completeSignIn({ callbackUrl: env.company.authorize(expectValue(begin.authorizationUrl), { account: 'account', approve: ['orders:read'] }), browserBinding: binding });
  const target = await env.auth.apiTarget(id, MCP), before = Object.values(env.raw().grants)[0].secretRef, original = env.company.handle;
  env.company.handle = async (request, options) => {
    const resource = request.url === env.company.tokenEndpoint ? new URLSearchParams(await request.clone().text()).get('resource') : null;
    const response = await original(request, options);
    if (resource === MCP && response.status === 200) env.setMetadata({ resource: 'invalid-after-success' });
    return response;
  };
  assert.equal((await env.auth.apiFetch(id, new Request(MCP), target, ['orders:read'])).status, 200);
  const grant = Object.values(env.raw().grants)[0]; assert.notEqual(grant.secretRef, before); assert.equal(grant.status, 'active'); assert.equal(grant.operationId, null);
  env.company.handle = original; env.setMetadata(null);
  assert.equal((await env.auth.renew(id, { resource: MCP })).status, 'completed', 'the known successor remains usable');
});

test('hostile MCP metadata fails before resource token acquisition; cross-issuer and missing ES256 are rejected', async () => {
  for (const value of [
    { resource: OTHER, authorization_servers: ['https://wrong.test'] },
    { resource: MCP, authorization_servers: ['https://wrong.test'] },
    { resource: MCP, authorization_servers: ['http://bad.test'] },
    { resource: MCP, authorization_servers: ['https://auth.shop.test/tenant'], dpop_signing_alg_values_supported: ['RS256'] },
    { resource: MCP, authorization_servers: ['https://auth.shop.test/tenant'], dpop_signing_alg_values_supported: null },
  ]) { const env = await fixture(); env.setMetadata(value); await assert.rejects(env.auth.apiTarget(env.connection.id, MCP), { code: 'invalid_target' }); assert.deepEqual(env.issued, [null]); }
});

test('a conversation cannot share a Bearer-only MCP resource; sign-in fails before dispatch', async () => {
  const env = await fixture(), id = env.connection.id;
  // A new connection receives this conflicting document; saved destinations are never silently changed.
  env.setDocument(doc => { expectValue(expectValue(doc.agent).protocols.find(entry=>entry.type==='poppy')).resource = MCP; }); expectValue(env.metadata.invalidate).call(env.metadata);
  const fresh = await env.auth.start(env.company.domain); assert.equal(fresh.status, 'completed');
  await assert.rejects(env.auth.apiTarget(fresh.connection.id, MCP), { code: 'invalid_target' });
  await assert.rejects(env.auth.beginSignIn(fresh.connection.id, { scopes: ['orders:read'], redirectUri: 'https://agent.test/callback', browserBinding: 'trusted-human-binding-0123456789' }), { code: 'invalid_target' });
  assert.deepEqual(env.issued, [null, null]);
});

test('browser joining sends a fresh secret form assertion only to a trusted agent controller', async () => {
  const env = await fixture(), id = env.connection.id, forms:Parameters<AgentBrowserController['postForm']>[0][] = [];
  const controller:AgentBrowserController = { kind: 'agent-controlled', async postForm(value) { forms.push(value); } };
  assert.equal(await env.auth.joinBrowser(id, 'https://shop.test/account', controller), undefined);
  await env.auth.joinBrowser(id, 'https://shop.test/account', controller);
  const claims = decodeJwt(forms[0].fields.assertion); assert.equal(claims.aud, 'https://shop.test/browser-session'); assert.equal(claims.session_id, env.connection.sessionId); assert.equal(claims.return_to, 'https://shop.test/account'); assert.equal(expectValue(claims.exp) - expectValue(claims.iat), 60); assert.equal(decodeProtectedHeader(forms[0].fields.assertion).typ, 'poppy-browser+jwt'); assert.notEqual(forms[0].fields.assertion, forms[1].fields.assertion);
  // @ts-expect-error A consent controller must be rejected at runtime.
  await assert.rejects(env.auth.joinBrowser(id, 'https://shop.test/account', { ...controller, kind: 'user-consent' }), { code: 'invalid_browser' });
  for (const url of ['https://shop.test.evil.test/', 'http://shop.test/', 'https://evil.test/']) await assert.rejects(env.auth.joinBrowser(id, url, controller), { code: 'invalid_target' });
  await assert.rejects(env.auth.joinBrowser(id, 'https://shop.test/account', { kind: 'agent-controlled', postForm: async () => { throw new Error(forms[0].fields.assertion); } }), error => error instanceof Error && 'code' in error && error.code === 'browser_failed' && !error.message.includes(forms[0].fields.assertion));
  assert.equal(forms.length, 2); await env.auth.signOut(id);
  await assert.rejects(env.auth.joinBrowser(id, 'https://shop.test/account', controller), { code: 'invalid_browser' });
});

test('trusted browser adapter rejects secret-body redirect replay and blocked actual network destinations', async () => {
  const env = await fixture(), id = env.connection.id, navigations:string[] = [];
  const controller = (status:number,location:string):AgentBrowserController => ({ kind: 'agent-controlled', async postForm(input) { navigations.push(input.validateRedirect(status, location)); } });
  await env.auth.joinBrowser(id, 'https://shop.test/account', controller(303, 'https://shop.test/account'));
  for (const [status, location] of ([[307, 'https://shop.test/account'], [308, 'https://evil.test/'], [303, 'https://evil.test/'], [303, 'https://127.0.0.1/']] satisfies [number,string][])) await assert.rejects(env.auth.joinBrowser(id, 'https://shop.test/account', controller(status, location)), { code: 'browser_failed' });
  assert.deepEqual(navigations, ['https://shop.test/account']);
  env.setDocument(doc => { expectValue(doc.web).browser_session_endpoint = 'https://127.0.0.1/browser-session'; }); expectValue(env.metadata.invalidate).call(env.metadata);
  const connection = (await env.auth.start(env.company.domain)).connection, safe = createNodeTransport();
  try {
    await assert.rejects(env.auth.joinBrowser(connection.id, 'https://shop.test/account', { kind: 'agent-controlled', async postForm(input) {
      await safe.fetch(new Request(input.url, { method: 'POST', body: new URLSearchParams(input.fields), redirect: 'error' }));
    } }), { code: 'browser_failed' });
  } finally { expectValue(safe.close).call(safe); }
});

test('Bearer realm and multiple challenges renew only the selected MCP resource with a new credential', async () => {
  const env = await fixture(), id = env.connection.id, target = await env.auth.apiTarget(id, MCP);
  let requests = 0; env.setReply(() => ++requests === 1 ? new Response(null, { status: 401, headers: { 'www-authenticate': 'DPoP error="invalid_dpop_proof", Bearer realm="tools, one", error="invalid_token"' } }) : Response.json({ ok: true }));
  assert.equal((await env.auth.apiFetch(id, new Request(MCP), target)).status, 200);
  assert.equal(requests, 2); assert.deepEqual(env.issued, [null, MCP, MCP]); assert.notEqual(env.apiRequests[0].token, env.apiRequests[1].token);
});

test('feedback supports signed-out sessions, validates known kinds and lengths, and never retries a rejected or ambiguous POST', async () => {
  const env = await fixture(), id = env.connection.id, report:import('../dist/integrations.js').FeedbackReport = { kind: 'missing', task: 'Export records', description: 'There is no export operation.' };
  assert.equal(await env.auth.feedback(id, report), undefined); assert.equal(env.apiRequests.length, 1);
  for (const input of [{ ...report, kind: 'future' }, { ...report, task: 'x'.repeat(201) }, { ...report, description: 'x'.repeat(2001) }]) {
    // @ts-expect-error Unknown feedback kinds must reach runtime validation.
    await assert.rejects(env.auth.feedback(id,input));
  }
  assert.equal(env.apiRequests.length, 1);
  env.setReply(() => new Response(null, { status: 401, headers: { 'www-authenticate': 'DPoP error="invalid_token"' } }));
  await assert.rejects(env.auth.feedback(id, report), { code: 'feedback_failed' }); assert.equal(env.apiRequests.length, 2);
  env.setReply(() => { throw new Error('lost response'); }); await assert.rejects(env.auth.feedback(id, report)); assert.equal(env.apiRequests.length, 3);
});

test('changed discovery endpoints and disconnected resources fail before another API/browser send', async () => {
  const env = await fixture(), id = env.connection.id, target = await env.auth.apiTarget(id, MCP);
  env.setDocument(doc => { expectValue(doc.apis)[1].url = OTHER; }); expectValue(env.metadata.invalidate).call(env.metadata);
  await assert.rejects(env.auth.apiFetch(id, new Request(MCP), target), { code: 'metadata_changed' }); assert.equal(env.apiRequests.length, 0);
  const fresh = await fixture(), otherTarget = await fresh.auth.apiTarget(fresh.connection.id, MCP);
  await fresh.auth.signOut(fresh.connection.id);
  await assert.rejects(fresh.auth.apiFetch(fresh.connection.id, new Request(MCP), otherTarget), { code: 'disconnected' }); assert.equal(fresh.apiRequests.length, 0);
});
