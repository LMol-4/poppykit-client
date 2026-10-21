// Independent fake Company (discovery, token, authorization and revocation endpoints, conversation resource), written from spec 3, 4.1-4.5, 4.8-4.9.
import { compactVerify, decodeProtectedHeader, importJWK, calculateJwkThumbprint } from 'jose';
import { createHash, randomUUID } from 'node:crypto';

const JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const CLIENT_ASSERTION = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const sha256 = text => createHash('sha256').update(text).digest('base64url');
class Reject extends Error { constructor(status, error, headers = {}) { super(error); this.status = status; this.error = error; this.headers = headers; } }
const json = (status, body, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

// Sessions end after this long without a token issued for them (spec 4.2: the Company decides how long a Session lasts).
const SESSION_IDLE_MS = 86_400_000;

export function createFakeCompany({ name = 'shop', jwks, clientId, now, issuerPath = '/tenant', redirectUris = [], directScopes = ['poppy:read', 'poppy:write'], conversationResource }) {
  const domain = `${name}.test`;
  const issuer = `https://auth.${domain}${issuerPath}`;
  const tokenEndpoint = `${issuer}/token`;
  const endpoint = `https://api.${domain}/poppy/conversations`;
  const authorizationEndpoint = `${issuer}/authorize`;
  const company = {
    domain, issuer, tokenEndpoint, endpoint, authorizationEndpoint, codes: new Map(), grants: new Map(),
    behavior: { requireNonce: false, rotateNonceEveryTime: false, tokenOverride: null, tokenError: null, resourceHandler: null, rotate: true, revokeStatus: 200 },
    revocations: [],
    requests: [], assertions: [], proofs: [],
    sessions: new Map(), tokens: new Map(), seenAssertionJti: new Set(), seenProofJti: new Set(), nonce: null,
  };
  const seconds = () => Math.floor(now() / 1000);
  const newNonce = () => (company.nonce = `n-${randomUUID()}`);
  // A live Session for this User, or invalid_session (spec 4.2, 4.8); issuing a token for it keeps it alive.
  const liveSession = (sessionId, sub) => {
    const session = company.sessions.get(sessionId);
    if (!session || session.expires <= now() || (sub !== undefined && session.sub !== sub)) throw new Reject(400, 'invalid_session');
    session.expires = now() + SESSION_IDLE_MS;
    return session;
  };
  const newSession = (sub, account = null) => { const id = `ses_${randomUUID()}`; company.sessions.set(id, { sub, account, expires: now() + SESSION_IDLE_MS }); return id; };

  // Verifies a client or session assertion; aud is compared character for character with the issuer.
  company.verifyAssertion = async (jwt, kind) => {
    let header, payload;
    try {
      header = decodeProtectedHeader(jwt);
      const jwk = jwks.keys.find(key => key.kid === header.kid);
      if (!jwk || header.alg !== 'ES256') throw 0;
      payload = JSON.parse(new TextDecoder().decode((await compactVerify(jwt, await importJWK(jwk, 'ES256'))).payload));
    } catch { throw new Reject(kind === 'client' ? 401 : 400, kind === 'client' ? 'invalid_client' : 'invalid_grant'); }
    const fail = () => { throw new Reject(400, 'invalid_grant'); };
    if (kind === 'client' && header.typ !== undefined && header.typ !== 'client-authentication+jwt') fail();
    if (payload.iss !== clientId || typeof payload.aud !== 'string' || payload.aud !== issuer) fail();
    if (kind === 'client' && payload.sub !== clientId) fail();
    if (typeof payload.sub !== 'string' || !payload.sub) fail();
    if (!Number.isInteger(payload.iat) || !Number.isInteger(payload.exp) || payload.exp - payload.iat > 300 || payload.exp <= seconds() || payload.iat > seconds() + 60) fail();
    if (typeof payload.jti !== 'string' || payload.jti.length < 16 || payload.jti.length > 256 || company.seenAssertionJti.has(payload.jti)) fail();
    company.seenAssertionJti.add(payload.jti);
    company.assertions.push({ kind, header, payload });
    return payload;
  };

  async function verifyProof(request, token) {
    const values = request.headers.get('dpop');
    if (!values || values.includes(',')) throw new Reject(400, 'invalid_dpop_proof');
    let header, payload;
    try {
      header = decodeProtectedHeader(values);
      if (header.typ !== 'dpop+jwt' || header.alg !== 'ES256' || !header.jwk || 'd' in header.jwk) throw 0;
      payload = JSON.parse(new TextDecoder().decode((await compactVerify(values, await importJWK(header.jwk, 'ES256'))).payload));
    } catch { throw new Reject(400, 'invalid_dpop_proof'); }
    const url = new URL(request.url); url.search = '';
    if (payload.htm !== request.method || payload.htu !== url.href || Math.abs(payload.iat - seconds()) > 60) throw new Reject(400, 'invalid_dpop_proof');
    if (token === undefined ? 'ath' in payload : payload.ath !== sha256(token)) throw new Reject(400, 'invalid_dpop_proof');
    if (token === undefined) { if (company.seenProofJti.has(payload.jti)) throw new Reject(400, 'invalid_dpop_proof'); company.seenProofJti.add(payload.jti); }
    const thumbprint = await calculateJwkThumbprint(header.jwk);
    company.proofs.push({ header, payload, thumbprint });
    if (company.behavior.requireNonce && (payload.nonce === undefined || payload.nonce !== company.nonce || company.behavior.rotateNonceEveryTime)) throw new Reject(400, 'use_dpop_nonce', { 'dpop-nonce': newNonce() });
    return thumbprint;
  }

  // The User's browser at the authorization endpoint (spec 4.5 steps 2-3): approve some scopes for an account, or decline.
  company.authorize = (authorizationUrl, { account, approve = null, deny = false }) => {
    const url = new URL(authorizationUrl); const q = name => url.searchParams.get(name);
    if (url.origin + url.pathname !== authorizationEndpoint || q('response_type') !== 'code' || q('client_id') !== clientId || q('code_challenge_method') !== 'S256' || !q('code_challenge') || !q('state')) throw new Error('bad authorization request');
    if (!redirectUris.includes(q('redirect_uri'))) throw new Error('unregistered redirect_uri');
    const requested = q('scope').split(' ');
    if (!requested.every(scope => directScopes.includes(scope))) throw new Error('invalid_scope');
    const callback = new URL(q('redirect_uri'));
    if (deny) callback.searchParams.set('error', 'access_denied');
    else {
      const code = `code_${randomUUID()}`;
      const scopes = (approve ?? requested).filter(scope => requested.includes(scope));
      company.codes.set(code, { redirectUri: q('redirect_uri'), challenge: q('code_challenge'), scopes, account, resource: q('resource'), used: false });
      callback.searchParams.set('code', code);
    }
    callback.searchParams.set('state', q('state')); callback.searchParams.set('iss', issuer);
    return callback.href;
  };

  async function exchangeCode(request, form) {
    await company.verifyAssertion(form.get('client_assertion'), 'client');
    const jkt = await verifyProof(request);
    const grant = company.codes.get(form.get('code'));
    if (!grant || grant.used) throw new Reject(400, 'invalid_grant');
    grant.used = true;
    if (form.get('redirect_uri') !== grant.redirectUri || sha256(form.get('code_verifier') ?? '') !== grant.challenge || form.get('resource') !== grant.resource) throw new Reject(400, 'invalid_grant');
    const session = liveSession(form.get('session_id'));
    // A Session remembers its account forever (spec 4.4).
    if (session.account && session.account !== grant.account) throw new Reject(400, 'account_mismatch');
    session.account = grant.account;
    const refreshToken = `pat_${randomUUID()}`, accessToken = `tok_${randomUUID()}`;
    company.grants.set(refreshToken, { family: refreshToken, sub: session.sub, account: grant.account, scopes: grant.scopes, revoked: false, rotated: false });
    session.family = refreshToken;
    company.tokens.set(accessToken, { jkt, sessionId: form.get('session_id'), sub: session.sub, account: grant.account, scopes: grant.scopes, resource: grant.resource, family: refreshToken, expires: now() + 3600_000 });
    return json(200, { access_token: accessToken, token_type: 'DPoP', expires_in: 3600, refresh_token: refreshToken, refresh_token_expires_in: 2592000, scope: grant.scopes.join(' '), session_id: form.get('session_id'), signed_in: true, ...company.behavior.tokenOverride }, { 'cache-control': 'no-store' });
  }

  // Revoking a grant signs out every Session signed in with it; they continue signed out (spec 4.9).
  function revokeFamily(family) {
    for (const grant of company.grants.values()) if (grant.family === family) grant.revoked = true;
    for (const session of company.sessions.values()) if (session.family === family) session.family = null;
    for (const token of company.tokens.values()) if (token.family === family) token.expires = 0;
  }

  // Account Token refresh (spec 4.8), rotating on success; without session_id it starts a new signed-in Session; presenting an already-rotated token is reuse and revokes the whole grant (RFC 9700 4.14.2).
  async function refresh(request, form) {
    await company.verifyAssertion(form.get('client_assertion'), 'client');
    const jkt = await verifyProof(request);
    const presented = form.get('refresh_token');
    const grant = company.grants.get(presented);
    if (!grant || grant.revoked) throw new Reject(400, 'invalid_grant');
    if (grant.rotated) { revokeFamily(grant.family); throw new Reject(400, 'invalid_grant'); }
    const sessionId = form.has('session_id') ? form.get('session_id') : newSession(grant.sub, grant.account);
    const session = liveSession(sessionId, grant.sub);
    if (session.account && session.account !== grant.account) throw new Reject(400, 'account_mismatch');
    const scopes = form.has('scope') ? form.get('scope').split(' ') : grant.scopes;
    if (!scopes.every(scope => grant.scopes.includes(scope))) throw new Reject(400, 'invalid_scope');
    session.account = grant.account; session.family = grant.family;
    const body = { token_type: 'DPoP', expires_in: 3600, scope: scopes.join(' '), session_id: sessionId, signed_in: true };
    if (company.behavior.rotate) {
      body.refresh_token = `pat_${randomUUID()}`;
      company.grants.set(body.refresh_token, { ...grant });
      grant.rotated = true;
    }
    body.access_token = `tok_${randomUUID()}`;
    company.tokens.set(body.access_token, { jkt, sessionId, sub: session.sub, account: grant.account, scopes, resource: form.get('resource'), family: grant.family, expires: now() + 3600_000 });
    return json(200, { ...body, ...company.behavior.tokenOverride }, { 'cache-control': 'no-store' });
  }

  // RFC 7009 revocation with client authentication; unknown tokens still get 200.
  async function revoke(request) {
    const form = new URLSearchParams(await request.text());
    if (form.get('client_assertion_type') !== CLIENT_ASSERTION || form.get('client_id') !== clientId) throw new Reject(400, 'invalid_request');
    await company.verifyAssertion(form.get('client_assertion'), 'client');
    company.revocations.push({ token: form.get('token'), hint: form.get('token_type_hint'), dpop: request.headers.has('dpop') });
    if (company.behavior.revokeStatus !== 200) return json(company.behavior.revokeStatus, { error: 'temporarily_unavailable' });
    const grant = company.grants.get(form.get('token'));
    if (grant) revokeFamily(grant.family);
    return new Response(null, { status: 200 });
  }

  async function token(request) {
    if (company.behavior.tokenError) return json(company.behavior.tokenError.status, company.behavior.tokenError.body);
    const form = new URLSearchParams(await request.text());
    if (form.get('client_assertion_type') !== CLIENT_ASSERTION || form.get('client_id') !== clientId) throw new Reject(400, 'invalid_request');
    if (form.get('grant_type') === 'authorization_code') return exchangeCode(request, form);
    if (form.get('grant_type') === 'refresh_token') return refresh(request, form);
    if (form.get('grant_type') !== JWT_BEARER) throw new Reject(400, 'unsupported_grant_type');
    await company.verifyAssertion(form.get('client_assertion'), 'client');
    const assertion = await company.verifyAssertion(form.get('assertion'), 'session');
    const jkt = await verifyProof(request);
    let sessionId = form.get('session_id');
    if (sessionId === null) sessionId = newSession(assertion.sub);
    else liveSession(sessionId, assertion.sub);
    const accessToken = `tok_${randomUUID()}`;
    company.tokens.set(accessToken, { jkt, sessionId, sub: assertion.sub, resource: form.get('resource'), expires: now() + 3600_000 });
    return json(200, { access_token: accessToken, token_type: 'DPoP', expires_in: 3600, scope: '', session_id: sessionId, signed_in: false, ...company.behavior.tokenOverride }, { 'cache-control': 'no-store' });
  }

  async function resource(request) {
    const authorization = request.headers.get('authorization') ?? '';
    const challenge = (error, headers = {}) => new Response(null, { status: 401, headers: { 'www-authenticate': `DPoP error="${error}"`, ...headers } });
    const match = /^DPoP (\S+)$/.exec(authorization);
    if (!match) return challenge('invalid_token');
    const bound = company.tokens.get(match[1]);
    if (!bound || bound.expires <= now()) return challenge('invalid_token');
    // An entry with a resource accepts only tokens issued for it (spec 4.3).
    if (conversationResource && bound.resource !== conversationResource) return challenge('invalid_token');
    let jkt;
    try { jkt = await verifyProof(request, match[1]); } catch (error) { return challenge(error.error, error.headers); }
    if (jkt !== bound.jkt) return challenge('invalid_dpop_proof');
    if (company.behavior.resourceHandler) return company.behavior.resourceHandler(request, bound);
    return json(200, { sub: bound.sub, session_id: bound.sessionId, account: bound.account ?? null, scopes: bound.scopes ?? [], method: request.method, body: await request.text() });
  }

  company.handle = async (request, options) => {
    const url = new URL(request.url);
    company.requests.push({ url: request.url, method: request.method, mode: options?.mode, authorization: request.headers.get('authorization') });
    try {
      if (url.href === `https://${domain}/.well-known/poppy.json`) return json(200, { protocol_version: '0.2', organization: { name, domain }, auth: { issuer, direct: { scopes: directScopes } }, agent: { protocols: [{ type: 'other', endpoint: `https://api.${domain}/other` }, { type: 'poppy', endpoint, ...(conversationResource ? { resource: conversationResource } : {}) }] } });
      if (url.href === `https://auth.${domain}/.well-known/oauth-authorization-server${issuerPath}`) return json(200, { issuer, token_endpoint: tokenEndpoint, revocation_endpoint: `${issuer}/revoke`, authorization_endpoint: authorizationEndpoint, poppy_domains: [domain] });
      if (url.href === tokenEndpoint && request.method === 'POST') return await token(request);
      if (url.href === `${issuer}/revoke` && request.method === 'POST') return await revoke(request);
      if (url.origin === `https://api.${domain}`) return await resource(request);
      return json(404, { error: 'not_found' });
    } catch (error) {
      if (!(error instanceof Reject)) throw error;
      return json(error.status, { error: error.error, error_description: 'internal detail: secret-diagnostic' }, error.headers);
    }
  };
  return company;
}

export function fakeTransport(...companies) {
  const transport = {
    calls: 0, fail: false,
    async fetch(request, options) {
      transport.calls++;
      if (transport.fail) { const { TransportError } = await import('../../dist/network/transport.js'); throw new TransportError('timeout'); }
      const company = companies.find(item => new URL(request.url).hostname.endsWith(item.domain));
      return company ? company.handle(request, options) : json(404, {});
    },
  };
  return transport;
}
