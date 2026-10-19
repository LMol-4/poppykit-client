// Independent fake Company (discovery + token endpoint + conversation resource), written from spec 3, 4.1-4.3.
import { compactVerify, decodeProtectedHeader, importJWK, calculateJwkThumbprint } from 'jose';
import { createHash, randomUUID } from 'node:crypto';

const JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const CLIENT_ASSERTION = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const sha256 = text => createHash('sha256').update(text).digest('base64url');
class Reject extends Error { constructor(status, error, headers = {}) { super(error); this.status = status; this.error = error; this.headers = headers; } }
const json = (status, body, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

export function createFakeCompany({ name = 'shop', jwks, clientId, now, issuerPath = '/tenant' }) {
  const domain = `${name}.test`;
  const issuer = `https://auth.${domain}${issuerPath}`;
  const tokenEndpoint = `${issuer}/token`;
  const endpoint = `https://api.${domain}/poppy/conversations`;
  const company = {
    domain, issuer, tokenEndpoint, endpoint,
    behavior: { requireNonce: false, rotateNonceEveryTime: false, tokenOverride: null, tokenError: null, resourceHandler: null },
    requests: [], assertions: [], proofs: [],
    sessions: new Map(), tokens: new Map(), seenAssertionJti: new Set(), seenProofJti: new Set(), nonce: null,
  };
  const seconds = () => Math.floor(now() / 1000);
  const newNonce = () => (company.nonce = `n-${randomUUID()}`);

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

  async function token(request) {
    if (company.behavior.tokenError) return json(company.behavior.tokenError.status, company.behavior.tokenError.body);
    const form = new URLSearchParams(await request.text());
    if (form.get('grant_type') !== JWT_BEARER || form.get('client_assertion_type') !== CLIENT_ASSERTION || form.get('client_id') !== clientId) throw new Reject(400, 'invalid_request');
    await company.verifyAssertion(form.get('client_assertion'), 'client');
    const assertion = await company.verifyAssertion(form.get('assertion'), 'session');
    const jkt = await verifyProof(request);
    let sessionId = form.get('session_id');
    if (sessionId === null) { sessionId = `ses_${randomUUID()}`; company.sessions.set(sessionId, { sub: assertion.sub }); }
    else if (company.sessions.get(sessionId)?.sub !== assertion.sub) throw new Reject(400, 'invalid_session');
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
    let jkt;
    try { jkt = await verifyProof(request, match[1]); } catch (error) { return challenge(error.error, error.headers); }
    if (jkt !== bound.jkt) return challenge('invalid_dpop_proof');
    if (company.behavior.resourceHandler) return company.behavior.resourceHandler(request, bound);
    return json(200, { sub: bound.sub, session_id: bound.sessionId, method: request.method, body: await request.text() });
  }

  company.handle = async (request, options) => {
    const url = new URL(request.url);
    company.requests.push({ url: request.url, method: request.method, mode: options?.mode, authorization: request.headers.get('authorization') });
    try {
      if (url.href === `https://${domain}/.well-known/poppy.json`) return json(200, { protocol_version: '0.2', organization: { name, domain }, auth: { issuer }, agent: { protocols: [{ type: 'other', endpoint: `https://api.${domain}/other` }, { type: 'poppy', endpoint }] } });
      if (url.href === `https://auth.${domain}/.well-known/oauth-authorization-server${issuerPath}`) return json(200, { issuer, token_endpoint: tokenEndpoint, revocation_endpoint: `${issuer}/revoke`, poppy_domains: [domain] });
      if (url.href === tokenEndpoint && request.method === 'POST') return await token(request);
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
