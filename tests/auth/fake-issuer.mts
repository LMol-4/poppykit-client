import { expectValue } from '../../test-support/assertions.mjs';
import assert from 'node:assert/strict';
import type { JWK, ProtectedHeaderParameters } from 'jose';
import type { HttpTransport } from '../../dist/network/transport.js';
// Independent fake Company (discovery, token, authorization and revocation endpoints, conversation resource), written from spec 3, 4.1-4.5, 4.8-4.9.
import { compactVerify, decodeProtectedHeader, importJWK, calculateJwkThumbprint } from 'jose';
import { createHash, randomUUID } from 'node:crypto';


type Options = Parameters<HttpTransport['fetch']>[1];
interface AssertionClaims { iss: string; sub: string; aud: string; iat: number; exp: number; jti: string }
interface ProofClaims { htm: string; htu: string; iat: number; jti: string; ath?: string; nonce?: string }
function assertionClaims(value: unknown): asserts value is AssertionClaims {
  assert.ok(value && typeof value === 'object');
  for (const key of ['iss','sub','aud','jti']) assert.ok(key in value && typeof Reflect.get(value,key) === 'string');
  for (const key of ['iat','exp']) assert.ok(key in value && typeof Reflect.get(value,key) === 'number');
}
function proofClaims(value: unknown): asserts value is ProofClaims {
  assert.ok(value && typeof value === 'object');
  for (const key of ['htm','htu','jti']) assert.ok(key in value && typeof Reflect.get(value,key) === 'string');
  assert.ok('iat' in value && typeof value.iat === 'number');
}
interface Session { agentId?: string; sub: string; account: string | null | undefined; expires: number; family?: string | null }
interface Grant { family: string; sub: string; account: string | undefined; scopes: string[]; revoked: boolean; rotated: boolean }
interface SessionClaims { iss:string;aud:string;sid:string;sub:string;agent_id?:string;htm:string;htu:string;iat:number;jti:string;ath?:string }
interface Bound { tokenType?:'Bearer'|'DPoP'; jkt: string; sessionId: string; sub: string; resource: string | null; expires: number; account?: string; scopes?: string[]; family?: string }
interface Code { sessionKey: string; redirectUri: string; challenge: string; scopes: string[]; account: string | undefined; resource: string | null; used: boolean }
interface FakeOptions { name?: string; jwks: { keys: JWK[] }; clientId: string; now(): number; issuerPath?: string; redirectUris?: string[]; directScopes?: string[]; conversationResource?: string; method?: string }
export interface FakeCompany {
 domain: string; issuer: string; tokenEndpoint: string; endpoint: string; authorizationEndpoint: string;
 codes: Map<string | null, Code>; grants: Map<string | null, Grant>; sessions: Map<string | null, Session>; sessionKeys: Map<string,string>; sessionRequests:{header:ProtectedHeaderParameters;payload:SessionClaims}[]; tokens: Map<string | null | undefined, Bound>;
 behavior: { requireNonce: boolean; rotateNonceEveryTime: boolean; tokenOverride: Record<string, unknown> | null; tokenError: {status:number;body:unknown} | null; resourceHandler: ((request:Request,bound:Bound)=>Response|Promise<Response>) | null; rotate: boolean; revokeStatus: number };
 revocations: {token:string|null;hint:string|null;dpop:boolean}[];
 requests: {url:string;method:string;mode?:'endpoint'|'discovery';authorization:string|null}[];
 assertions: {kind:string;header:ProtectedHeaderParameters;payload:AssertionClaims}[];
 proofs: {header:ProtectedHeaderParameters & {jwk:JWK};payload:ProofClaims;thumbprint:string}[];
 seenAssertionJti: Set<string>; seenProofJti: Set<string>; nonce: string | null;
 devices: Map<string|null,{scopes:string[];used:boolean;sessionKey?:string}>; challenges: Map<string,{clientId:string;scopes:string[];resource:string|null;expires:number}>;
 signInBehavior: {status:string;scopes:string[];account:string;code:string;codeRequired:boolean;attempts:number};
 verifyAssertion(jwt:string|null,kind:string):Promise<AssertionClaims>;
 authorize(url:string,input:{account?:string;approve?:string[]|null;deny?:boolean}):string;
 handle(request:Request,options?:Options):Promise<Response>;
}

const CLIENT_ASSERTION = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const sha256 = (text: string) => createHash('sha256').update(text).digest('base64url');
class Reject extends Error { constructor(readonly status:number, readonly error:string, readonly headers:Record<string,string> = {}) { super(error); } }
const json = (status:number, body:unknown, headers:Record<string,string> = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

// Sessions end after this long without a token issued for them (spec 4.2: the Company decides how long a Session lasts).
const SESSION_IDLE_MS = 86_400_000;

export function createFakeCompany({ name = 'shop', jwks, clientId, now, issuerPath = '/tenant', redirectUris = [], directScopes = ['orders:read', 'orders:write'], conversationResource, method = 'direct' }: FakeOptions) {
  const domain = `${name}.test`;
  const issuer = `https://auth.${domain}${issuerPath}`;
  const tokenEndpoint = `${issuer}/token`;
  const endpoint = `https://api.${domain}/poppy/conversations`;
  const authorizationEndpoint = `${issuer}/authorize`;
  const company: FakeCompany = {
    domain, issuer, tokenEndpoint, endpoint, authorizationEndpoint, codes: new Map(), grants: new Map(),
    behavior: { requireNonce: false, rotateNonceEveryTime: false, tokenOverride: null, tokenError: null, resourceHandler: null, rotate: true, revokeStatus: 200 },
    revocations: [],
    requests: [], assertions: [], proofs: [],
    sessions: new Map(), sessionKeys: new Map(), sessionRequests: [], tokens: new Map(), seenAssertionJti: new Set(), seenProofJti: new Set(), nonce: null,
    devices: new Map(), challenges: new Map(), signInBehavior: { status: 'approved', scopes: directScopes, account: 'acct_1', code: '123456', codeRequired: false, attempts: 0 },
    verifyAssertion: async()=>{throw new Error('uninitialized assertion verifier');}, authorize:()=>{throw new Error('uninitialized authorization');}, handle:async()=>{throw new Error('uninitialized handler');},
  };
  const seconds = () => Math.floor(now() / 1000);
  const newNonce = () => (company.nonce = `n-${randomUUID()}`);
  // Verifies a client or session assertion; aud is compared character for character with the issuer.
  company.verifyAssertion = async (jwt, kind) => {
    let header: ProtectedHeaderParameters; let payload: unknown;
    try {
      assert.ok(jwt); header = decodeProtectedHeader(jwt);
      const jwk = jwks.keys.find(key => key.kid === header.kid);
      if (!jwk || header.alg !== 'ES256') throw 0;
      payload = JSON.parse(new TextDecoder().decode((await compactVerify(jwt, await importJWK(jwk, 'ES256'))).payload));
      assertionClaims(payload);
    } catch { throw new Reject(kind === 'client' ? 401 : 400, kind === 'client' ? 'invalid_client' : 'invalid_grant'); }
    assertionClaims(payload);
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

  async function verifyProof(request:Request, token?:string) {
    const values = request.headers.get('dpop');
    if (!values || values.includes(',')) throw new Reject(400, 'invalid_dpop_proof');
    let header:ProtectedHeaderParameters; let payload:unknown;
    try {
      header = decodeProtectedHeader(values);
      if (header.typ !== 'dpop+jwt' || header.alg !== 'ES256' || !header.jwk || 'd' in header.jwk) throw 0;
      payload = JSON.parse(new TextDecoder().decode((await compactVerify(values, await importJWK(header.jwk, 'ES256'))).payload));
    proofClaims(payload);
    } catch { throw new Reject(400, 'invalid_dpop_proof'); }
    proofClaims(payload); assert.ok(header.jwk);
    const url = new URL(request.url); url.search = '';
    if (payload.htm !== request.method || payload.htu !== url.href || Math.abs(payload.iat - seconds()) > 60) throw new Reject(400, 'invalid_dpop_proof');
    if (token === undefined ? 'ath' in payload : payload.ath !== sha256(token)) throw new Reject(400, 'invalid_dpop_proof');
    if (token === undefined) { if (company.seenProofJti.has(payload.jti)) throw new Reject(400, 'invalid_dpop_proof'); company.seenProofJti.add(payload.jti); }
    const thumbprint = await calculateJwkThumbprint(header.jwk);
    company.proofs.push({ header: {...header,jwk:header.jwk}, payload, thumbprint });
    if (company.behavior.requireNonce && (payload.nonce === undefined || payload.nonce !== company.nonce || company.behavior.rotateNonceEveryTime)) throw new Reject(400, 'use_dpop_nonce', { 'dpop-nonce': newNonce() });
    return thumbprint;
  }

  // The User's browser at the authorization endpoint (spec 4.5 steps 2-3): approve some scopes for an account, or decline.
  company.authorize = (authorizationUrl, { account, approve = null, deny = false }) => {
    const url = new URL(authorizationUrl); const q = (name:string) => url.searchParams.get(name);
    if (url.origin + url.pathname !== authorizationEndpoint || q('response_type') !== 'code' || q('client_id') !== clientId || q('code_challenge_method') !== 'S256' || !q('code_challenge') || !q('state') || !/^[A-Za-z0-9_-]{43}$/.test(q('dpop_jkt') ?? '')) throw new Error('bad authorization request');
    if (!redirectUris.includes(expectValue(q('redirect_uri')))) throw new Error('unregistered redirect_uri');
    const requested = expectValue(q('scope')).split(' ');
    if (!requested.every(scope => directScopes.includes(scope))) throw new Error('invalid_scope');
    const callback = new URL(expectValue(q('redirect_uri')));
    if (deny) callback.searchParams.set('error', 'access_denied');
    else {
      const code = `code_${randomUUID()}`;
      const scopes = (approve ?? requested).filter(scope => requested.includes(scope));
      company.codes.set(code, { sessionKey: expectValue(q('dpop_jkt')), redirectUri: expectValue(q('redirect_uri')), challenge: expectValue(q('code_challenge')), scopes, account, resource: q('resource'), used: false });
      callback.searchParams.set('code', code);
    }
    callback.searchParams.set('state',expectValue(q('state'))); callback.searchParams.set('iss', issuer);
    return callback.href;
  };

  async function exchangeCode(request:Request, form:URLSearchParams) {
    await company.verifyAssertion(form.get('client_assertion'), 'client');
    const jkt = request.headers.has('dpop') ? await verifyProof(request) : '';
    const grant = company.codes.get(form.get('code'));
    if (!grant || grant.used || grant.sessionKey !== jkt) throw new Reject(400, 'invalid_grant');
    grant.used = true;
    if (form.get('redirect_uri') !== grant.redirectUri || sha256(form.get('code_verifier') ?? '') !== grant.challenge || form.get('resource') !== grant.resource) throw new Reject(400, 'invalid_grant');
    return issueSignedIn(jkt, grant.account, grant.scopes, grant.resource);
  }
  function issueSignedIn(jkt:string,account:string|undefined,scopes:string[],resource:string|null) {
    const refreshToken = `pat_${randomUUID()}`, accessToken = `tok_${randomUUID()}`;
    company.grants.set(refreshToken, { family: refreshToken, sub:'', account, scopes, revoked: false, rotated: false });
    company.tokens.set(accessToken, { jkt, sessionId:'', sub:'', account, scopes, resource, family: refreshToken, expires: now() + 3600_000, tokenType:jkt?'DPoP':'Bearer' });
    return json(200, { access_token: accessToken, token_type: jkt?'DPoP':'Bearer', expires_in: 3600, refresh_token: refreshToken, refresh_token_expires_in: 2592000, scope: scopes.join(' '), ...company.behavior.tokenOverride }, { 'cache-control': 'no-store' });
  }

  // Revoking a grant signs out every Session signed in with it; they continue signed out (spec 4.9).
  function revokeFamily(family:string) {
    for (const grant of company.grants.values()) if (grant.family === family) grant.revoked = true;
    for (const session of company.sessions.values()) if (session.family === family) session.family = null;
    for (const token of company.tokens.values()) if (token.family === family) token.expires = 0;
  }

  // Account Token refresh (spec 4.8), rotating on success; without session_id it starts a new signed-in Session; presenting an already-rotated token is reuse and revokes the whole grant (RFC 9700 4.14.2).
  async function refresh(request:Request,form:URLSearchParams) {
    await company.verifyAssertion(form.get('client_assertion'), 'client');
    const jkt = request.headers.has('dpop') ? await verifyProof(request) : '';
    const presented = form.get('refresh_token');
    const grant = company.grants.get(presented);
    if (!grant || grant.revoked) throw new Reject(400, 'invalid_grant');
    if (grant.rotated) { revokeFamily(grant.family); throw new Reject(400, 'invalid_grant'); }
    const scopes = form.has('scope') ? (form.get('scope')??'').split(' ') : grant.scopes;
    if (!scopes.every(scope => grant.scopes.includes(scope))) throw new Reject(400, 'invalid_scope');
    const body: {token_type:string;expires_in:number;scope:string;refresh_token?:string;access_token?:string} = { token_type: jkt?'DPoP':'Bearer', expires_in: 3600, scope: scopes.join(' ') };
    if (company.behavior.rotate) {
      body.refresh_token = `pat_${randomUUID()}`;
      company.grants.set(body.refresh_token, { ...grant });
      grant.rotated = true;
    }
    body.access_token = `tok_${randomUUID()}`;
    company.tokens.set(body.access_token, { jkt, tokenType:jkt?'DPoP':'Bearer', sessionId:'', sub:'', account: grant.account, scopes, resource: form.get('resource'), family: grant.family, expires: now() + 3600_000 });
    return json(200, { ...body, ...company.behavior.tokenOverride }, { 'cache-control': 'no-store' });
  }

  // RFC 7009 revocation with client authentication; unknown tokens still get 200.
  async function revoke(request:Request) {
    const form = new URLSearchParams(await request.text());
    assert.equal(form.has('session_id'), false, 'token requests use only standard parameters');
    if (form.get('client_assertion_type') !== CLIENT_ASSERTION || form.get('client_id') !== clientId) throw new Reject(400, 'invalid_request');
    await company.verifyAssertion(form.get('client_assertion'), 'client');
    company.revocations.push({ token: form.get('token'), hint: form.get('token_type_hint'), dpop: request.headers.has('dpop') });
    if (company.behavior.revokeStatus !== 200) return json(company.behavior.revokeStatus, { error: 'temporarily_unavailable' });
    const grant = company.grants.get(form.get('token'));
    if (grant) revokeFamily(grant.family);
    return new Response(null, { status: 200 });
  }

  async function token(request:Request) {
    if (company.behavior.tokenError) return json(company.behavior.tokenError.status, company.behavior.tokenError.body);
    const form = new URLSearchParams(await request.text());
    if (form.get('client_assertion_type') !== CLIENT_ASSERTION || form.get('client_id') !== clientId) throw new Reject(400, 'invalid_request');
    if (form.get('grant_type') === 'authorization_code') return exchangeCode(request, form);
    if (form.get('grant_type') === 'urn:ietf:params:oauth:grant-type:device_code') {
      await company.verifyAssertion(form.get('client_assertion'), 'client'); const jkt = request.headers.has('dpop') ? await verifyProof(request) : '';
      const device = company.devices.get(form.get('device_code'));
      if (!device || device.used) throw new Reject(400, 'invalid_grant');
      const behavior = company.signInBehavior;
      if (behavior.status !== 'approved') throw new Reject(400, behavior.status);
      device.used = true;
      return issueSignedIn(jkt, behavior.account, behavior.scopes.filter(scope => device.scopes.includes(scope)), form.get('resource'));
    }
    if (form.get('grant_type') === 'refresh_token') return refresh(request, form);
    if (form.get('grant_type') === 'https://personalagentprotocol.org/grant/mediated-sign-in') {
      await company.verifyAssertion(form.get('client_assertion'),'client');
      const jkt=request.headers.has('dpop')?await verifyProof(request):'',behavior=company.signInBehavior,id=form.get('sign_in_id');
      let scopes:string[],resource:string|null;
      if(id){
        const challenge=company.challenges.get(id);
        if(!challenge||challenge.clientId!==clientId)throw new Reject(400,'invalid_grant');
        if(challenge.expires<=now())throw new Reject(400,'expired_token');
        assert.equal(form.has('scope'),false);assert.equal(form.has('password'),false);
        if(++behavior.attempts>=3)throw new Reject(400,'invalid_grant');
        if(form.get('one_time_code')!==behavior.code)return json(400,{error:'code_required',sign_in_id:id,sent_to:'Your phone',expires_in:Math.ceil((challenge.expires-now())/1000)});
        scopes=challenge.scopes;resource=challenge.resource;company.challenges.delete(id);
      }else{
        if(!form.get('password')||behavior.status==='access_denied')throw new Reject(400,'invalid_grant');
        scopes=(form.get('scope')??'').split(' ');resource=form.get('resource');
        if(behavior.codeRequired){const id=randomUUID();company.challenges.set(id,{clientId,scopes,resource,expires:now()+60000});return json(400,{error:'code_required',sign_in_id:id,sent_to:'Your phone',expires_in:60});}
      }
      return issueSignedIn(jkt,behavior.account,behavior.scopes.filter(scope=>scopes.includes(scope)),resource);
    }
    throw new Reject(400,'unsupported_grant_type');
  }

  // This peer builds its verification independently of the SDK's Session codec.
  async function verifySession(request:Request,token?:string):Promise<SessionClaims> {
    try {
      const jwt=request.headers.get('poppy-session');assert.ok(jwt);const header=decodeProtectedHeader(jwt);
      assert.equal(header.typ,'poppy-session+jwt');assert.equal(header.alg,'ES256');assert.equal(typeof header.pap_dlg,'string');
      const delegation=header.pap_dlg as string,delegationHeader=decodeProtectedHeader(delegation),root=jwks.keys.find(key=>key.kid===delegationHeader.kid);assert.ok(root);assert.equal(delegationHeader.typ,'pap-delegation+jwt');
      const delegated=JSON.parse(new TextDecoder().decode((await compactVerify(delegation,await importJWK(root,'ES256'),{algorithms:['ES256']})).payload));
      assert.equal(delegated.iss,clientId);assert.ok(delegated.exp>seconds()&&delegated.exp-delegated.iat<=86400);assert.ok(!('d' in delegated.cnf.jwk));assert.equal(header.kid,await calculateJwkThumbprint(delegated.cnf.jwk));
      const claims=JSON.parse(new TextDecoder().decode((await compactVerify(jwt,await importJWK(delegated.cnf.jwk,'ES256'),{algorithms:['ES256']})).payload)) as SessionClaims;
      assert.equal(claims.iss,clientId);assert.equal(claims.aud,issuer);assert.equal(claims.htm,request.method);const url=new URL(request.url);assert.equal(claims.htu,url.origin+url.pathname);assert.ok(claims.iat>=seconds()-60&&claims.iat<=seconds()+30);assert.ok(claims.iat<=delegated.exp);
      assert.match(claims.sid,/^[A-Za-z0-9_-]{1,256}$/);assert.ok(claims.sub);assert.ok(claims.jti);
      assert.equal(claims.ath,token===undefined?undefined:sha256(token));if(token===undefined)assert.equal('ath' in claims,false);
      const old=company.sessions.get(claims.sid);
      if(old){assert.ok(old.expires>now());assert.equal(old.sub,claims.sub);assert.equal(old.agentId,claims.agent_id);}
      else company.sessions.set(claims.sid,{sub:claims.sub,agentId:claims.agent_id,account:null,expires:now()+SESSION_IDLE_MS});
      company.sessionRequests.push({header,payload:claims});return claims;
    }catch{throw new Reject(400,'invalid_session');}
  }

  async function resource(request:Request) {
    const authorization=request.headers.get('authorization');
    const challenge=(error:string,headers:Record<string,string>={})=>new Response(null,{status:401,headers:{'www-authenticate':`DPoP error="${error}", Bearer error="${error}"`,...headers}});
    let credential:Bound|undefined,access:string|undefined;
    if(authorization){
      const match=/^(DPoP|Bearer) (\S+)$/.exec(authorization);if(!match)return challenge('invalid_token');
      access=match[2];credential=company.tokens.get(access);if(!credential||credential.expires<=now()||(conversationResource&&credential.resource!==conversationResource))return challenge('invalid_token');
      if(match[1]==='DPoP'){
        let jkt;try{jkt=await verifyProof(request,access);}catch(error){if(!(error instanceof Reject))throw error;return challenge(error.error,error.headers);}
        if(jkt!==credential.jkt)return challenge('invalid_dpop_proof');
      }else if(credential.jkt)return challenge('invalid_token');
    }
    const claims=await verifySession(request,access),session=expectValue(company.sessions.get(claims.sid));
    if(credential?.account){if(session.account&&session.account!==credential.account)throw new Reject(400,'invalid_session');session.account=credential.account;session.family=credential.family;}
    if(credential?.jkt)company.sessionKeys.set(credential.jkt,claims.sid); // Diagnostic only; never used to identify or admit a Session.
    const bound:Bound={jkt:credential?.jkt??'',sessionId:claims.sid,sub:claims.sub,resource:credential?.resource??null,expires:session.expires,...(credential?{account:credential.account,scopes:credential.scopes,family:credential.family}:{})};
    if (company.behavior.resourceHandler) return company.behavior.resourceHandler(request, bound);
    return json(200, { sub: bound.sub, session_id: bound.sessionId, account: bound.account ?? null, scopes: bound.scopes ?? [], method: request.method, body: await request.text() });
  }

  company.handle = async (request, options) => {
    const url = new URL(request.url);
    company.requests.push({ url: request.url, method: request.method, mode: options?.mode, authorization: request.headers.get('authorization') });
    try {
      if (url.href === `https://${domain}/.well-known/oauth-protected-resource`) return json(200, { resource: `https://${domain}`, authorization_servers: [issuer] });
      if (url.pathname.startsWith('/.well-known/oauth-protected-resource')) return conversationResource ? json(200,{resource:conversationResource,authorization_servers:[issuer]}) : new Response(null,{status:404});
      if (url.href === `https://${domain}/.well-known/poppy.json`) return json(200, { protocol_version: '0.3', organization: { name, domain }, ...(method==='mediated'?{extensions:{'mediated-sign-in':{version:'1',scopes:directScopes,fields:[{name:'password',label:'Password',secret:true}]}}}:{}), auth: { issuer, scopes: Object.fromEntries(directScopes.map(scope => [scope, `Company permission ${scope}`])),  }, agent: { protocols: [{ type: 'other', endpoint: `https://api.${domain}/other` }, { type: 'poppy', endpoint, ...(conversationResource ? { resource: conversationResource } : {}) }] } });
      if (url.href === `https://auth.${domain}/.well-known/oauth-authorization-server${issuerPath}`) return json(200, { issuer, token_endpoint: tokenEndpoint, revocation_endpoint: `${issuer}/revoke`, ...(method === 'direct' ? { authorization_endpoint: authorizationEndpoint } : {}), ...(method === 'device' ? { device_authorization_endpoint: `${issuer}/device` } : {}), protected_resources: [`https://${domain}`], dpop_signing_alg_values_supported:['ES256'],grant_types_supported: ['refresh_token',...(method==='mediated'?['https://personalagentprotocol.org/grant/mediated-sign-in']:[]), ...(method === 'direct' ? ['authorization_code'] : []), ...(method === 'device' ? ['urn:ietf:params:oauth:grant-type:device_code'] : [])], scopes_supported: directScopes });
      if (url.href === `${issuer}/device`) {
        const form = new URLSearchParams(await request.text()); await company.verifyAssertion(form.get('client_assertion'), 'client');
        const code = randomUUID(); company.devices.set(code, { scopes: expectValue(form.get('scope')).split(' '), used: false });
        return json(200, { device_code: code, user_code: 'ABCD-EFGH', verification_uri: `${issuer}/approve`, expires_in: 600, interval: 5 });
      }
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

export function fakeTransport(...companies:FakeCompany[]) {
  const transport:HttpTransport & {calls:number;fail:boolean} = {
    calls: 0, fail: false,
    async fetch(request:Request, options?:Options) {
      transport.calls++;
      if (transport.fail) { const { TransportError } = await import('../../dist/network/transport.js'); throw new TransportError('timeout'); }
      const company = companies.find(item => new URL(request.url).hostname.endsWith(item.domain));
      return company ? company.handle(request, options) : json(404, {});
    },
  };
  return transport;
}
