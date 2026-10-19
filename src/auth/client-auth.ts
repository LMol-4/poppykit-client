import { calculateJwkThumbprint } from 'jose';
import { parseProtocolError, parseTokenResponse } from '../protocol/wire.js';
import type { JsonObject, TokenResponse } from '../protocol/wire.js';
import { validateClientId } from '../network/discovery.js';
import type { CompanyMetadata, MetadataResolver } from '../network/discovery.js';
import type { HttpTransport } from '../network/transport.js';

export interface StateStore<S> {
  read(): Promise<S>;
  transaction<T>(change: (draft: S) => T): Promise<T>;
}
export interface SecretStore {
  stage(secret: string): Promise<string>;
  read(reference: string): Promise<string | null>;
  remove(reference: string): Promise<void>;
}
export interface IdentitySigner {
  // ES256 JOSE compact JWS; kid selects a public key in the host's published JWKS.
  readonly kid: string;
  publicJwk(): Promise<JsonObject>;
  // Exactly 64-byte IEEE-P1363 signature over the input, not DER.
  sign(input: Uint8Array): Promise<Uint8Array>;
}
export interface ClientAuthOptions {
  namespace: string; localUserId: string; clientId: string;
  redirectUris: readonly string[]; // used by Direct Sign-In (J09)
  identity: IdentitySigner;
  store: StateStore<ClientAuthState>; secrets: SecretStore;
  transport: HttpTransport; metadata: MetadataResolver;
  now?: () => number;
}

export type ConnectionStatus = 'signed_out' | 'signed_in' | 'disconnected' | 'uncertain';
export interface Connection {
  id: string; domain: string; issuer: string;
  sessionId: string | null; generation: number; status: ConnectionStatus;
  scopes: string[];
}
export type OperationStatus = 'pending' | 'completed' | 'denied' | 'expired' | 'cancelled' | 'failed' | 'uncertain';
export interface AuthOutcome {
  operationId: string; status: OperationStatus; connection: Connection;
  error?: string; missingScopes?: string[];
  nextAction?: 'wait' | 'sign_in' | 'retry_cleanup';
}
export interface ConversationTarget { issuer: string; endpoint: string; resource?: string }
export interface ClientAuth {
  start(domain: string): Promise<AuthOutcome>;
  get(connectionId: string): Promise<Connection | null>;
  list(): Promise<Connection[]>;
  target(connectionId: string): Promise<ConversationTarget>;
  authorizedFetch(connectionId: string, request: Request, target: ConversationTarget, requiredScopes?: readonly string[]): Promise<Response>;
}

export interface CredentialRecord {
  secretRef: string; tokenType: 'DPoP'; dpopKeyRef: string;
  scopes: string[]; expiresAt: number; generation: number;
}
export interface ConnectionRecord {
  id: string; domain: string; issuer: string; metadata: CompanyMetadata;
  userId: string; dpopKeyRef: string; sessionId: string | null;
  generation: number; status: ConnectionStatus; grantId: string | null;
  // Key JSON.stringify([sessionId, resource ?? null]); preserves absent vs exact resource.
  slots: Record<string, CredentialRecord>;
}
export interface OperationRecord {
  epoch: string; id: string; kind: 'start' | 'renew' | 'sign_in'; connectionId: string;
  connectionGeneration: number; grantId: string | null; grantGeneration: number | null;
  phase: 'prepared' | 'dispatched' | 'staged' | 'terminal';
  status: OperationStatus; createdAt: number; expiresAt: number;
  resource: string | null; scopes: string[];
  direct: JsonObject | null; staged: JsonObject | null;
  result: AuthOutcome | null;
}
export interface ClientAuthState {
  version: 1; epoch: string;
  owner: { namespace: string; clientId: string; localUserId: string } | null;
  identities: Record<string, { userId: string; dpopKeyRef: string }>;
  connections: Record<string, ConnectionRecord>;
  // Grant and cleanup records arrive with sign-in and sign-out (J09).
  grants: Record<string, JsonObject>;
  operations: Record<string, OperationRecord>;
  cleanup: Record<string, JsonObject>;
}

export class AuthFailure extends Error {
  constructor(readonly code: string, readonly connectionId?: string) { super(`Auth ${code}`); this.name = 'AuthFailure'; }
}

const EC = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const ES256 = { name: 'ECDSA', hash: 'SHA-256' } as const;
const SKEW_MS = 30_000;
const ASSERTION_SECONDS = 60;
// OAuth codes the token endpoint may return (spec 4.2, RFC 6749/8707); anything else is reported as token_error.
const SAFE_ERRORS = new Set(['invalid_request', 'invalid_client', 'invalid_grant', 'unauthorized_client', 'unsupported_grant_type', 'invalid_scope', 'invalid_target', 'invalid_session', 'account_mismatch', 'invalid_dpop_proof', 'use_dpop_nonce', 'extension_required', 'rate_limited']);

const b64 = (data: Uint8Array | string) => Buffer.from(data).toString('base64url');
const randomId = (prefix = '') => prefix + b64(crypto.getRandomValues(new Uint8Array(16)));
const own = <T>(record: Record<string, T>, key: string): T | undefined => Object.hasOwn(record, key) ? record[key] : undefined;
const slotKey = (sessionId: string | null, resource: string | null) => JSON.stringify([sessionId, resource]);

export function initialClientAuthState(): ClientAuthState {
  return { version: 1, epoch: randomId(), owner: null, identities: {}, connections: {}, grants: {}, operations: {}, cleanup: {} };
}

type PublicEcJwk = { kty: 'EC'; crv: 'P-256'; x: string; y: string };
function publicEcJwk(value: unknown, code: string): PublicEcJwk {
  const jwk = (value ?? {}) as Record<string, unknown>;
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string' || 'd' in jwk) throw new AuthFailure(code);
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
}
async function compact(header: JsonObject, payload: JsonObject, sign: (input: Uint8Array<ArrayBuffer>) => Promise<Uint8Array>): Promise<string> {
  const input = `${b64(JSON.stringify(header))}.${b64(JSON.stringify(payload))}`;
  return `${input}.${b64(await sign(new TextEncoder().encode(input)))}`;
}
function challengeError(header: string | null): string | undefined {
  if (!header || !/^\s*DPoP\b/i.test(header)) return undefined;
  return /\berror\s*=\s*"?([A-Za-z0-9_]+)"?/.exec(header)?.[1];
}

interface DpopKey { privateKey: CryptoKey; jwk: PublicEcJwk; thumbprint: string }

export function createClientAuth(options: ClientAuthOptions): ClientAuth {
  const { namespace, localUserId, clientId, identity, store, secrets, transport } = options;
  const now = options.now ?? Date.now;
  if (typeof namespace !== 'string' || !namespace || typeof localUserId !== 'string' || !localUserId) throw new AuthFailure('invalid_options');
  try { validateClientId(clientId); } catch { throw new AuthFailure('invalid_options'); }
  const owner = { namespace, clientId, localUserId };
  // shortcut: nonces live in memory per origin, so a restart costs one extra use_dpop_nonce round trip.
  const nonces = new Map<string, string>();

  function checkOwner(state: ClientAuthState): void {
    if (state.owner && (state.owner.namespace !== namespace || state.owner.clientId !== clientId || state.owner.localUserId !== localUserId)) throw new AuthFailure('owner_mismatch');
  }
  async function load(): Promise<ClientAuthState> { const state = await store.read(); checkOwner(state); return state; }
  function transaction<T>(change: (state: ClientAuthState) => T): Promise<T> {
    return store.transaction(state => { checkOwner(state); state.owner ??= owner; return change(state); });
  }
  async function record(connectionId: string): Promise<ConnectionRecord> {
    const found = typeof connectionId === 'string' ? own((await load()).connections, connectionId) : undefined;
    if (!found) throw new AuthFailure('unknown_connection');
    return found;
  }
  function publicConnection(connection: ConnectionRecord): Connection {
    const { id, domain, issuer, sessionId, generation, status } = connection;
    return { id, domain, issuer, sessionId, generation, status, scopes: [] };
  }

  async function loadDpopKey(reference: string): Promise<DpopKey> {
    const text = await secrets.read(reference);
    if (text === null) throw new AuthFailure('missing_key');
    const { d, ...rest } = JSON.parse(text) as Record<string, unknown>;
    const jwk = publicEcJwk(rest, 'missing_key');
    const privateKey = await crypto.subtle.importKey('jwk', { ...jwk, d } as JsonWebKey, EC, false, ['sign']);
    return { privateKey, jwk, thumbprint: await calculateJwkThumbprint(jwk) };
  }
  async function signIdentity(header: JsonObject, payload: JsonObject, dpopThumbprint: string): Promise<string> {
    const jwk = publicEcJwk(await identity.publicJwk(), 'invalid_signer');
    if (await calculateJwkThumbprint(jwk) === dpopThumbprint) throw new AuthFailure('key_separation');
    let key: CryptoKey;
    try { key = await crypto.subtle.importKey('jwk', jwk, EC, false, ['verify']); } catch { throw new AuthFailure('invalid_signer'); }
    return compact({ ...header, alg: 'ES256', kid: identity.kid }, payload, async input => {
      const signature = await identity.sign(input);
      // A signer that silently uses another key or DER encoding would produce assertions every Company rejects.
      if (!(signature instanceof Uint8Array) || signature.length !== 64 || !await crypto.subtle.verify(ES256, key, new Uint8Array(signature), input)) throw new AuthFailure('invalid_signer');
      return signature;
    });
  }
  async function proof(key: DpopKey, method: string, url: string, token?: string): Promise<string> {
    const htu = new URL(url); htu.search = ''; htu.hash = '';
    const payload: JsonObject = { jti: randomId(), htm: method, htu: htu.href, iat: Math.floor(now() / 1000) };
    if (token !== undefined) payload.ath = b64(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))));
    const nonce = nonces.get(htu.origin);
    if (nonce !== undefined) payload.nonce = nonce;
    return compact({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.jwk }, payload, async input => new Uint8Array(await crypto.subtle.sign(ES256, key.privateKey, input)));
  }
  function rememberNonce(url: string, response: Response): void {
    const nonce = response.headers.get('dpop-nonce');
    if (nonce) nonces.set(new URL(url).origin, nonce);
  }

  // Signed-out Session Token via the JWT bearer grant (spec 4.2); renewal passes session_id.
  async function signedOutToken(metadata: CompanyMetadata, userId: string, dpopKeyRef: string, sessionId: string | null, resource: string | null): Promise<TokenResponse> {
    const authorization = metadata.authorization!;
    const endpoint = authorization.token_endpoint;
    const key = await loadDpopKey(dpopKeyRef);
    for (let attempt = 0; ; attempt++) {
      const iat = Math.floor(now() / 1000);
      const claims = (sub: string) => ({ iss: clientId, sub, aud: authorization.issuer, iat, exp: iat + ASSERTION_SECONDS, jti: randomId() });
      const body = new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: await signIdentity({ typ: 'JWT' }, claims(userId), key.thumbprint),
        client_id: clientId,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: await signIdentity({ typ: 'client-authentication+jwt' }, claims(clientId), key.thumbprint),
      });
      if (sessionId !== null) body.set('session_id', sessionId);
      if (resource !== null) body.set('resource', resource);
      const request = new Request(endpoint, { method: 'POST', body, headers: { accept: 'application/json', dpop: await proof(key, 'POST', endpoint) } });
      let response: Response;
      try { response = await transport.fetch(request); } catch { throw new AuthFailure('transport_error'); }
      rememberNonce(endpoint, response);
      const json: unknown = await response.json().catch(() => undefined);
      if (response.status === 200) {
        let token: TokenResponse;
        try { token = parseTokenResponse(json); } catch { throw new AuthFailure('invalid_response'); }
        // Only DPoP is executable; a Bearer token is never used as a fallback.
        if (token.token_type !== 'DPoP') throw new AuthFailure('unsupported_token_type');
        if (token.signed_in !== false || token.scope !== '' || (sessionId !== null && token.session_id !== sessionId)) throw new AuthFailure('invalid_response');
        return token;
      }
      let error = 'token_error';
      try { error = parseProtocolError(json).error; } catch { /* non-OAuth body */ }
      if (error === 'use_dpop_nonce' && response.status === 400 && attempt === 0 && response.headers.has('dpop-nonce')) continue;
      throw new AuthFailure(SAFE_ERRORS.has(error) ? error : 'token_error');
    }
  }

  async function identityFor(issuer: string): Promise<{ userId: string; dpopKeyRef: string }> {
    const existing = own((await load()).identities, issuer);
    if (existing) return existing;
    const pair = await crypto.subtle.generateKey(EC, true, ['sign', 'verify']);
    const { kty, crv, x, y, d } = await crypto.subtle.exportKey('jwk', pair.privateKey);
    const dpopKeyRef = await secrets.stage(JSON.stringify({ kty, crv, x, y, d }));
    const userId = randomId('usr_');
    const winner = await transaction(state => own(state.identities, issuer) ?? (state.identities[issuer] = { userId, dpopKeyRef }));
    // A concurrent start won; our staged key was never referenced by any record.
    if (winner.dpopKeyRef !== dpopKeyRef) await secrets.remove(dpopKeyRef);
    return winner;
  }

  async function renew(connection: ConnectionRecord, resource: string | null): Promise<CredentialRecord> {
    // Signed-in renewal uses the Account Token and arrives with sign-in (J09).
    if (connection.status !== 'signed_out') throw new AuthFailure('renewal_unavailable', connection.id);
    const token = await signedOutToken(connection.metadata, connection.userId, connection.dpopKeyRef, connection.sessionId, resource);
    const expiresAt = now() + token.expires_in * 1000;
    const secretRef = await secrets.stage(token.access_token);
    return transaction(state => {
      const current = own(state.connections, connection.id);
      // shortcut: a lost race leaves the staged token as an orphan secret; storage-level orphan cleanup removes it.
      if (!current || current.generation !== connection.generation || current.status !== 'signed_out' || current.sessionId !== connection.sessionId) throw new AuthFailure('state_changed', connection.id);
      return current.slots[slotKey(current.sessionId, resource)] = { secretRef, tokenType: 'DPoP', dpopKeyRef: current.dpopKeyRef, scopes: [], expiresAt, generation: current.generation };
    });
  }

  function targetOf(connection: ConnectionRecord): ConversationTarget {
    const entry = connection.metadata.document.agent?.protocols.find(protocol => protocol.type === 'poppy');
    if (!entry) throw new AuthFailure('no_conversation', connection.id);
    return { issuer: connection.issuer, endpoint: entry.endpoint, ...(entry.resource === undefined ? {} : { resource: entry.resource }) };
  }

  return {
    async start(domain) {
      let metadata: CompanyMetadata;
      try { metadata = await options.metadata.resolveCompany(domain); } catch { throw new AuthFailure('discovery_failed'); }
      if (!metadata.authorization) throw new AuthFailure('no_auth');
      const issuer = metadata.authorization.issuer;
      const { userId, dpopKeyRef } = await identityFor(issuer);
      const token = await signedOutToken(metadata, userId, dpopKeyRef, null, null);
      const createdAt = now();
      const secretRef = await secrets.stage(token.access_token);
      const id = randomId('con_'), operationId = randomId('op_');
      return transaction(state => {
        // A reset or competing identity since we signed means this session belongs to no current identity.
        if (own(state.identities, issuer)?.dpopKeyRef !== dpopKeyRef) throw new AuthFailure('state_changed');
        const connection: ConnectionRecord = {
          id, domain, issuer, metadata, userId, dpopKeyRef, sessionId: token.session_id, generation: 1, status: 'signed_out', grantId: null,
          slots: { [slotKey(token.session_id, null)]: { secretRef, tokenType: 'DPoP', dpopKeyRef, scopes: [], expiresAt: createdAt + token.expires_in * 1000, generation: 1 } },
        };
        state.connections[id] = connection;
        const result: AuthOutcome = { operationId, status: 'completed', connection: publicConnection(connection) };
        state.operations[operationId] = {
          epoch: state.epoch, id: operationId, kind: 'start', connectionId: id, connectionGeneration: 1, grantId: null, grantGeneration: null,
          phase: 'terminal', status: 'completed', createdAt, expiresAt: createdAt, resource: null, scopes: [], direct: null, staged: null, result,
        };
        return result;
      });
    },
    async get(connectionId) {
      const found = typeof connectionId === 'string' ? own((await load()).connections, connectionId) : undefined;
      return found ? publicConnection(found) : null;
    },
    async list() { return Object.values((await load()).connections).map(publicConnection); },
    async target(connectionId) { return targetOf(await record(connectionId)); },
    async authorizedFetch(connectionId, request, target, requiredScopes = []) {
      let connection = await record(connectionId);
      const expected = targetOf(connection);
      if (target.issuer !== expected.issuer || target.endpoint !== expected.endpoint || target.resource !== expected.resource) throw new AuthFailure('invalid_target', connectionId);
      // Credentials go only to the endpoint itself or a slash-delimited child on the same origin.
      const url = new URL(request.url), endpoint = new URL(expected.endpoint);
      const base = endpoint.pathname.replace(/\/$/, '');
      if (url.protocol !== 'https:' || url.hash || url.username || url.password || url.origin !== endpoint.origin || (url.pathname !== endpoint.pathname && !url.pathname.startsWith(`${base}/`))) throw new AuthFailure('invalid_target', connectionId);
      const resource = expected.resource ?? null;
      const slot = own(connection.slots, slotKey(connection.sessionId, resource));
      let credential = slot && slot.expiresAt - SKEW_MS > now() ? slot : await renew(connection, resource);
      let nonceRetried = false, renewed = false;
      for (;;) {
        if (!requiredScopes.every(scope => credential.scopes.includes(scope))) throw new AuthFailure('insufficient_scope', connectionId);
        const token = await secrets.read(credential.secretRef);
        if (token === null) throw new AuthFailure('missing_credential', connectionId);
        const headers = new Headers(request.headers);
        headers.set('authorization', `DPoP ${token}`);
        headers.set('dpop', await proof(await loadDpopKey(credential.dpopKeyRef), request.method, request.url, token));
        // Clone per attempt so the original body stays available for a bounded retry.
        const response = await transport.fetch(new Request(request.clone(), { headers }));
        rememberNonce(request.url, response);
        if (response.status !== 401) return response;
        const error = challengeError(response.headers.get('www-authenticate'));
        if (error === 'use_dpop_nonce' && !nonceRetried && response.headers.has('dpop-nonce')) { nonceRetried = true; continue; }
        if (error === 'invalid_token' && !renewed) {
          renewed = true;
          connection = await record(connectionId);
          credential = await renew(connection, resource);
          continue;
        }
        return response;
      }
    },
  };
}
