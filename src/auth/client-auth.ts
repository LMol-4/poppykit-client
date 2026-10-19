import { createHash } from 'node:crypto';
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
  beginSignIn(connectionId: string, input: { scopes: string[]; redirectUri: string; browserBinding: string }): Promise<{ outcome: AuthOutcome; authorizationUrl?: string }>;
  completeSignIn(input: { callbackUrl: string; browserBinding: string }): Promise<AuthOutcome>;
  cancelSignIn(operationId: string): Promise<AuthOutcome>;
  operation(operationId: string): Promise<AuthOutcome | null>;
  recover(): Promise<AuthOutcome[]>;
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
export interface GrantRecord {
  id: string; issuer: string; userId: string; secretRef: string;
  scopes: string[]; expiresAt: number | null; generation: number;
  status: 'active' | 'uncertain' | 'revoking' | 'revoked';
  operationId: string | null;
}
export interface DirectRecord {
  stateHash: string; verifierRef: string; browserHash: string;
  redirectUri: string; issuer: string; clientId: string; sessionId: string;
}
export interface OperationRecord {
  epoch: string; id: string; kind: 'start' | 'renew' | 'sign_in'; connectionId: string;
  connectionGeneration: number; grantId: string | null; grantGeneration: number | null;
  phase: 'prepared' | 'dispatched' | 'staged' | 'terminal';
  status: OperationStatus; createdAt: number; expiresAt: number;
  resource: string | null; scopes: string[];
  // shortcut: activation commits in the same transaction as the result, so 'staged' and staged stay unused; add them if activation ever needs a second step.
  direct: DirectRecord | null; staged: JsonObject | null;
  result: AuthOutcome | null;
}
// An Account Token that must be revoked remotely before its secret is deleted (revocation is J13).
export interface CleanupRecord {
  id: string; connectionId: string; issuer: string; revocationEndpoint: string;
  secretRef: string; status: 'pending' | 'uncertain';
}
export interface ClientAuthState {
  version: 1; epoch: string;
  owner: { namespace: string; clientId: string; localUserId: string } | null;
  identities: Record<string, { userId: string; dpopKeyRef: string }>;
  connections: Record<string, ConnectionRecord>;
  grants: Record<string, GrantRecord>;
  operations: Record<string, OperationRecord>;
  cleanup: Record<string, CleanupRecord>;
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
const sha256 = (text: string) => createHash('sha256').update(text).digest('base64url');
const SIGN_IN_MS = 10 * 60_000;
// OAuth response parameters an authorization redirect may add to the redirect URI (RFC 6749 4.1.2, RFC 9207).
const CALLBACK_PARAMS = ['code', 'state', 'iss', 'error', 'error_description', 'error_uri'];
const AUTHORIZE_ERRORS = new Set(['invalid_request', 'unauthorized_client', 'unsupported_response_type', 'invalid_scope', 'invalid_target', 'server_error', 'temporarily_unavailable']);
// Redirect identity without the response parameters; origin alone would hide userinfo.
const redirectShape = (url: URL) => JSON.stringify([url.origin, url.username, url.password, url.pathname, [...url.searchParams]]);

function parseCallback(callbackUrl: unknown): { params: Record<string, string>; base: URL } {
  if (typeof callbackUrl !== 'string' || !URL.canParse(callbackUrl)) throw new AuthFailure('invalid_callback');
  const base = new URL(callbackUrl);
  if (base.hash) throw new AuthFailure('invalid_callback');
  const params: Record<string, string> = {};
  for (const name of CALLBACK_PARAMS) {
    const values = base.searchParams.getAll(name);
    if (values.length > 1) throw new AuthFailure('invalid_callback');
    if (values.length) params[name] = values[0]!;
    base.searchParams.delete(name);
  }
  return { params, base };
}

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
  function publicConnection(state: ClientAuthState, connection: ConnectionRecord): Connection {
    const { id, domain, issuer, sessionId, generation, status, grantId } = connection;
    const scopes = grantId === null ? [] : [...own(state.grants, grantId)?.scopes ?? []];
    return { id, domain, issuer, sessionId, generation, status, scopes };
  }

  async function loadDpopKey(reference: string): Promise<DpopKey> {
    const text = await secrets.read(reference);
    if (text === null) throw new AuthFailure('missing_key');
    // Parse errors quote the input, so a corrupted secret must never reach an error message.
    let parsed: Record<string, unknown> | null;
    try { parsed = JSON.parse(text); } catch { throw new AuthFailure('missing_key'); }
    const { d, ...rest } = parsed ?? {};
    const jwk = publicEcJwk(rest, 'missing_key');
    let privateKey: CryptoKey;
    try { privateKey = await crypto.subtle.importKey('jwk', { ...jwk, d } as JsonWebKey, EC, false, ['sign']); } catch { throw new AuthFailure('missing_key'); }
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

  // Token endpoint request with client assertion and fresh DPoP proof (spec 4.1-4.3); sessionSub adds a session assertion.
  // Throws transport_error only when the request may have reached the issuer without a readable answer.
  async function tokenRequest(metadata: CompanyMetadata, dpopKeyRef: string, fields: Record<string, string>, sessionSub: string | null): Promise<TokenResponse> {
    const authorization = metadata.authorization!;
    const endpoint = authorization.token_endpoint;
    const key = await loadDpopKey(dpopKeyRef);
    for (let attempt = 0; ; attempt++) {
      const iat = Math.floor(now() / 1000);
      const claims = (sub: string) => ({ iss: clientId, sub, aud: authorization.issuer, iat, exp: iat + ASSERTION_SECONDS, jti: randomId() });
      const body = new URLSearchParams(fields);
      if (sessionSub !== null) body.set('assertion', await signIdentity({ typ: 'JWT' }, claims(sessionSub), key.thumbprint));
      body.set('client_id', clientId);
      body.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
      body.set('client_assertion', await signIdentity({ typ: 'client-authentication+jwt' }, claims(clientId), key.thumbprint));
      const request = new Request(endpoint, { method: 'POST', body, headers: { accept: 'application/json', dpop: await proof(key, 'POST', endpoint) } });
      let response: Response, text: string;
      try { response = await transport.fetch(request); text = await response.text(); } catch { throw new AuthFailure('transport_error'); }
      rememberNonce(endpoint, response);
      let json: unknown;
      try { json = JSON.parse(text); } catch { /* reported below */ }
      if (response.status === 200) {
        try { return parseTokenResponse(json); } catch { throw new AuthFailure('invalid_response'); }
      }
      let error = 'token_error';
      try { error = parseProtocolError(json).error; } catch { /* non-OAuth body */ }
      if (error === 'use_dpop_nonce' && response.status === 400 && attempt === 0 && response.headers.has('dpop-nonce')) continue;
      throw new AuthFailure(SAFE_ERRORS.has(error) ? error : 'token_error');
    }
  }

  // Signed-out Session Token via the JWT bearer grant (spec 4.2); renewal passes session_id.
  async function signedOutToken(metadata: CompanyMetadata, userId: string, dpopKeyRef: string, sessionId: string | null, resource: string | null): Promise<TokenResponse> {
    const fields: Record<string, string> = { grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer' };
    if (sessionId !== null) fields.session_id = sessionId;
    if (resource !== null) fields.resource = resource;
    const token = await tokenRequest(metadata, dpopKeyRef, fields, userId);
    // Only DPoP is executable; a Bearer token is never used as a fallback.
    if (token.token_type !== 'DPoP') throw new AuthFailure('unsupported_token_type');
    if (token.signed_in !== false || token.scope !== '' || (sessionId !== null && token.session_id !== sessionId)) throw new AuthFailure('invalid_response');
    return token;
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
    // Expiry counts from before dispatch so a slow response never extends the token's believed lifetime.
    const issuedAt = now();
    const token = await signedOutToken(connection.metadata, connection.userId, connection.dpopKeyRef, connection.sessionId, resource);
    const expiresAt = issuedAt + token.expires_in * 1000;
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

  function outcomeOf(state: ClientAuthState, operation: OperationRecord): AuthOutcome {
    return operation.result ?? { operationId: operation.id, status: 'pending', connection: publicConnection(state, own(state.connections, operation.connectionId)!), nextAction: 'wait' };
  }
  // The terminal result is recorded once and returned verbatim to duplicate callbacks.
  function finish(state: ClientAuthState, operation: OperationRecord, status: OperationStatus, extra: { error?: string; missingScopes?: string[] } = {}): AuthOutcome {
    operation.phase = 'terminal'; operation.status = status;
    const result: AuthOutcome = { operationId: operation.id, status, connection: publicConnection(state, own(state.connections, operation.connectionId)!), ...extra };
    if (status === 'failed' || status === 'expired' || status === 'uncertain') result.nextAction = 'sign_in';
    return operation.result = result;
  }
  // An Account Token that will not be used stays private until it is revoked (J13).
  function retire(state: ClientAuthState, id: string, connection: ConnectionRecord, secretRef: string): void {
    state.cleanup[id] = { id, connectionId: connection.id, issuer: connection.issuer, revocationEndpoint: connection.metadata.authorization!.revocation_endpoint, secretRef, status: 'pending' };
  }
  // Records a terminal sign-in result if the exchange still owns the operation; a recovery that ran meanwhile wins.
  async function settle(operationId: string, verifierRef: string, status: OperationStatus, extra: { error?: string; missingScopes?: string[] }, unusedGrantRef: string | null = null): Promise<AuthOutcome> {
    const outcome = await transaction(state => {
      const operation = own(state.operations, operationId);
      if (!operation || operation.epoch !== state.epoch) throw new AuthFailure('state_changed');
      if (unusedGrantRef !== null) retire(state, `cln_${operationId}`, own(state.connections, operation.connectionId)!, unusedGrantRef);
      return operation.phase === 'dispatched' ? finish(state, operation, status, extra) : outcomeOf(state, operation);
    });
    // Terminal operations never read their verifier again.
    await secrets.remove(verifierRef);
    return outcome;
  }

  return {
    async start(domain) {
      let metadata: CompanyMetadata;
      try { metadata = await options.metadata.resolveCompany(domain); } catch { throw new AuthFailure('discovery_failed'); }
      if (!metadata.authorization) throw new AuthFailure('no_auth');
      const issuer = metadata.authorization.issuer;
      const { userId, dpopKeyRef } = await identityFor(issuer);
      const createdAt = now();
      const token = await signedOutToken(metadata, userId, dpopKeyRef, null, null);
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
        const result: AuthOutcome = { operationId, status: 'completed', connection: publicConnection(state, connection) };
        state.operations[operationId] = {
          epoch: state.epoch, id: operationId, kind: 'start', connectionId: id, connectionGeneration: 1, grantId: null, grantGeneration: null,
          phase: 'terminal', status: 'completed', createdAt, expiresAt: createdAt, resource: null, scopes: [], direct: null, staged: null, result,
        };
        return result;
      });
    },
    async get(connectionId) {
      const state = await load();
      const found = typeof connectionId === 'string' ? own(state.connections, connectionId) : undefined;
      return found ? publicConnection(state, found) : null;
    },
    async list() {
      const state = await load();
      return Object.values(state.connections).map(connection => publicConnection(state, connection));
    },
    async target(connectionId) { return targetOf(await record(connectionId)); },

    // Direct Sign-In (spec 4.5): the operation binds everything the callback must match before the URL exists.
    async beginSignIn(connectionId, input) {
      const connection = await record(connectionId);
      const direct = connection.metadata.document.auth?.direct;
      const authorizationEndpoint = connection.metadata.authorization?.authorization_endpoint;
      if (!direct || !authorizationEndpoint) throw new AuthFailure('direct_unavailable', connectionId);
      const { scopes, redirectUri, browserBinding } = (input ?? {}) as { scopes?: unknown; redirectUri?: unknown; browserBinding?: unknown };
      if (!Array.isArray(scopes) || !scopes.length || new Set(scopes).size !== scopes.length || !scopes.every(scope => typeof scope === 'string' && direct.scopes.includes(scope))) throw new AuthFailure('invalid_scope', connectionId);
      if (typeof redirectUri !== 'string' || !options.redirectUris.includes(redirectUri) || !URL.canParse(redirectUri)) throw new AuthFailure('invalid_redirect', connectionId);
      // The host derives this from its authenticated browser session; a short value would be guessable.
      if (typeof browserBinding !== 'string' || browserBinding.length < 22) throw new AuthFailure('invalid_binding', connectionId);
      if ((connection.status !== 'signed_out' && connection.status !== 'signed_in') || connection.sessionId === null) throw new AuthFailure('sign_in_unavailable', connectionId);
      const state = b64(crypto.getRandomValues(new Uint8Array(32)));
      const verifier = b64(crypto.getRandomValues(new Uint8Array(32)));
      // Ask for the conversation resource up front so the signed-in token is usable there (spec 4.3 "Narrower tokens").
      const resource = connection.metadata.document.agent?.protocols.find(protocol => protocol.type === 'poppy')?.resource ?? null;
      const verifierRef = await secrets.stage(verifier);
      const createdAt = now(), operationId = randomId('op_');
      const outcome = await transaction(draft => {
        const current = own(draft.connections, connectionId);
        // shortcut: a lost race leaves the staged verifier as an orphan secret; storage-level orphan cleanup removes it.
        if (!current || current.generation !== connection.generation || current.status !== connection.status) throw new AuthFailure('state_changed', connectionId);
        const operation: OperationRecord = draft.operations[operationId] = {
          epoch: draft.epoch, id: operationId, kind: 'sign_in', connectionId, connectionGeneration: current.generation, grantId: current.grantId, grantGeneration: null,
          phase: 'prepared', status: 'pending', createdAt, expiresAt: createdAt + SIGN_IN_MS, resource, scopes: [...scopes],
          direct: { stateHash: sha256(state), verifierRef, browserHash: sha256(browserBinding), redirectUri, issuer: current.issuer, clientId, sessionId: connection.sessionId! },
          staged: null, result: null,
        };
        return outcomeOf(draft, operation);
      });
      const url = new URL(authorizationEndpoint);
      const query = { response_type: 'code', client_id: clientId, redirect_uri: redirectUri, scope: scopes.join(' '), state, code_challenge: sha256(verifier), code_challenge_method: 'S256' };
      for (const [name, value] of Object.entries(query)) url.searchParams.set(name, value);
      if (resource !== null) url.searchParams.set('resource', resource);
      return { outcome, authorizationUrl: url.href };
    },

    async completeSignIn(input) {
      const { callbackUrl, browserBinding } = (input ?? {}) as { callbackUrl?: unknown; browserBinding?: unknown };
      const { params, base } = parseCallback(callbackUrl);
      if (typeof browserBinding !== 'string' || params.state === undefined || (params.code === undefined) === (params.error === undefined)) throw new AuthFailure('invalid_callback');
      const stateHash = sha256(params.state), browserHash = sha256(browserBinding);
      const snapshot = await load();
      const found = Object.values(snapshot.operations).find(operation => operation.kind === 'sign_in' && operation.epoch === snapshot.epoch && operation.direct?.stateHash === stateHash);
      const direct = found?.direct;
      // A wrong browser, redirect or issuer (mix-up, spec 4.5) leaves the operation untouched so the genuine callback still completes.
      if (!found || !direct || direct.browserHash !== browserHash || redirectShape(base) !== redirectShape(new URL(direct.redirectUri)) || params.iss !== direct.issuer) throw new AuthFailure('invalid_callback');
      const operationId = found.id;
      const verifier = found.phase === 'prepared' && params.code !== undefined ? await secrets.read(direct.verifierRef) : null;
      const at = now();
      // Only one claimant moves prepared -> dispatched; everyone else gets the recorded progress or result.
      const claim = await transaction(state => {
        const operation = own(state.operations, operationId);
        if (!operation || operation.epoch !== state.epoch) throw new AuthFailure('invalid_callback');
        if (operation.phase !== 'prepared') return outcomeOf(state, operation);
        const connection = own(state.connections, operation.connectionId)!;
        if (connection.generation !== operation.connectionGeneration) return finish(state, operation, 'failed', { error: 'state_changed' });
        if (at >= operation.expiresAt) return finish(state, operation, 'expired');
        if (params.error !== undefined) return params.error === 'access_denied' ? finish(state, operation, 'denied', { error: 'access_denied' }) : finish(state, operation, 'failed', { error: AUTHORIZE_ERRORS.has(params.error) ? params.error : 'authorization_error' });
        if (verifier === null) return finish(state, operation, 'failed', { error: 'missing_key' });
        operation.phase = 'dispatched';
        return { connection, operation };
      });
      if (!('operation' in claim)) {
        if (claim.status !== 'pending') await secrets.remove(direct.verifierRef);
        return claim;
      }
      const { connection, operation } = claim;
      const fields: Record<string, string> = { grant_type: 'authorization_code', code: params.code!, redirect_uri: direct.redirectUri, code_verifier: verifier!, session_id: direct.sessionId };
      if (operation.resource !== null) fields.resource = operation.resource;
      const issuedAt = now();
      let token: TokenResponse;
      try { token = await tokenRequest(connection.metadata, connection.dpopKeyRef, fields, null); } catch (error) {
        // A definite rejection is a failure; a lost answer may have consumed the code, so it is never resent.
        const definite = error instanceof AuthFailure && error.code !== 'transport_error';
        return settle(operationId, direct.verifierRef, definite ? 'failed' : 'uncertain', { error: definite ? error.code : 'lost_response' });
      }
      const granted = token.scope.split(' ').filter(Boolean);
      const missingScopes = operation.scopes.filter(scope => !granted.includes(scope));
      let problem: string | null = null;
      if (token.token_type !== 'DPoP') problem = 'unsupported_token_type';
      else if (token.signed_in !== true || token.session_id !== direct.sessionId || token.refresh_token === undefined || granted.some(scope => !operation.scopes.includes(scope))) problem = 'invalid_response';
      else if (missingScopes.length) problem = 'insufficient_scope';
      let refreshRef: string | null = null, accessRef = '';
      try {
        if (token.refresh_token !== undefined) refreshRef = await secrets.stage(token.refresh_token);
        if (!problem) accessRef = await secrets.stage(token.access_token);
      } catch {
        return settle(operationId, direct.verifierRef, 'uncertain', { error: 'storage_error' }, refreshRef);
      }
      // Partial consent or a malformed grant keeps the previous credentials; the new Account Token only awaits revocation.
      if (problem) return settle(operationId, direct.verifierRef, 'failed', problem === 'insufficient_scope' ? { error: problem, missingScopes } : { error: problem }, refreshRef);
      const grantId = randomId('grt_');
      const refreshExpiresAt = token.refresh_token_expires_in === undefined ? null : issuedAt + token.refresh_token_expires_in * 1000;
      const outcome = await transaction(state => {
        const current = own(state.operations, operationId);
        // shortcut: after a full reset the staged secrets are orphans and the remote grant is not revoked; reset cleanup removes the secrets.
        if (!current || current.epoch !== state.epoch) throw new AuthFailure('state_changed');
        const target = own(state.connections, current.connectionId)!;
        // A sign-out or recovery that ran during the exchange wins; the new grant is kept only for revocation.
        if (current.phase !== 'dispatched' || target.generation !== current.connectionGeneration) {
          retire(state, `cln_${operationId}`, target, refreshRef!);
          return current.phase === 'dispatched' ? finish(state, current, 'failed', { error: 'state_changed' }) : outcomeOf(state, current);
        }
        const previous = target.grantId === null ? undefined : own(state.grants, target.grantId);
        if (previous) { retire(state, `cln_${previous.id}`, target, previous.secretRef); delete state.grants[previous.id]; }
        state.grants[grantId] = { id: grantId, issuer: target.issuer, userId: target.userId, secretRef: refreshRef!, scopes: granted, expiresAt: refreshExpiresAt, generation: 1, status: 'active', operationId: null };
        target.grantId = grantId; target.status = 'signed_in';
        // Older tokens for this session reflect the old authority, so only the new one stays selectable (spec 4.3).
        target.slots = { [slotKey(direct.sessionId, current.resource)]: { secretRef: accessRef, tokenType: 'DPoP', dpopKeyRef: target.dpopKeyRef, scopes: granted, expiresAt: issuedAt + token.expires_in * 1000, generation: target.generation } };
        return finish(state, current, 'completed');
      });
      await secrets.remove(direct.verifierRef);
      return outcome;
    },

    async cancelSignIn(operationId) {
      const { outcome, verifierRef } = await transaction(state => {
        const operation = typeof operationId === 'string' ? own(state.operations, operationId) : undefined;
        if (!operation?.direct || operation.epoch !== state.epoch) throw new AuthFailure('unknown_operation');
        // Once the code is sent, cancelling cannot undo the remote exchange; its outcome stands.
        return { outcome: operation.phase === 'prepared' ? finish(state, operation, 'cancelled') : outcomeOf(state, operation), verifierRef: operation.direct.verifierRef };
      });
      if (outcome.status !== 'pending') await secrets.remove(verifierRef);
      return outcome;
    },

    async operation(operationId) {
      const state = await load();
      const found = typeof operationId === 'string' ? own(state.operations, operationId) : undefined;
      return found && found.epoch === state.epoch ? outcomeOf(state, found) : null;
    },

    // Host calls this at startup; it never repeats a remote exchange.
    async recover() {
      const at = now();
      const settled = await transaction(state => {
        const results: { outcome: AuthOutcome; verifierRef: string | null }[] = [];
        for (const operation of Object.values(state.operations)) {
          if (operation.epoch !== state.epoch || operation.phase === 'terminal') continue;
          const verifierRef = operation.direct?.verifierRef ?? null;
          // The code may have reached the issuer before the crash; only a fresh sign-in is safe.
          if (operation.phase !== 'prepared') results.push({ outcome: finish(state, operation, 'uncertain', { error: 'lost_response' }), verifierRef });
          else if (at >= operation.expiresAt) results.push({ outcome: finish(state, operation, 'expired'), verifierRef });
        }
        return results;
      });
      for (const { verifierRef } of settled) if (verifierRef !== null) await secrets.remove(verifierRef);
      return settled.map(item => item.outcome);
    },
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
