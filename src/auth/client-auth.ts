import { createHash } from 'node:crypto';
import { calculateJwkThumbprint } from 'jose';
import { parseProtocolError, parseTokenResponse } from '../protocol/wire.js';
import type { JsonObject, TokenResponse } from '../protocol/wire.js';
import { validateClientId } from '../network/discovery.js';
import type { CompanyMetadata, MetadataResolver } from '../network/discovery.js';
import type { HttpTransport } from '../network/transport.js';
import { dpopChallenge } from './challenge.js';

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
export interface SignOutOutcome { connection: Connection; cleanup: 'complete' | 'pending' | 'uncertain' }
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
  renew(connectionId: string, input?: { resource?: string; scopes?: string[] }): Promise<AuthOutcome>;
  signOut(connectionId: string): Promise<SignOutOutcome>;
  retryCleanup(connectionId: string): Promise<SignOutOutcome>;
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
  // Sign-in activates in one transaction with its result; only refresh records staged refs first.
  direct: DirectRecord | null; staged: StagedRefresh | null;
  result: AuthOutcome | null;
}
export interface StagedRefresh {
  accessRef: string; refreshRef: string | null; sessionId: string; scopes: string[];
  signedIn: boolean; expiresAt: number; refreshExpiresAt: number | null;
}
// An Account Token that must be revoked remotely before its secret is deleted; uncertain means its secret is gone.
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
// Token endpoint failures after which the Company may have acted: lost, unreadable or non-OAuth answers.
const AMBIGUOUS = new Set(['transport_error', 'invalid_response', 'token_error']);
const CLIENT_ASSERTION = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const ASSERTION_SECONDS = 60;
// OAuth codes the token endpoint may return (spec 4.2, RFC 6749/8707); anything else is reported as token_error.
const SAFE_ERRORS = new Set(['invalid_request', 'invalid_client', 'invalid_grant', 'unauthorized_client', 'unsupported_grant_type', 'invalid_scope', 'invalid_target', 'invalid_session', 'account_mismatch', 'invalid_dpop_proof', 'use_dpop_nonce', 'extension_required', 'rate_limited']);

const b64 = (data: Uint8Array | string) => Buffer.from(data).toString('base64url');
const randomId = (prefix = '') => prefix + b64(crypto.getRandomValues(new Uint8Array(16)));
const own = <T>(record: Record<string, T>, key: string): T | undefined => Object.hasOwn(record, key) ? record[key] : undefined;
const slotKey = (sessionId: string | null, resource: string | null) => JSON.stringify([sessionId, resource]);
const sha256 = (text: string) => createHash('sha256').update(text).digest('base64url');
const SIGN_IN_MS = 10 * 60_000;
const KEEP_OPERATIONS = 100;
// shortcut: a longer wait is still sent as asked, but we stop waiting after this hold; raise it if Companies honour longer polls.
const MAX_WAIT_SECONDS = 300;
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

  function assertionClaims(sub: string, aud: string): JsonObject {
    const iat = Math.floor(now() / 1000);
    return { iss: clientId, sub, aud, iat, exp: iat + ASSERTION_SECONDS, jti: randomId() };
  }
  // Token endpoint request with client assertion and fresh DPoP proof (spec 4.1-4.3); sessionSub adds a session assertion.
  // Throws transport_error only when the request may have reached the issuer without a readable answer.
  async function tokenRequest(metadata: CompanyMetadata, dpopKeyRef: string, fields: Record<string, string>, sessionSub: string | null): Promise<TokenResponse> {
    const authorization = metadata.authorization!;
    const endpoint = authorization.token_endpoint;
    const key = await loadDpopKey(dpopKeyRef);
    for (let attempt = 0; ; attempt++) {
      const body = new URLSearchParams(fields);
      if (sessionSub !== null) body.set('assertion', await signIdentity({ typ: 'JWT' }, assertionClaims(sessionSub, authorization.issuer), key.thumbprint));
      body.set('client_id', clientId);
      body.set('client_assertion_type', CLIENT_ASSERTION);
      body.set('client_assertion', await signIdentity({ typ: 'client-authentication+jwt' }, assertionClaims(clientId, authorization.issuer), key.thumbprint));
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
      // Only a recognised OAuth code on a 4xx is a definite rejection; a 5xx or proxy page may follow a completed exchange.
      throw new AuthFailure(response.status >= 400 && response.status < 500 && SAFE_ERRORS.has(error) ? error : 'token_error');
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

  // Commits a change that may stage or release secrets. When our own fence check rejects it, nothing references the
  // staged secrets, so they are removed; references the committed change pushed to `drop` are removed after commit.
  // shortcut: a crash between stage() and commit leaves an unreferenced secret; SecretStore cannot list, so add a sweep when D offers one.
  async function commit<T>(staged: (string | null)[], change: (state: ClientAuthState, drop: string[]) => T): Promise<T> {
    const drop: string[] = [];
    let result: T;
    try { result = await transaction(state => { drop.length = 0; return change(state, drop); }); } catch (error) {
      if (error instanceof AuthFailure && error.code === 'state_changed') for (const ref of staged) if (ref !== null) await secrets.remove(ref);
      throw error;
    }
    for (const ref of drop) await secrets.remove(ref);
    return result;
  }
  // Credentials of an ended Session are unusable for every resource, so all of its slots go with it.
  function switchSession(connection: ConnectionRecord, sessionId: string, drop: string[]): void {
    if (connection.sessionId === sessionId) return;
    drop.push(...Object.values(connection.slots).map(slot => slot.secretRef));
    connection.slots = {}; connection.sessionId = sessionId;
  }
  function replaceSlot(connection: ConnectionRecord, resource: string | null, credential: CredentialRecord, drop: string[]): void {
    const key = slotKey(connection.sessionId, resource);
    const old = own(connection.slots, key);
    if (old) drop.push(old.secretRef);
    connection.slots[key] = credential;
  }
  // Completed renewals are only history; uncertain ones stay because they decide the cleanup status.
  function pruneRenewals(state: ClientAuthState, connectionId: string): void {
    for (const op of Object.values(state.operations)) if (op.kind === 'renew' && op.connectionId === connectionId && op.phase === 'terminal' && op.status !== 'uncertain') delete state.operations[op.id];
  }
  // Terminal start/sign-in results only answer late duplicate callbacks, so keep the newest few; uncertain ones decide the cleanup status.
  function pruneHistory(state: ClientAuthState): void {
    // Newest first; reverse() keeps insertion order as the tie-break for equal timestamps.
    const done = Object.values(state.operations).reverse().filter(op => op.kind !== 'renew' && op.phase === 'terminal' && op.status !== 'uncertain').sort((a, b) => b.createdAt - a.createdAt);
    for (const op of done.slice(KEEP_OPERATIONS)) delete state.operations[op.id];
  }
  function renewOperation(state: ClientAuthState, id: string, connection: ConnectionRecord, grant: GrantRecord | null, at: number, resource: string | null, scopes: string[]): OperationRecord {
    pruneRenewals(state, connection.id);
    return state.operations[id] = {
      epoch: state.epoch, id, kind: 'renew', connectionId: connection.id, connectionGeneration: connection.generation, grantId: grant?.id ?? null, grantGeneration: grant?.generation ?? null,
      phase: 'prepared', status: 'pending', createdAt: at, expiresAt: at, resource, scopes, direct: null, staged: null, result: null,
    };
  }

  async function signedOutRenewal(connection: ConnectionRecord, resource: string | null): Promise<AuthOutcome> {
    // Expiry counts from before dispatch so a slow response never extends the token's believed lifetime.
    const issuedAt = now(), operationId = randomId('op_');
    let token: TokenResponse;
    try { token = await signedOutToken(connection.metadata, connection.userId, connection.dpopKeyRef, connection.sessionId, resource); } catch (error) {
      // The Session ended (spec 4.2): start a new signed-out one. Signed-out renewal never touches an account.
      if (!(error instanceof AuthFailure && error.code === 'invalid_session')) throw error;
      token = await signedOutToken(connection.metadata, connection.userId, connection.dpopKeyRef, null, resource);
    }
    const secretRef = await secrets.stage(token.access_token);
    return commit([secretRef], (state, drop) => {
      const current = own(state.connections, connection.id);
      if (!current || current.generation !== connection.generation || current.status !== 'signed_out' || current.sessionId !== connection.sessionId) throw new AuthFailure('state_changed', connection.id);
      switchSession(current, token.session_id, drop);
      replaceSlot(current, resource, { secretRef, tokenType: 'DPoP', dpopKeyRef: current.dpopKeyRef, scopes: [], expiresAt: issuedAt + token.expires_in * 1000, generation: current.generation }, drop);
      return finish(state, renewOperation(state, operationId, current, null, issuedAt, resource, []), 'completed');
    });
  }

  // Account Token refresh (spec 4.8). The grant claim allows one rotation in flight per grant across processes,
  // because a second sender could present a token the first rotation already replaced.
  async function refresh(connection: ConnectionRecord, resource: string | null, scopes: string[] | null): Promise<AuthOutcome> {
    const at = now(), operationId = randomId('op_');
    const claim = await transaction(state => {
      const current = own(state.connections, connection.id)!;
      const grant = current.grantId === null ? undefined : own(state.grants, current.grantId);
      if (current.status !== 'signed_in' || !grant) throw new AuthFailure('state_changed', connection.id);
      const running = grant.operationId === null ? undefined : own(state.operations, grant.operationId);
      if (running && running.phase !== 'terminal') return { running: outcomeOf(state, running) } as const;
      if (grant.status !== 'active') throw new AuthFailure('grant_uncertain', connection.id);
      if (scopes && !scopes.every(scope => grant.scopes.includes(scope))) throw new AuthFailure('invalid_scope', connection.id);
      grant.operationId = operationId;
      const operation = renewOperation(state, operationId, current, grant, at, resource, scopes ?? [...grant.scopes]);
      return { running: null, connection: current, secretRef: grant.secretRef, requested: operation.scopes };
    });
    if (claim.running) return claim.running;
    let refreshToken: string | null;
    try { refreshToken = await secrets.read(claim.secretRef); } catch { return endRefresh(operationId, 'failed', 'storage_error'); }
    if (refreshToken === null) return endRefresh(operationId, 'failed', 'missing_credential');
    const sessionId = claim.connection.sessionId!;
    const fields: Record<string, string> = { grant_type: 'refresh_token', refresh_token: refreshToken, session_id: sessionId };
    if (resource !== null) fields.resource = resource;
    if (scopes) fields.scope = scopes.join(' ');
    // The last local step before the send; a crash before it sent nothing, so recover just releases the grant.
    const dispatched = await transaction(state => {
      const operation = own(state.operations, operationId);
      if (!operation || operation.epoch !== state.epoch || operation.phase !== 'prepared') return false;
      operation.phase = 'dispatched';
      return true;
    });
    if (!dispatched) return endRefresh(operationId, 'failed', 'state_changed');
    const issuedAt = now();
    const send = () => tokenRequest(claim.connection.metadata, claim.connection.dpopKeyRef, fields, null);
    let token: TokenResponse, newSession = false;
    try {
      try { token = await send(); } catch (error) {
        // A definite invalid_session (a 4xx OAuth code) left the Account Token unused, so this is a new request, not a resend:
        // without session_id the Company starts a new Session signed in to the same account (spec 4.8).
        if (!(error instanceof AuthFailure && error.code === 'invalid_session')) throw error;
        delete fields.session_id; newSession = true;
        token = await send();
      }
    } catch (error) {
      const code = error instanceof AuthFailure ? error.code : 'local_error'; // non-AuthFailure errors come from local signing before dispatch
      // A lost, unreadable or non-OAuth answer may follow a rotation, so the old Account Token is never resent (IMPLEMENTATION 4).
      if (AMBIGUOUS.has(code)) return endRefresh(operationId, 'uncertain', 'lost_response');
      return endRefresh(operationId, 'failed', code);
    }
    const granted = token.scope.split(' ').filter(Boolean);
    let problem: string | null = null;
    if (token.token_type !== 'DPoP') problem = 'unsupported_token_type';
    else if (token.signed_in !== true || (newSession ? token.session_id === sessionId : token.session_id !== sessionId) || granted.some(scope => !claim.requested.includes(scope))) problem = 'invalid_response';
    let refreshRef: string | null = null, accessRef: string | null = null;
    try { if (token.refresh_token !== undefined) refreshRef = await secrets.stage(token.refresh_token); } catch { return endRefresh(operationId, 'uncertain', 'storage_error'); }
    if (!problem) try { accessRef = await secrets.stage(token.access_token); } catch { problem = 'storage_error'; }
    if (problem || accessRef === null) return endRefresh(operationId, 'failed', problem ?? 'storage_error', refreshRef);
    const staged: StagedRefresh = {
      accessRef, refreshRef, sessionId: token.session_id, scopes: granted, signedIn: true, expiresAt: issuedAt + token.expires_in * 1000,
      refreshExpiresAt: token.refresh_token_expires_in === undefined ? null : issuedAt + token.refresh_token_expires_in * 1000,
    };
    // Its own commit, so a crash before activation leaves the new Account Token referenced for recover (interface 4).
    const recorded = await transaction(state => {
      const operation = own(state.operations, operationId);
      if (!operation || operation.epoch !== state.epoch || operation.phase !== 'dispatched') return false;
      operation.phase = 'staged'; operation.staged = staged;
      return true;
    });
    if (!recorded) return endRefresh(operationId, 'failed', 'state_changed', refreshRef, accessRef);
    return commit([accessRef, refreshRef], (state, drop) => {
      const operation = own(state.operations, operationId);
      if (!operation || operation.epoch !== state.epoch) throw new AuthFailure('state_changed');
      return operation.phase === 'staged' ? activateRefresh(state, operation, drop) : outcomeOf(state, operation);
    });
  }
  // Ends a refresh that will not activate. A returned Account Token is parked for revocation.
  function endRefresh(operationId: string, status: OperationStatus, error: string, refreshRef: string | null = null, accessRef: string | null = null): Promise<AuthOutcome> {
    return commit([refreshRef, accessRef], (state, drop) => {
      const operation = own(state.operations, operationId);
      if (!operation || operation.epoch !== state.epoch) throw new AuthFailure('state_changed');
      if (accessRef !== null) drop.push(accessRef);
      if (refreshRef !== null) retire(state, `cln_${operationId}`, own(state.connections, operation.connectionId)!, refreshRef);
      return operation.phase === 'terminal' ? outcomeOf(state, operation) : closeRefresh(state, operation, status, error, refreshRef !== null, drop);
    });
  }
  function closeRefresh(state: ClientAuthState, operation: OperationRecord, status: OperationStatus, error: string, rotated: boolean, drop: string[]): AuthOutcome {
    const connection = own(state.connections, operation.connectionId)!;
    const grant = operation.grantId === null ? undefined : own(state.grants, operation.grantId);
    if (grant?.operationId === operation.id) {
      grant.operationId = null;
      if (connection.grantId === grant.id && connection.generation === operation.connectionGeneration) {
        if (error === 'invalid_grant') {
          // Expired or revoked: the Session continues signed out and the User signs in again only on request (spec 4.8, 4.9).
          drop.push(grant.secretRef, ...Object.values(connection.slots).map(slot => slot.secretRef));
          delete state.grants[grant.id];
          connection.grantId = null; connection.status = 'signed_out'; connection.slots = {};
        } else if (status === 'uncertain' || rotated) {
          // The Account Token we hold may already be replaced; only a fresh sign-in is safe.
          grant.status = 'uncertain'; connection.status = 'uncertain';
        }
      }
    }
    return finish(state, operation, status, { error });
  }
  function activateRefresh(state: ClientAuthState, operation: OperationRecord, drop: string[]): AuthOutcome {
    const staged = operation.staged!;
    const connection = own(state.connections, operation.connectionId)!;
    const grant = operation.grantId === null ? undefined : own(state.grants, operation.grantId);
    if (!grant || grant.operationId !== operation.id || grant.generation !== operation.grantGeneration || connection.grantId !== grant.id || connection.generation !== operation.connectionGeneration) {
      // A sign-out or replacement won the race; the late Account Token cannot activate and awaits revocation.
      if (staged.refreshRef !== null) retire(state, `cln_${operation.id}`, connection, staged.refreshRef);
      drop.push(staged.accessRef);
      if (grant?.operationId === operation.id) grant.operationId = null;
      return finish(state, operation, 'failed', { error: 'state_changed' });
    }
    grant.operationId = null; grant.generation++;
    if (staged.refreshRef !== null) {
      // The Company rotated the Account Token; the old one is dead and is never sent again (spec 4.8).
      drop.push(grant.secretRef); grant.secretRef = staged.refreshRef;
      if (staged.refreshExpiresAt !== null) grant.expiresAt = staged.refreshExpiresAt;
    }
    switchSession(connection, staged.sessionId, drop);
    // Only this resource's credential changes; other resources' credentials survive (IMPLEMENTATION 3).
    replaceSlot(connection, operation.resource, { secretRef: staged.accessRef, tokenType: 'DPoP', dpopKeyRef: connection.dpopKeyRef, scopes: staged.scopes, expiresAt: staged.expiresAt, generation: connection.generation }, drop);
    return finish(state, operation, 'completed');
  }
  function renewal(connection: ConnectionRecord, resource: string | null, scopes: string[] | null): Promise<AuthOutcome> {
    if (connection.status === 'signed_out') {
      if (scopes?.length) throw new AuthFailure('invalid_scope', connection.id);
      return signedOutRenewal(connection, resource);
    }
    if (connection.status !== 'signed_in') throw new AuthFailure(connection.status === 'disconnected' ? 'disconnected' : 'grant_uncertain', connection.id);
    return refresh(connection, resource, scopes);
  }

  // In-process single flight: parallel requests on one stale slot share one renewal; the grant claim covers other processes.
  const renewing = new Map<string, Promise<CredentialRecord>>();
  function renewShared(connectionId: string, resource: string | null): Promise<CredentialRecord> {
    const key = JSON.stringify([connectionId, resource]);
    let pending = renewing.get(key);
    if (!pending) {
      pending = (async () => {
        const outcome = await renewal(await record(connectionId), resource, null);
        if (outcome.status !== 'completed') throw new AuthFailure(outcome.status === 'pending' ? 'renewal_pending' : outcome.error ?? 'renewal_failed', connectionId);
        const slot = own((await record(connectionId)).slots, slotKey(outcome.connection.sessionId, resource));
        if (!slot) throw new AuthFailure('state_changed', connectionId);
        return slot;
      })().finally(() => renewing.delete(key));
      renewing.set(key, pending);
    }
    return pending;
  }
  // A valid current credential, or a renewal; `stale` skips a credential the Company rejected or a renewal removed.
  async function credentialFor(connectionId: string, resource: string | null, stale: string | null): Promise<CredentialRecord> {
    const connection = await record(connectionId);
    if (connection.status === 'disconnected') throw new AuthFailure('disconnected', connectionId);
    const slot = own(connection.slots, slotKey(connection.sessionId, resource));
    return slot && slot.secretRef !== stale && slot.expiresAt - SKEW_MS > now() ? slot : renewShared(connectionId, resource);
  }

  function cleanupStatus(state: ClientAuthState, connectionId: string): SignOutOutcome['cleanup'] {
    const operations = Object.values(state.operations).filter(op => op.connectionId === connectionId && op.epoch === state.epoch);
    const items = Object.values(state.cleanup).filter(item => item.connectionId === connectionId);
    // A lost exchange or rotation may have issued an Account Token we never saw, so it can never be claimed revoked.
    if (operations.some(op => op.status === 'uncertain') || items.some(item => item.status === 'uncertain')) return 'uncertain';
    return items.length || operations.some(op => op.phase === 'dispatched' || op.phase === 'staged') ? 'pending' : 'complete';
  }
  // RFC 7009 revocation with a fresh client assertion (spec 4.9). Replay is safe, so anything but 200 stays pending.
  async function revoke(connection: ConnectionRecord, item: CleanupRecord, token: string): Promise<boolean> {
    try {
      const key = await loadDpopKey(connection.dpopKeyRef);
      const body = new URLSearchParams({ token, token_type_hint: 'refresh_token', client_id: clientId, client_assertion_type: CLIENT_ASSERTION, client_assertion: await signIdentity({ typ: 'client-authentication+jwt' }, assertionClaims(clientId, item.issuer), key.thumbprint) });
      const response = await transport.fetch(new Request(item.revocationEndpoint, { method: 'POST', body, headers: { accept: 'application/json' } }));
      await response.body?.cancel();
      return response.status === 200;
    } catch { return false; }
  }
  async function cleanupNow(connectionId: string): Promise<SignOutOutcome> {
    const connection = await record(connectionId);
    const items = Object.values((await load()).cleanup).filter(item => item.connectionId === connectionId && item.status === 'pending');
    for (const item of items) {
      const token = await secrets.read(item.secretRef);
      const revoked = token !== null && await revoke(connection, item, token);
      if (token !== null && !revoked) continue;
      await commit([], (state, drop) => {
        const current = own(state.cleanup, item.id);
        if (current?.secretRef !== item.secretRef) return;
        if (revoked) { delete state.cleanup[item.id]; drop.push(item.secretRef); } else current.status = 'uncertain';
      });
    }
    const state = await load();
    return { connection: publicConnection(state, own(state.connections, connectionId)!), cleanup: cleanupStatus(state, connectionId) };
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
  // An Account Token that will not be used stays private until retryCleanup revokes it.
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
      return commit([secretRef], state => {
        // A reset or competing identity since we signed means this session belongs to no current identity.
        if (own(state.identities, issuer)?.dpopKeyRef !== dpopKeyRef) throw new AuthFailure('state_changed');
        const connection: ConnectionRecord = {
          id, domain, issuer, metadata, userId, dpopKeyRef, sessionId: token.session_id, generation: 1, status: 'signed_out', grantId: null,
          slots: { [slotKey(token.session_id, null)]: { secretRef, tokenType: 'DPoP', dpopKeyRef, scopes: [], expiresAt: createdAt + token.expires_in * 1000, generation: 1 } },
        };
        state.connections[id] = connection;
        pruneHistory(state);
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
      const found = await record(connectionId);
      const direct = found.metadata.document.auth?.direct;
      const authorizationEndpoint = found.metadata.authorization?.authorization_endpoint;
      if (!direct || !authorizationEndpoint) throw new AuthFailure('direct_unavailable', connectionId);
      const { scopes, redirectUri, browserBinding } = (input ?? {}) as { scopes?: unknown; redirectUri?: unknown; browserBinding?: unknown };
      if (!Array.isArray(scopes) || !scopes.length || new Set(scopes).size !== scopes.length || !scopes.every(scope => typeof scope === 'string' && direct.scopes.includes(scope))) throw new AuthFailure('invalid_scope', connectionId);
      if (typeof redirectUri !== 'string' || !options.redirectUris.includes(redirectUri) || !URL.canParse(redirectUri)) throw new AuthFailure('invalid_redirect', connectionId);
      // The host derives this from its authenticated browser session; a short value would be guessable.
      if (typeof browserBinding !== 'string' || browserBinding.length < 22) throw new AuthFailure('invalid_binding', connectionId);
      // Ask for the conversation resource up front so the signed-in token is usable there (spec 4.3 "Narrower tokens").
      const resource = found.metadata.document.agent?.protocols.find(protocol => protocol.type === 'poppy')?.resource ?? null;
      // The code exchange names this Session (spec 4.5). A stale credential means it may have ended, so renew first,
      // which replaces an ended Session; a failed renewal leaves the Session as it was for the issuer to judge.
      const renew = () => credentialFor(connectionId, resource, null).catch(error => { if (!(error instanceof AuthFailure)) throw error; });
      if (found.status === 'signed_out' || found.status === 'signed_in') await renew();
      let connection = await record(connectionId);
      // An expired Account Token ends the refresh as invalid_grant, leaving the connection signed out on a possibly ended Session.
      if (found.status === 'signed_in' && connection.status === 'signed_out') { await renew(); connection = await record(connectionId); }
      // An uncertain grant recovers only through a fresh sign-in; a disconnected connection never signs in again (spec 4.9).
      if (connection.status === 'disconnected' || connection.sessionId === null) throw new AuthFailure('sign_in_unavailable', connectionId);
      const state = b64(crypto.getRandomValues(new Uint8Array(32)));
      const verifier = b64(crypto.getRandomValues(new Uint8Array(32)));
      const verifierRef = await secrets.stage(verifier);
      const createdAt = now(), operationId = randomId('op_');
      const outcome = await commit([verifierRef], draft => {
        const current = own(draft.connections, connectionId);
        if (!current || current.generation !== connection.generation || current.status !== connection.status || current.sessionId !== connection.sessionId) throw new AuthFailure('state_changed', connectionId);
        pruneHistory(draft);
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
        // A definite rejection is a failure; a lost or non-OAuth answer may have consumed the code, so it is never resent.
        const definite = error instanceof AuthFailure && !AMBIGUOUS.has(error.code);
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
      const outcome = await commit([refreshRef, accessRef], (state, drop) => {
        const current = own(state.operations, operationId);
        // shortcut: after a full reset there is no connection to park the new grant on, so its secrets are removed and it is not revoked remotely; revoke here if resets during sign-in matter.
        if (!current || current.epoch !== state.epoch) throw new AuthFailure('state_changed');
        const target = own(state.connections, current.connectionId)!;
        // A sign-out or recovery that ran during the exchange wins; the new grant is kept only for revocation.
        if (current.phase !== 'dispatched' || target.generation !== current.connectionGeneration) {
          retire(state, `cln_${operationId}`, target, refreshRef!);
          drop.push(accessRef);
          return current.phase === 'dispatched' ? finish(state, current, 'failed', { error: 'state_changed' }) : outcomeOf(state, current);
        }
        const previous = target.grantId === null ? undefined : own(state.grants, target.grantId);
        if (previous) { retire(state, `cln_${previous.id}`, target, previous.secretRef); delete state.grants[previous.id]; }
        state.grants[grantId] = { id: grantId, issuer: target.issuer, userId: target.userId, secretRef: refreshRef!, scopes: granted, expiresAt: refreshExpiresAt, generation: 1, status: 'active', operationId: null };
        target.grantId = grantId; target.status = 'signed_in';
        // Older tokens for this session reflect the old authority, so all are retired and only the new one stays selectable (spec 4.3).
        drop.push(...Object.values(target.slots).map(slot => slot.secretRef));
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
      return commit([], (state, drop) => {
        const results: AuthOutcome[] = [];
        for (const operation of Object.values(state.operations)) {
          if (operation.epoch !== state.epoch || operation.phase === 'terminal') continue;
          // A fully staged refresh finishes locally; its fences still decide whether it activates.
          if (operation.kind === 'renew') {
            if (operation.phase === 'staged') results.push(activateRefresh(state, operation, drop));
            else results.push(operation.phase === 'prepared' ? closeRefresh(state, operation, 'failed', 'interrupted', false, drop) : closeRefresh(state, operation, 'uncertain', 'lost_response', false, drop));
          }
          // The code may have reached the issuer before the crash; only a fresh sign-in is safe.
          else if (operation.phase !== 'prepared') results.push(finish(state, operation, 'uncertain', { error: 'lost_response' }));
          else if (at >= operation.expiresAt) results.push(finish(state, operation, 'expired'));
          else continue;
          // Terminal operations never read their verifier again.
          if (operation.direct) drop.push(operation.direct.verifierRef);
        }
        return results;
      });
    },

    async renew(connectionId, input) {
      const { resource = null, scopes } = (input ?? {}) as { resource?: unknown; scopes?: unknown };
      if (resource !== null && (typeof resource !== 'string' || !URL.canParse(resource))) throw new AuthFailure('invalid_target', connectionId);
      if (scopes !== undefined && (!Array.isArray(scopes) || !scopes.length || new Set(scopes).size !== scopes.length || !scopes.every(scope => typeof scope === 'string'))) throw new AuthFailure('invalid_scope', connectionId);
      return renewal(await record(connectionId), resource, scopes ?? null);
    },

    // Sign-out wins over in-flight sign-in and refresh: disconnection and the new generation commit before anything goes remote (IMPLEMENTATION 4).
    async signOut(connectionId) {
      await record(connectionId);
      await commit([], (state, drop) => {
        const connection = own(state.connections, connectionId)!;
        if (connection.status === 'disconnected') return;
        connection.generation++; connection.status = 'disconnected';
        drop.push(...Object.values(connection.slots).map(slot => slot.secretRef));
        connection.slots = {};
        const grant = connection.grantId === null ? undefined : own(state.grants, connection.grantId);
        if (grant) { retire(state, `cln_${grant.id}`, connection, grant.secretRef); delete state.grants[grant.id]; }
        connection.grantId = null;
        for (const operation of Object.values(state.operations)) {
          if (operation.connectionId !== connectionId || operation.epoch !== state.epoch || operation.phase !== 'prepared') continue;
          finish(state, operation, 'cancelled');
          if (operation.direct) drop.push(operation.direct.verifierRef);
        }
      });
      return cleanupNow(connectionId);
    },
    retryCleanup: cleanupNow,

    async authorizedFetch(connectionId, request, target, requiredScopes = []) {
      const expected = targetOf(await record(connectionId));
      if (target.issuer !== expected.issuer || target.endpoint !== expected.endpoint || target.resource !== expected.resource) throw new AuthFailure('invalid_target', connectionId);
      // Credentials go only to the endpoint itself or a slash-delimited child on the same origin.
      const url = new URL(request.url), endpoint = new URL(expected.endpoint);
      const base = endpoint.pathname.replace(/\/$/, '');
      if (url.protocol !== 'https:' || url.hash || url.username || url.password || url.origin !== endpoint.origin || (url.pathname !== endpoint.pathname && !url.pathname.startsWith(`${base}/`))) throw new AuthFailure('invalid_target', connectionId);
      const resource = expected.resource ?? null;
      // A conversation long poll is held up to `wait` seconds (spec 7.3, 7.5); that hold must not count as a network timeout.
      const wait = url.searchParams.get('wait');
      const waitMs = wait !== null && /^\d+$/.test(wait) ? Math.min(Number(wait), MAX_WAIT_SECONDS) * 1000 : 0;
      let credential = await credentialFor(connectionId, resource, null);
      let nonceRetried = false, renewed = false;
      for (;;) {
        if (!requiredScopes.every(scope => credential.scopes.includes(scope))) throw new AuthFailure('insufficient_scope', connectionId);
        const token = await secrets.read(credential.secretRef);
        if (token === null) {
          // A concurrent renewal replaced and removed this credential; take its successor once.
          if (renewed) throw new AuthFailure('missing_credential', connectionId);
          renewed = true; credential = await credentialFor(connectionId, resource, credential.secretRef);
          continue;
        }
        const headers = new Headers(request.headers);
        headers.set('authorization', `DPoP ${token}`);
        headers.set('dpop', await proof(await loadDpopKey(credential.dpopKeyRef), request.method, request.url, token));
        // Clone per attempt so the original body stays available for a bounded retry.
        const response = await transport.fetch(new Request(request.clone(), { headers }), { waitMs });
        rememberNonce(request.url, response);
        if (response.status !== 401) return response;
        const error = dpopChallenge(response.headers.get('www-authenticate'))?.error;
        if (error === 'use_dpop_nonce' && !nonceRetried && response.headers.has('dpop-nonce')) { nonceRetried = true; continue; }
        if (error === 'invalid_token' && !renewed) { renewed = true; credential = await credentialFor(connectionId, resource, credential.secretRef); continue; }
        return response;
      }
    },
  };
}
