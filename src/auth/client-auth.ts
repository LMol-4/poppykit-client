import { parseAlternative } from '../network/tasks.js';
import type { Alternative, ExcludedTask } from '../network/tasks.js';
import { registeredRedirect } from '../network/redirect.js';
import type { AuthSelection, AuthStore } from './store.js';
import { acquireOwner, releaseOwner, localOwnerAlive } from './ownership.js';
import type { OperationOwner } from './ownership.js';
import { createHash } from 'node:crypto';
import { calculateJwkThumbprint } from 'jose';
import { parseJson, parseProtocolError, parseTokenResponse, retryAfterMilliseconds } from '../protocol/wire.js';
import type { JsonObject, TokenResponse } from '../protocol/wire.js';
import { validateClientId, signInMethods, companyIdentifier, mediatedSignIn, MEDIATED_GRANT } from '../network/discovery.js';
import type { CompanyMetadata, MetadataResolver } from '../network/discovery.js';
import type { HttpTransport } from '../network/transport.js';
import { dpopChallenge, schemeChallenge } from './challenge.js';
import { resolveApiTarget, serviceAuthorization, browserDestination, validateFeedback } from '../integrations.js';
import type { ApiTarget, AgentBrowserController, FeedbackReport } from '../integrations.js';

export type { AuthStore, AuthSelection };
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
export type AssertionRequest = { operationId: string; issuer: string; purpose: 'client-authentication' };
export interface AssertionProvider {
  assert(request: AssertionRequest): Promise<{ assertion: string; expiresAt: number }>;
  delegate?(request: { operationId: string; jwk: JsonObject }): Promise<{ delegation: string; expiresAt: number }>;
}
export interface ProviderIdentity {
  // Authenticated, issuer-specific identity from the bound enrollment adapter.
  identity(issuer: string): Promise<{ clientId: string; userId: string }>;
}
export type SignInMethod = 'direct' | 'device' | 'mediated';
export interface AuthorizationRequirement {
  scopeDescriptions?: Record<string, string>;
  requiredScopes: string[]; grantedScopes: string[]; missingScopes: string[]; sufficient: boolean;
  methods: { method: SignInMethod; scopes: string[] }[];
  organization: { name: string; domain: string };
}
export interface TrustedInput {
  // Invoke only in trusted UI code. Never expose this adapter as a model tool.
  collect(request: { operationId: string; issuer: string; organization: { name: string; domain: string }; fields: { name: string; label: string; secret: boolean }[]; challenge?: { id: string; sentTo: string; expiresAt: number } }): Promise<Record<string, string> | null>;
}
export interface SignInInput {
  method?: SignInMethod; scopes: string[]; redirectUri?: string; browserBinding?: string;
  force?: boolean; // An explicit user request to sign in again, even when the grant suffices.
  // Explicitly permit replacing a grant while dropping unneeded old scopes. Default: preserve all old scopes.
  requiredExistingScopes?: string[];
}
export interface SignInStart {
  outcome: AuthOutcome; authorizationUrl?: string;
  device?: { verificationUri: string; verificationUriComplete?: string; userCode: string; organization: { name: string; domain: string }; nextPollAt: number };
}
export interface ClientAuthOptions {
  namespace: string; localUserId: string; clientId: string;
  redirectUris: readonly string[]; // used by Direct Sign-In (J09)
  identity?: IdentitySigner;
  assertions?: AssertionProvider; providerIdentity?: ProviderIdentity; trustedInput?: TrustedInput;
  store: AuthStore; secrets: SecretStore;
  transport: HttpTransport; metadata: MetadataResolver;
  now?: () => number;
  ownerAlive?: (owner: OperationOwner) => boolean;
}

export type ConnectionStatus = 'signed_out' | 'signed_in' | 'disconnected' | 'uncertain';
export interface Connection {
  id: string; domain: string; issuer: string;
  // The verified company that answered discovery; its domain can differ from `domain` after a redirect (guide "Finding a company").
  organization: { name: string; domain: string };
  // Random Poppy sid, independent of OAuth grants and proof keys.
  sessionId: string | null; generation: number; status: ConnectionStatus;
  scopes: string[];
}
export type OperationStatus = 'pending' | 'completed' | 'denied' | 'expired' | 'cancelled' | 'failed' | 'uncertain';
export interface AuthOutcome {
  operationId: string; status: OperationStatus; connection: Connection;
  error?: string; grantedScopes?: string[]; missingScopes?: string[]; retryAfterMs?: number;
  nextAction?: 'wait' | 'sign_in' | 'retry_cleanup';
}
export interface SignOutOutcome { connection: Connection; cleanup: 'complete' | 'pending' | 'uncertain' }
export interface ConversationTarget { issuer: string; endpoint: string; resource?: string }
export interface ClientAuth {
  start(domain: string, input?: { anonymous?: boolean; accountFrom?: string }): Promise<AuthOutcome>;
  get(connectionId: string): Promise<Connection | null>;
  list(): Promise<Connection[]>;
  target(connectionId: string): Promise<ConversationTarget>;
  authorization(connectionId: string, requiredScopes: readonly string[]): Promise<AuthorizationRequirement>;
  beginSignIn(connectionId: string, input: SignInInput): Promise<SignInStart>;
  continueSignIn(operationId: string): Promise<AuthOutcome>;
  completeSignIn(input: { callbackUrl: string; browserBinding: string }): Promise<AuthOutcome>;
  cancelSignIn(operationId: string): Promise<AuthOutcome>;
  operation(operationId: string): Promise<AuthOutcome | null>;
  renew(connectionId: string, input?: { resource?: string; scopes?: string[] }): Promise<AuthOutcome>;
  signOut(connectionId: string): Promise<SignOutOutcome>;
  retryCleanup(connectionId: string): Promise<SignOutOutcome>;
  recover(): Promise<AuthOutcome[]>;
  authorizedFetch(connectionId: string, request: Request, target: ConversationTarget, requiredScopes?: readonly string[]): Promise<Response>;
  apiTarget(connectionId: string, apiUrl: string, destination?: string): Promise<ApiTarget>;
  apiFetch(connectionId: string, request: Request, target: ApiTarget, requiredScopes?: readonly string[]): Promise<Response>;
  joinBrowser(connectionId: string, returnTo: string, controller: AgentBrowserController): Promise<void>;
  feedback(connectionId: string, report: FeedbackReport): Promise<Alternative | void>;
  excludedTasks(connectionId: string): Promise<ExcludedTask[]>;
}

export interface CredentialRecord {
  secretRef: string; tokenType: 'DPoP' | 'Bearer'; dpopKeyRef: string;
  scopes: string[]; expiresAt: number; generation: number;
}
export interface ConnectionRecord {
  id: string; domain: string; issuer: string; metadata: CompanyMetadata;
  userId: string; dpopKeyRef: string; sessionId: string | null;
  generation: number; status: ConnectionStatus; grantId: string | null;
  // Key JSON.stringify([sessionId, resource ?? null]); preserves absent vs exact resource.
  slots: Record<string, CredentialRecord>;
  anonymous?: boolean; notBefore?: string;
  needsSessionKey?: boolean;
  sessionSigning?: { keyRef: string; delegationRef: string; expiresAt: number };
  signingCleanup?: string[];
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
  owner?: OperationOwner;
  epoch: string; id: string; kind: 'start' | 'renew' | 'sign_in'; connectionId: string;
  connectionGeneration: number; grantId: string | null; grantGeneration: number | null;
  phase: 'prepared' | 'dispatched' | 'staged' | 'terminal';
  status: OperationStatus; createdAt: number; expiresAt: number;
  resource: string | null; scopes: string[];
  // Sign-in activates in one transaction with its result; only refresh records staged refs first.
  direct: DirectRecord | null; staged: StagedRefresh | null;
  result: AuthOutcome | null;
  method?: SignInMethod; requiredExistingScopes?: string[]; signInSessionId?: string; signInSessionKey?: string;
  device?: { codeRef: string; intervalMs: number; nextPollAt: number };
  mediated?: { challengeId: string; sentTo: string };
  cancelRequested?: boolean;
}
export interface StagedRefresh {
  tokenType?: 'DPoP' | 'Bearer';
  accessRef: string; refreshRef: string | null; sessionId: string; scopes: string[];
  signedIn: boolean; expiresAt: number; refreshExpiresAt: number | null;
}
// An Account Token that must be revoked remotely before its secret is deleted; uncertain means its secret is gone.
export interface CleanupRecord {
  id: string; connectionId: string; issuer: string; revocationEndpoint: string;
  secretRef: string; status: 'pending' | 'uncertain';
  notBefore?: string;
}
export interface ClientAuthState {
  version: 1 | 2 | 3; epoch: string;
  owner: { namespace: string; clientId: string; localUserId: string } | null;
  identities: Record<string, { userId: string; dpopKeyRef?: string }>;
  connections: Record<string, ConnectionRecord>;
  grants: Record<string, GrantRecord>;
  operations: Record<string, OperationRecord>;
  cleanup: Record<string, CleanupRecord>;
}

export class AuthFailure extends Error {
  constructor(readonly code: string, readonly connectionId?: string, readonly retryAfterMs?: number, readonly retryAt?: string) { super(`Auth ${code}`); this.name = 'AuthFailure'; }
}

class MediatedCodeRequired extends AuthFailure {
  constructor(readonly challenge: { id: string; sentTo: string; expiresAt: number }) { super('code_required'); }
}

const EC = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const ES256 = { name: 'ECDSA', hash: 'SHA-256' } as const;
const SKEW_MS = 30_000;
// Token endpoint failures after which the Company may have acted: lost, unreadable or non-OAuth answers.
const AMBIGUOUS = new Set(['transport_error', 'invalid_response', 'token_error']);
const CLIENT_ASSERTION = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const ASSERTION_SECONDS = 60;
function providerFailure(error: unknown, connectionId?: string): AuthFailure {
  const code = (error as { code?: unknown } | null)?.code;
  return new AuthFailure(code === 'unauthorized' ? 'provider_unauthorized' : code === 'rate_limited' ? 'provider_rate_limited'
    : ['timeout', 'network_error', 'blocked_address', 'overloaded', 'closed'].includes(String(code)) ? 'provider_network_error'
    : ['invalid_response', 'binding_conflict', 'expired', 'consumed', 'canceled'].includes(String(code)) ? 'provider_invalid_response' : 'provider_unavailable', connectionId);
}
// OAuth codes the token endpoint may return (spec 4.2, RFC 6749/8707); anything else is reported as token_error.
const SAFE_ERRORS = new Set(['invalid_request', 'invalid_client', 'invalid_grant', 'unauthorized_client', 'unsupported_grant_type', 'invalid_scope', 'invalid_target', 'account_mismatch', 'invalid_dpop_proof', 'use_dpop_nonce', 'extension_required', 'rate_limited']);

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
function safeHttps(value: string): boolean {
  try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password && !url.hash && !/[\\\s\x00-\x1f]/.test(value); } catch { return false; }
}
function allowedHost(value: string, hosts: readonly string[]): boolean {
  if (!safeHttps(value)) return false;
  const hostname = new URL(value).hostname.toLowerCase();
  return hosts.some(host => hostname === host.toLowerCase() || hostname.endsWith(`.${host.toLowerCase()}`));
}
// Ignore unknown OAuth response fields, but preserve every registered redirect component.
function redirectMatches(url: URL, registered: URL): boolean {
  return url.origin === registered.origin && url.username === registered.username && url.password === registered.password && url.pathname === registered.pathname
    && [...registered.searchParams.keys()].every(key => JSON.stringify(url.searchParams.getAll(key)) === JSON.stringify(registered.searchParams.getAll(key)));
}

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
  return { version: 3, epoch: randomId(), owner: null, identities: {}, connections: {}, grants: {}, operations: {}, cleanup: {} };
}

/** Upgrade a complete namespace under its writer lock; dispatched/staged work still goes through recover(). */
export function upgradeClientAuthState(state: ClientAuthState): void {
  if (state.version === 3) return;
  if (state.version !== 1 && state.version !== 2) throw new Error('unsupported auth state version');
  for (const connection of Object.values(state.connections)) { connection.needsSessionKey = true; connection.slots = {}; }
  for (const operation of Object.values(state.operations)) if (operation.phase === 'prepared') {
    operation.phase = 'terminal'; operation.status = 'cancelled';
    const connection = own(state.connections, operation.connectionId);
    if (connection) (connection.signingCleanup ??= []).push(...(operation.direct ? [operation.direct.verifierRef] : []), ...(operation.device ? [operation.device.codeRef] : []));
    operation.result = null;
    const grant = operation.grantId ? own(state.grants, operation.grantId) : undefined;
    if (grant?.operationId === operation.id) grant.operationId = null;
  }
  state.version = 3;
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
interface AcquiredToken { token: TokenResponse; scheme: 'DPoP' | 'Bearer' }

export function createClientAuth(options: ClientAuthOptions): ClientAuth {
  const { namespace, localUserId, clientId, identity, store, transport } = options;
  // Session Tokens live in memory only (guide "Storing tokens"); after a restart the missing token triggers a renewal.
  const sessionTokens = new Map<string, string>(); // keyed by refs this closure created, so a host ref can never match
  const secrets: SecretStore = {
    stage: secret => options.secrets.stage(secret),
    read: async ref => sessionTokens.has(ref) ? sessionTokens.get(ref)! : options.secrets.read(ref),
    remove: async ref => { if (!sessionTokens.delete(ref)) await options.secrets.remove(ref); },
  };
  async function stageSessionToken(token: string): Promise<string> { const ref = `mem:${randomId()}`; sessionTokens.set(ref, token); return ref; }
  const now = options.now ?? Date.now;
  if (typeof namespace !== 'string' || !namespace || typeof localUserId !== 'string' || !localUserId) throw new AuthFailure('invalid_options');
  try { validateClientId(clientId); } catch { throw new AuthFailure('invalid_options'); }
  if ((!identity && !options.assertions) || (!!options.assertions !== !!options.providerIdentity)) throw new AuthFailure('invalid_options');
  const owner = { namespace, clientId, localUserId };
  // shortcut: nonces live in memory per origin, so a restart costs one extra use_dpop_nonce round trip.
  const nonces = new Map<string, string>();

  function checkOwner(state: ClientAuthState): void {
    if (state.owner && (state.owner.namespace !== namespace || state.owner.clientId !== clientId || state.owner.localUserId !== localUserId)) throw new AuthFailure('owner_mismatch');
  }
  async function load(selection: AuthSelection): Promise<ClientAuthState> { const state = await store.read(selection); checkOwner(state); upgradeClientAuthState(state); return state; }
  function transaction<T>(selection: AuthSelection, change: (state: ClientAuthState) => T): Promise<T> {
    return store.transaction(selection, state => { checkOwner(state); upgradeClientAuthState(state); state.owner ??= owner; return change(state); });
  }
  async function record(connectionId: string): Promise<ConnectionRecord> {
    const found = typeof connectionId === 'string' ? own((await load({ connectionId })).connections, connectionId) : undefined;
    if (!found) throw new AuthFailure('unknown_connection');
    return found;
  }
  function destinations(metadata: CompanyMetadata): string {
    const auth = metadata.authorization;
    return JSON.stringify([auth?.issuer, auth?.token_endpoint, auth?.revocation_endpoint, auth?.authorization_endpoint, auth?.device_authorization_endpoint,
      metadata.document.extensions?.['mediated-sign-in'], metadata.document.agent?.protocols, metadata.document.apis, metadata.document.web, metadata.document.feedback]);
  }
  async function verified(metadata: CompanyMetadata): Promise<CompanyMetadata> {
    let fresh: CompanyMetadata;
    try { fresh = await options.metadata.resolveCompany(new URL(metadata.url).host); } catch { throw new AuthFailure('discovery_failed'); }
    if (destinations(fresh) !== destinations(metadata)) throw new AuthFailure('metadata_changed');
    return fresh;
  }
  async function currentConnection(id: string): Promise<ConnectionRecord> {
    const found = await record(id), metadata = await verified(found.metadata);
    return await transaction({ connectionId: id }, state => {
      const current = own(state.connections, id)!;
      if (destinations(current.metadata) !== destinations(metadata)) throw new AuthFailure('state_changed', id);
      current.metadata = metadata; return current;
    });
  }
  function publicConnection(state: ClientAuthState, connection: ConnectionRecord): Connection {
    const { id, domain, issuer, sessionId, generation, status, grantId } = connection;
    const scopes = grantId === null ? [] : [...own(state.grants, grantId)?.scopes ?? []];
    return { id, domain, issuer, organization: { ...connection.metadata.document.organization }, sessionId, generation, status, scopes };
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
    if (!identity) throw new AuthFailure('invalid_signer');
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
  async function proof(key: DpopKey, method: string, url: string, token?: string, browserCode?: string): Promise<string> {
    const htu = new URL(url); htu.search = ''; htu.hash = '';
    const payload: JsonObject = { jti: randomId(), htm: method, htu: htu.href, iat: Math.floor(now() / 1000) };
    if (token !== undefined) payload.ath = b64(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))));
    const nonce = browserCode ?? nonces.get(htu.origin);
    if (nonce !== undefined) payload.nonce = nonce;
    return compact({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.jwk }, payload, async input => new Uint8Array(await crypto.subtle.sign(ES256, key.privateKey, input)));
  }

  const signing = new Map<string, Promise<ConnectionRecord>>();
  async function cleanupSigning(connection: ConnectionRecord): Promise<void> {
    for (const ref of connection.signingCleanup ?? []) {
      try { await secrets.remove(ref); } catch { return; }
      await transaction({connectionId:connection.id},state=>{
        const live=own(state.connections,connection.id)!;
        live.signingCleanup=(live.signingCleanup ?? []).filter(value=>value!==ref);
        if (!live.signingCleanup.length) delete live.signingCleanup;
      });
    }
  }
  async function signingConnection(connection: ConnectionRecord): Promise<ConnectionRecord> {
    await cleanupSigning(connection);
    connection=await record(connection.id);
    if ((connection.signingCleanup?.length ?? 0) >= 128) throw new AuthFailure('storage_cleanup_pending');
    if (connection.sessionSigning && connection.sessionSigning.expiresAt > now() + SKEW_MS) return connection;
    let pending = signing.get(connection.id);
    if (!pending) {
      pending = (async () => {
        const keyRef = await newSessionKey(), key = await loadDpopKey(keyRef);
        const at = Math.floor(now() / 1800000) * 1800; let expiresAt = (at + 3600) * 1000;
        let delegation: string, committing = false;
        try {
          if (options.assertions && !connection.anonymous) {
            if (!options.assertions.delegate) throw new AuthFailure('provider_delegation_unavailable');
            let result;
            try { result = await options.assertions.delegate({ operationId: randomId('dlg_'), jwk: key.jwk }); }
            catch (error) { throw providerFailure(error); }
            if (!result || typeof result.delegation !== 'string' || !result.delegation || !Number.isFinite(result.expiresAt) || result.expiresAt * 1000 <= now() || result.expiresAt * 1000 > now() + 3600000 + SKEW_MS) throw new AuthFailure('provider_invalid_response');
            delegation = result.delegation; expiresAt = result.expiresAt * 1000;
          } else delegation = await signIdentity({ typ: 'pap-delegation+jwt' }, { iss: clientId, cnf: { jwk: key.jwk }, iat: at, exp: at + 3600, jti: randomId() }, key.thumbprint);
          const delegationRef = await secrets.stage(delegation);
          committing = true;
          const current = await commit({ connectionId: connection.id }, [keyRef, delegationRef], (state, drop) => {
            const live = own(state.connections, connection.id)!;
            if (live.generation !== connection.generation || live.userId !== connection.userId || live.sessionId !== connection.sessionId) throw new AuthFailure('state_changed');
            if (live.sessionSigning && live.sessionSigning.expiresAt > now() + SKEW_MS) drop.push(keyRef, delegationRef);
            else {
              if (live.sessionSigning) (live.signingCleanup ??= []).push(live.sessionSigning.keyRef, live.sessionSigning.delegationRef);
              live.sessionSigning = { keyRef, delegationRef, expiresAt };
            }
            return live;
          });
          await cleanupSigning(current);
          return current;
        } catch (error) { if (!committing) await secrets.remove(keyRef); throw error; }
      })().finally(() => signing.delete(connection.id));
      signing.set(connection.id, pending);
    }
    return pending;
  }
  async function sessionHeader(connection: ConnectionRecord, request: Request, token?: string): Promise<string> {
    if (connection.anonymous && token !== undefined) throw new AuthFailure('anonymous_account_access');
    connection = await signingConnection(connection);
    const material = connection.sessionSigning!;
    if (!connection.sessionId || !connection.userId || material.expiresAt <= now()) throw new AuthFailure('invalid_session');
    const delegation = await secrets.read(material.delegationRef), key = await loadDpopKey(material.keyRef);
    if (!delegation) throw new AuthFailure('missing_key');
    const url = new URL(request.url); url.search = ''; url.hash = '';
    const claims: JsonObject = { iss: clientId, aud: connection.issuer, sid: connection.sessionId, sub: connection.userId,
      htm: request.method, htu: url.href, iat: Math.floor(now() / 1000), jti: randomId(), ...(token === undefined ? {} : { ath: sha256(token) }) };
    return compact({ typ: 'poppy-session+jwt', alg: 'ES256', kid: key.thumbprint, pap_dlg: delegation }, claims,
      async input => new Uint8Array(await crypto.subtle.sign(ES256, key.privateKey, input)));
  }

  function rememberNonce(url: string, response: Response): void {
    const nonce = response.headers.get('dpop-nonce');
    if (nonce) nonces.set(new URL(url).origin, nonce);
  }

  function assertionClaims(sub: string, aud: string): JsonObject {
    const iat = Math.floor(now() / 1000);
    return { iss: clientId, sub, aud, iat, exp: iat + ASSERTION_SECONDS, jti: randomId() };
  }
  async function assertion(purpose: 'client-authentication', issuer: string, key: DpopKey, sub = clientId, operationId = randomId('op_')): Promise<string> {
    if (!options.assertions) return signIdentity({ typ: 'client-authentication+jwt' }, assertionClaims(sub, issuer), key.thumbprint);
    let result;
    try { result = await options.assertions.assert({ operationId, issuer, purpose }); }
    catch (error) { throw providerFailure(error); }
    return providerAssertion(result);
  }
  function providerAssertion(result: { assertion: string; expiresAt: number }, connectionId?: string): string {
    if (!result || typeof result.assertion !== 'string' || !result.assertion || !Number.isFinite(result.expiresAt)) throw new AuthFailure('provider_invalid_response', connectionId);
    const at = now(), expires = result.expiresAt * 1000;
    if (expires <= at) throw new AuthFailure('provider_assertion_expired', connectionId);
    // Local freshness tolerance; the issuer still verifies signed claims, lifetime and replay.
    if (expires > at + ASSERTION_SECONDS * 1000 + SKEW_MS) throw new AuthFailure('provider_clock_skew', connectionId);
    return result.assertion;
  }
  function responseFailure(response: Response, code: string): AuthFailure {
    const value = response.headers.get('retry-after');
    const delay = retryAfterMilliseconds(value, now());
    const deadline = value && /^\d+$/.test(value) ? (BigInt(Math.floor(now())) + BigInt(value) * 1000n).toString()
      : delay === undefined ? undefined : String(Math.floor(now() + delay));
    return new AuthFailure(code, undefined, delay, deadline);
  }
  // OAuth requests use client authentication and optional DPoP, independently of Sessions.
  // Throws transport_error only when the request may have reached the issuer without a readable answer.
  async function tokenRequest(metadata: CompanyMetadata, dpopKeyRef: string, fields: Record<string, string>, operationId?: string): Promise<AcquiredToken> {
    const authorization = (await verified(metadata)).authorization!;
    const endpoint = authorization.token_endpoint;
    const key = await loadDpopKey(dpopKeyRef);
    const scheme = await resourceScheme(metadata, fields.resource ?? null);
    for (let attempt = 0; ; attempt++) {
      if (attempt > 0 && operationId && own((await load({operationId})).operations,operationId)?.cancelRequested) throw new AuthFailure('cancelled');
      const issuedAt=now();
      const body = new URLSearchParams(fields);
      body.set('client_id', clientId);
      body.set('client_assertion_type', CLIENT_ASSERTION);
      body.set('client_assertion', await assertion('client-authentication', authorization.issuer, key));
      const headers = new Headers({ accept: 'application/json' });
      if (scheme === 'DPoP') headers.set('dpop', await proof(key, 'POST', endpoint));
      const request = new Request(endpoint, { method: 'POST', body, headers });
      let response: Response, text: string;
      try { response = await transport.fetch(request); } catch { throw new AuthFailure('transport_error'); }
      try { text = await response.text(); } catch { throw responseFailure(response, 'transport_error'); }
      rememberNonce(endpoint, response);
      let json: unknown;
      try { json = parseJson(text); } catch { /* reported below */ }
      if (response.status === 200) {
        try {
          const token = parseTokenResponse(json);
          if (token.token_type === 'DPoP' && !headers.has('dpop')) throw 0;
          return { token, scheme: token.token_type };
        } catch { throw new AuthFailure('invalid_response'); }
      }
      if (response.status === 400 && json && typeof json === 'object' && 'error' in json && json.error === 'code_required') {
        const value=json as Record<string,unknown>;
        if (typeof value.sign_in_id !== 'string' || !/^[A-Za-z0-9_-]{1,256}$/.test(value.sign_in_id) || typeof value.sent_to !== 'string' || value.sent_to.length>512 || !Number.isSafeInteger(value.expires_in) || (value.expires_in as number)<=0 || !Number.isSafeInteger(issuedAt+(value.expires_in as number)*1000)) throw new AuthFailure('invalid_response');
        throw new MediatedCodeRequired({id:value.sign_in_id,sentTo:value.sent_to,expiresAt:issuedAt+(value.expires_in as number)*1000});
      }
      let error = response.status === 429 ? 'rate_limited' : 'token_error';
      try { if (response.status !== 429) error = parseProtocolError(json).error; } catch { /* non-OAuth body */ }
      if (error === 'use_dpop_nonce' && response.status === 400 && attempt === 0 && response.headers.has('dpop-nonce')) continue;
      // Only a recognised OAuth code on a 4xx is a definite rejection; a 5xx or proxy page may follow a completed exchange.
      throw responseFailure(response, response.status >= 400 && response.status < 500 && (SAFE_ERRORS.has(error) || ['authorization_pending', 'slow_down', 'access_denied', 'expired_token'].includes(error) || response.status === 429) ? error : 'token_error');
    }
  }

  async function resourceScheme(metadata: CompanyMetadata, resource: string | null): Promise<'DPoP' | 'Bearer'> {
    const mcp = metadata.document.apis?.find(api => api.type === 'mcp' && api.url === resource);
    if (!mcp) return metadata.authorization?.dpop_signing_alg_values_supported?.includes('ES256') ? 'DPoP' : 'Bearer';
    try { return (await serviceAuthorization(metadata, options.metadata, transport, mcp.url, { mcp: true })).scheme; }
    catch { throw new AuthFailure('invalid_target'); }
  }

  async function newSessionKey(): Promise<string> {
    // shortcut: SecretStore stores a private JWK; use a host signer when non-extractable key persistence is available.
    const pair = await crypto.subtle.generateKey(EC, true, ['sign', 'verify']);
    const { kty, crv, x, y, d } = await crypto.subtle.exportKey('jwk', pair.privateKey);
    return secrets.stage(JSON.stringify({ kty, crv, x, y, d }));
  }
  async function identityFor(issuer: string, anonymous = false): Promise<{ userId: string }> {
    if (anonymous && !identity) throw new AuthFailure('anonymous_unavailable');
    const existing = anonymous ? undefined : own((await load({ issuer })).identities, issuer);
    if (existing) return existing;
    let userId = randomId('usr_');
    if (options.providerIdentity && !anonymous) {
      let bound;
      try { bound = await options.providerIdentity.identity(issuer); }
      catch (error) { throw providerFailure(error); }
      if (!bound || bound.clientId !== clientId || typeof bound.userId !== 'string' || !bound.userId) throw new AuthFailure('provider_invalid_response');
      userId = bound.userId;
    }
    if (anonymous) return { userId };
    return transaction({ issuer }, state => own(state.identities, issuer) ?? (state.identities[issuer] = { userId }));
  }

  async function freshSessionKey(connection: ConnectionRecord, operationId?: string): Promise<ConnectionRecord> {
    const ref = await newSessionKey();
    const current = await commit({ connectionId: connection.id }, [ref], (state, drop) => {
      const live = own(state.connections, connection.id)!;
      if (live.generation !== connection.generation || live.dpopKeyRef !== connection.dpopKeyRef) { drop.push(ref); return live; }
      // Legacy keys may still be referenced by another old connection, so never delete them here.
      if (!live.needsSessionKey) drop.push(live.dpopKeyRef);
      live.dpopKeyRef = ref; delete live.needsSessionKey; live.generation++;
      if (operationId) own(state.operations, operationId)!.connectionGeneration = live.generation;
      return live;
    });
    return current;
  }

  // Commits a change that may stage or release secrets. When our own fence check rejects it, nothing references the
  // staged secrets, so they are removed; references the committed change pushed to `drop` are removed after commit.
  // shortcut: a crash between stage() and commit leaves an unreferenced secret; SecretStore cannot list, so add a sweep when D offers one.
  async function commit<T>(selection: AuthSelection, staged: (string | null)[], change: (state: ClientAuthState, drop: string[]) => T): Promise<T> {
    const drop: string[] = [];
    let result: T;
    try { result = await transaction(selection, state => { drop.length = 0; return change(state, drop); }); } catch (error) {
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
    const done = Object.values(state.operations).filter(op => op.kind !== 'renew' && op.phase === 'terminal' && op.status !== 'uncertain').sort((a, b) => b.createdAt - a.createdAt || (a.id < b.id ? 1 : a.id > b.id ? -1 : 0));
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
    return transaction({ connectionId: connection.id }, state => {
      const current = own(state.connections, connection.id)!;
      return finish(state, renewOperation(state, randomId('op_'), current, null, now(), resource, []), 'completed');
    });
  }

  // Account Token refresh (spec 4.8). The grant claim allows one rotation in flight per grant across processes,
  // because a second sender could present a token the first rotation already replaced.
  async function refresh(connection: ConnectionRecord, resource: string | null, scopes: string[] | null): Promise<AuthOutcome> {
    const executionOwner = acquireOwner();
    try {
    const at = now(), operationId = randomId('op_');
    const claim = await transaction({ connectionId: connection.id }, state => {
      const current = own(state.connections, connection.id)!;
      const grant = current.grantId === null ? undefined : own(state.grants, current.grantId);
      if (current.status !== 'signed_in' || !grant) throw new AuthFailure('state_changed', connection.id);
      const running = grant.operationId === null ? undefined : own(state.operations, grant.operationId);
      if (running && running.phase !== 'terminal') return { running: outcomeOf(state, running) } as const;
      if (grant.status !== 'active') throw new AuthFailure('grant_uncertain', connection.id);
      if (scopes && !scopes.every(scope => grant.scopes.includes(scope))) throw new AuthFailure('invalid_scope', connection.id);
      grant.operationId = operationId;
      const operation = renewOperation(state, operationId, current, grant, at, resource, scopes ?? [...grant.scopes]);
      operation.owner = executionOwner;
      return { running: null, connection: current, secretRef: grant.secretRef, requested: operation.scopes };
    });
    if (claim.running) return claim.running;
    let refreshToken: string | null;
    try { refreshToken = await secrets.read(claim.secretRef); } catch { return await endRefresh(operationId, 'failed', 'storage_error'); }
    if (refreshToken === null) return await endRefresh(operationId, 'failed', 'missing_credential');
    if (claim.connection.needsSessionKey) claim.connection = await freshSessionKey(claim.connection, operationId);
    const fields: Record<string, string> = { grant_type: 'refresh_token', refresh_token: refreshToken };
    if (resource !== null) fields.resource = resource;
    if (scopes) fields.scope = scopes.join(' ');
    // The last local step before the send; a crash before it sent nothing, so recover just releases the grant.
    const dispatched = await transaction({ operationId }, state => {
      const operation = own(state.operations, operationId);
      if (!operation || operation.epoch !== state.epoch || operation.phase !== 'prepared') return false;
      operation.phase = 'dispatched'; operation.owner = executionOwner;
      return true;
    });
    if (!dispatched) return await endRefresh(operationId, 'failed', 'state_changed');
    const issuedAt = now();
    const send = () => tokenRequest(claim.connection.metadata, claim.connection.dpopKeyRef, fields);
    let acquired: AcquiredToken | undefined;
    try {
      acquired = await send();
    } catch (error) {
      if (error instanceof AuthFailure && error.retryAfterMs !== undefined) await holdOff(connection.id, error);
      const code = error instanceof AuthFailure ? error.code : 'local_error'; // non-AuthFailure errors come from local signing before dispatch
      // A lost, unreadable or non-OAuth answer may follow a rotation, so the old Account Token is never resent (IMPLEMENTATION 4).
      if (AMBIGUOUS.has(code)) return await endRefresh(operationId, 'uncertain', 'lost_response');
      return await endRefresh(operationId, 'failed', code);
    }
    const { token, scheme } = acquired;
    const granted = (token.scope ?? claim.requested.join(' ')).split(' ').filter(Boolean);
    let problem: string | null = null;
    if (token.token_type !== scheme) problem = 'unsupported_token_type';
    else if (granted.some(scope => !claim.requested.includes(scope))) problem = 'invalid_response';
    let refreshRef: string | null = null, accessRef: string | null = null;
    try { if (token.refresh_token !== undefined) refreshRef = await secrets.stage(token.refresh_token); } catch { return await endRefresh(operationId, 'uncertain', 'storage_error'); }
    if (!problem) try { accessRef = await stageSessionToken(token.access_token); } catch { problem = 'storage_error'; }
    if (problem || accessRef === null) return await endRefresh(operationId, 'failed', problem ?? 'storage_error', refreshRef);
    const staged: StagedRefresh = {
      accessRef, refreshRef, tokenType: token.token_type, sessionId: claim.connection.sessionId!, scopes: granted, signedIn: true, expiresAt: issuedAt + (token.expires_in ?? 60) * 1000,
      refreshExpiresAt: token.refresh_token_expires_in === undefined ? null : issuedAt + token.refresh_token_expires_in * 1000,
    };
    // Its own commit, so a crash before activation leaves the new Account Token referenced for recover (interface 4).
    const recorded = await transaction({ operationId }, state => {
      const operation = own(state.operations, operationId);
      if (!operation || operation.epoch !== state.epoch || operation.phase !== 'dispatched') return false;
      operation.phase = 'staged'; operation.staged = staged;
      return true;
    });
    if (!recorded) return await endRefresh(operationId, 'failed', 'state_changed', refreshRef, accessRef);
    return await commit({ operationId }, [accessRef, refreshRef], (state, drop) => {
      const operation = own(state.operations, operationId);
      if (!operation || operation.epoch !== state.epoch) throw new AuthFailure('state_changed');
      return operation.phase === 'staged' ? activateRefresh(state, operation, drop) : outcomeOf(state, operation);
    });
    } finally { releaseOwner(executionOwner); }
  }
  // Ends a refresh that will not activate. A returned Account Token is parked for revocation.
  function endRefresh(operationId: string, status: OperationStatus, error: string, refreshRef: string | null = null, accessRef: string | null = null): Promise<AuthOutcome> {
    return commit({ operationId }, [refreshRef, accessRef], (state, drop) => {
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
      if (Object.values(state.connections).some(peer => peer.grantId === grant.id)) {
        if (error === 'invalid_grant') {
          // Expired or revoked: the Session continues signed out and the User signs in again only on request (spec 4.8, 4.9).
          drop.push(grant.secretRef);
          delete state.grants[grant.id];
          for (const peer of Object.values(state.connections)) if (peer.grantId === grant.id) {
            drop.push(...Object.values(peer.slots).map(slot => slot.secretRef));
            peer.grantId = null; peer.status = 'signed_out'; peer.slots = {}; peer.generation++;
          }
        } else if (status === 'uncertain' || rotated) {
          // The Account Token we hold may already be replaced; only a fresh sign-in is safe.
          grant.status = 'uncertain';
          for (const peer of Object.values(state.connections)) if (peer.grantId === grant.id) { peer.status = 'uncertain'; peer.generation++; }
        }
      }
    }
    return finish(state, operation, status, { error });
  }
  function activateRefresh(state: ClientAuthState, operation: OperationRecord, drop: string[]): AuthOutcome {
    const staged = operation.staged!;
    const connection = own(state.connections, operation.connectionId)!;
    const grant = operation.grantId === null ? undefined : own(state.grants, operation.grantId);
    if (!grant || grant.operationId !== operation.id || grant.generation !== operation.grantGeneration) {
      if (staged.refreshRef !== null) retire(state, `cln_${operation.id}`, connection, staged.refreshRef);
      drop.push(staged.accessRef);
      return finish(state, operation, 'failed', { error: 'state_changed' });
    }
    grant.operationId = null; grant.generation++;
    if (staged.refreshRef !== null) {
      drop.push(grant.secretRef); grant.secretRef = staged.refreshRef;
      if (staged.refreshExpiresAt !== null) grant.expiresAt = staged.refreshExpiresAt;
    }
    // Rotation belongs to the grant even if its initiating Session was replaced meanwhile.
    if (connection.grantId !== grant.id || connection.generation !== operation.connectionGeneration) {
      drop.push(staged.accessRef);
      return finish(state, operation, 'failed', { error: 'state_changed' });
    }
    switchSession(connection, staged.sessionId, drop);
    // Only this resource's credential changes; other resources' credentials survive (IMPLEMENTATION 3).
    replaceSlot(connection, operation.resource, { secretRef: staged.accessRef, tokenType: staged.tokenType ?? 'DPoP', dpopKeyRef: connection.dpopKeyRef, scopes: staged.scopes, expiresAt: staged.expiresAt, generation: connection.generation }, drop);
    return finish(state, operation, 'completed');
  }
  // Decimal absolute milliseconds preserve even Retry-After values beyond safe JS integers.
  async function holdOff(connectionId: string, error: AuthFailure): Promise<void> {
    if (error.retryAt === undefined) return;
    await transaction({ connectionId }, state => {
      const connection = own(state.connections, connectionId)!;
      if (BigInt(error.retryAt!) > BigInt(connection.notBefore ?? '0')) connection.notBefore = error.retryAt;
    });
  }
  function checkCooldown(connection: ConnectionRecord): void {
    const wait = BigInt(connection.notBefore ?? '0') - BigInt(Math.floor(now()));
    if (wait > 0n) throw new AuthFailure('rate_limited', connection.id, Number(wait), connection.notBefore);
  }
  // Every token-request path (internal refresh and public renew) goes through here, so all honour Retry-After.
  async function renewal(connection: ConnectionRecord, resource: string | null, scopes: string[] | null): Promise<AuthOutcome> {
    // Local failures first: a wait is only meaningful for a connection that can still send a token request.
    if (connection.status === 'signed_out' && scopes?.length) throw new AuthFailure('invalid_scope', connection.id);
    if (connection.status !== 'signed_out' && connection.status !== 'signed_in') throw new AuthFailure(connection.status === 'disconnected' ? 'disconnected' : 'grant_uncertain', connection.id);
    checkCooldown(await record(connection.id));
    let outcome: AuthOutcome;
    try {
      outcome = connection.status === 'signed_out' ? await signedOutRenewal(connection, resource) : await refresh(connection, resource, scopes);
    } catch (error) {
      if (error instanceof AuthFailure && error.retryAfterMs !== undefined) await holdOff(connection.id, error);
      throw error;
    }
    const deadline = (await record(connection.id)).notBefore;
    return deadline === undefined ? outcome : { ...outcome, retryAfterMs: Math.max(0, Number(BigInt(deadline) - BigInt(Math.floor(now())))) };
  }

  // In-process single flight: parallel requests on one stale slot share one renewal; the grant claim covers other processes.
  const renewing = new Map<string, Promise<CredentialRecord>>();
  function renewShared(connectionId: string, resource: string | null): Promise<CredentialRecord> {
    const key = JSON.stringify([connectionId, resource]);
    let pending = renewing.get(key);
    if (!pending) {
      pending = (async () => {
        const outcome = await renewal(await record(connectionId), resource, null);
        if (outcome.status !== 'completed') throw new AuthFailure(outcome.status === 'pending' ? 'renewal_pending' : outcome.error ?? 'renewal_failed', connectionId, outcome.retryAfterMs);
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
    if (connection.status === 'uncertain') throw new AuthFailure('grant_uncertain', connectionId);
    const slot = own(connection.slots, slotKey(connection.sessionId, resource));
    return slot && slot.secretRef !== stale && slot.expiresAt - SKEW_MS > now() ? slot : renewShared(connectionId, resource);
  }

  function cleanupStatus(state: ClientAuthState, connectionId: string): SignOutOutcome['cleanup'] {
    const operations = Object.values(state.operations).filter(op => op.connectionId === connectionId && op.epoch === state.epoch);
    const items = Object.values(state.cleanup).filter(item => item.connectionId === connectionId);
    // A lost exchange or rotation may have issued an Account Token we never saw, so it can never be claimed revoked.
    if (operations.some(op => op.status === 'uncertain') || items.some(item => item.status === 'uncertain')) return 'uncertain';
    return items.length || operations.some(op => op.phase !== 'terminal' && op.phase !== 'prepared') || (own(state.connections,connectionId)?.signingCleanup?.length ?? 0) ? 'pending' : 'complete';
  }
  // RFC 7009 revocation with a fresh client assertion (spec 4.9). Replay is safe, so anything but 200 stays pending.
  async function revoke(connection: ConnectionRecord, item: CleanupRecord, token: string): Promise<boolean> {
    try {
      if (BigInt(item.notBefore ?? '0') > BigInt(Math.floor(now()))) return false;
      const key = await loadDpopKey(connection.dpopKeyRef);
      await verified(connection.metadata);
      const body = new URLSearchParams({ token, token_type_hint: 'refresh_token', client_id: clientId, client_assertion_type: CLIENT_ASSERTION, client_assertion: await assertion('client-authentication', item.issuer, key) });
      const response = await transport.fetch(new Request(item.revocationEndpoint, { method: 'POST', body, headers: { accept: 'application/json' } }));
      if (response.status === 429 || response.status === 503) {
        const deadline = responseFailure(response, 'rate_limited').retryAt;
        if (deadline) await transaction({ connectionId: connection.id }, state => {
          const current = own(state.cleanup, item.id);
          if (current?.secretRef === item.secretRef && BigInt(deadline) > BigInt(current.notBefore ?? '0')) current.notBefore = deadline;
        });
      }
      await response.body?.cancel();
      return response.status === 200;
    } catch { return false; }
  }
  async function cleanupNow(connectionId: string): Promise<SignOutOutcome> {
    const connection = await record(connectionId), selection: AuthSelection = connection.anonymous ? { connectionId } : { account: { issuer: connection.issuer, userId: connection.userId } };
    const snapshot = await load(selection);
    for (const peer of Object.values(snapshot.connections)) await cleanupSigning(peer);
    const items = Object.values(snapshot.cleanup).filter(item => item.status === 'pending');
    for (const item of items) {
      const token = await secrets.read(item.secretRef);
      const revoked = token !== null && await revoke(own(snapshot.connections, item.connectionId)!, item, token);
      if (token !== null && !revoked) continue;
      await commit({ connectionId: item.connectionId }, [], (state, drop) => {
        const current = own(state.cleanup, item.id);
        if (current?.secretRef !== item.secretRef) return;
        if (revoked) { delete state.cleanup[item.id]; drop.push(item.secretRef); } else current.status = 'uncertain';
      });
    }
    const state = await load(selection), statuses = Object.keys(state.connections).map(id => cleanupStatus(state, id));
    return { connection: publicConnection(state, own(state.connections, connectionId)!), cleanup: statuses.includes('uncertain') ? 'uncertain' : statuses.includes('pending') ? 'pending' : 'complete' };
  }

  function targetOf(connection: ConnectionRecord): ConversationTarget {
    const entry = connection.metadata.document.agent?.protocols.find(protocol => protocol.type === 'poppy');
    if (!entry) throw new AuthFailure('no_conversation', connection.id);
    return { issuer: connection.issuer, endpoint: entry.endpoint };
  }

  function outcomeOf(state: ClientAuthState, operation: OperationRecord): AuthOutcome {
    return operation.result ?? { operationId: operation.id, status: operation.status, connection: publicConnection(state, own(state.connections, operation.connectionId)!), ...(operation.phase === 'terminal' ? {} : { nextAction: 'wait' as const }) };
  }
  // The terminal result is recorded once and returned verbatim to duplicate callbacks.
  function finish(state: ClientAuthState, operation: OperationRecord, status: OperationStatus, extra: { error?: string; missingScopes?: string[]; grantedScopes?: string[] } = {}): AuthOutcome {
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
    const outcome = await transaction({ operationId }, state => {
      const operation = own(state.operations, operationId);
      if (!operation || operation.epoch !== state.epoch) throw new AuthFailure('state_changed');
      if (unusedGrantRef !== null) retire(state, `cln_${operationId}`, own(state.connections, operation.connectionId)!, unusedGrantRef);
      return operation.phase === 'dispatched' ? finish(state, operation, operation.cancelRequested && status !== 'uncertain' ? 'cancelled' : status, extra) : outcomeOf(state, operation);
    });
    // Terminal operations never read their verifier again.
    await secrets.remove(verifierRef);
    return outcome;
  }

  function privateRefs(operation: OperationRecord): string[] {
    return [...(operation.direct ? [operation.direct.verifierRef] : []), ...(operation.device ? [operation.device.codeRef] : [])];
  }
  async function terminate(operationId: string, status: OperationStatus, error?: string): Promise<AuthOutcome> {
    return commit({ operationId }, [], (state, drop) => {
      const operation = own(state.operations, operationId)!;
      if (operation.phase === 'terminal') return outcomeOf(state, operation);
      drop.push(...privateRefs(operation));
      return finish(state, operation, operation.cancelRequested && status !== 'uncertain' ? 'cancelled' : status, error ? { error } : {});
    });
  }
  function activateSignIn(state: ClientAuthState, operation: OperationRecord, drop: string[]): AuthOutcome {
    const staged = operation.staged!, target = own(state.connections, operation.connectionId)!;
    const granted = staged.scopes, missingScopes = operation.scopes.filter(scope => !granted.includes(scope));
    const previous = target.grantId === null ? undefined : own(state.grants, target.grantId);
    const problem = operation.cancelRequested ? 'cancelled' : target.generation !== operation.connectionGeneration || target.sessionId !== operation.signInSessionId ? 'state_changed'
      : previous && !(operation.requiredExistingScopes ?? previous.scopes).every(scope => granted.includes(scope)) ? 'replacement_rejected' : null;
    drop.push(...privateRefs(operation));
    if (problem) {
      retire(state, `cln_${operation.id}`, target, staged.refreshRef!); drop.push(staged.accessRef);
      return finish(state, operation, problem === 'cancelled' ? 'cancelled' : 'failed', { error: problem, grantedScopes: [...granted], missingScopes });
    }
    if (previous && !Object.values(state.connections).some(row => row.id !== target.id && row.grantId === previous.id)) { retire(state, `cln_${previous.id}`, target, previous.secretRef); delete state.grants[previous.id]; }
    const grantId = randomId('grt_');
    state.grants[grantId] = { id: grantId, issuer: target.issuer, userId: target.userId, secretRef: staged.refreshRef!, scopes: granted,
      expiresAt: staged.refreshExpiresAt, generation: 1, status: 'active', operationId: null };
    switchSession(target, staged.sessionId, drop);
    target.grantId = grantId; target.status = 'signed_in'; target.generation++;
    drop.push(...Object.values(target.slots).map(slot => slot.secretRef));
    target.slots = { [slotKey(staged.sessionId, operation.resource)]: { secretRef: staged.accessRef, tokenType: staged.tokenType ?? 'DPoP', dpopKeyRef: target.dpopKeyRef,
      scopes: granted, expiresAt: staged.expiresAt, generation: target.generation } };
    return finish(state, operation, 'completed', { grantedScopes: [...granted], missingScopes });
  }
  async function acceptSignIn(operationId: string, token: TokenResponse, issuedAt: number): Promise<AuthOutcome> {
    const snapshot = await load({ operationId }), operation = own(snapshot.operations, operationId)!;
    const granted = (token.scope ?? operation.scopes.join(' ')).split(' ').filter(Boolean);
    let refreshRef: string | null = null;
    try { if (token.refresh_token !== undefined) refreshRef = await secrets.stage(token.refresh_token); }
    catch { return await terminate(operationId, 'uncertain', 'storage_error'); }
    if (!refreshRef ||
      !granted.length || new Set(granted).size !== granted.length || granted.some(scope => !operation.scopes.includes(scope))) {
      return commit({ operationId }, [], (state, drop) => {
        const current = own(state.operations, operationId)!;
        if (refreshRef) retire(state, `cln_${operationId}`, own(state.connections, current.connectionId)!, refreshRef);
        drop.push(...privateRefs(current)); return current.phase === 'terminal' ? outcomeOf(state, current) : finish(state, current, 'failed', { error: 'invalid_response' });
      });
    }
    const accessRef = await stageSessionToken(token.access_token);
    const staged: StagedRefresh = { accessRef, refreshRef, tokenType: token.token_type, sessionId: randomId('ses_'), scopes: granted, signedIn: true,
      expiresAt: issuedAt + (token.expires_in ?? 60) * 1000, refreshExpiresAt: token.refresh_token_expires_in === undefined ? null : issuedAt + token.refresh_token_expires_in * 1000 };
    // Stage before activation: recovery can finish locally without exchanging a consumed credential again.
    const recorded = await transaction({ operationId }, state => {
      const current = own(state.operations, operationId)!;
      if (current.phase !== 'dispatched') { retire(state, `cln_${operationId}`, own(state.connections, current.connectionId)!, refreshRef!); return false; }
      current.phase = 'staged'; current.staged = staged; return true;
    });
    if (!recorded) { await secrets.remove(accessRef); return (await api.operation(operationId))!; }
    return commit({ operationId }, [], (state, drop) => {
      const current = own(state.operations, operationId)!;
      return current.phase === 'staged' ? activateSignIn(state, current, drop) : outcomeOf(state, current);
    });
  }

  async function claimSignIn(operationId: string, executionOwner: OperationOwner, preSend = false): Promise<{ operation: OperationRecord; connection: ConnectionRecord } | AuthOutcome> {
    const snapshot = await load({ operationId }), operation = own(snapshot.operations, operationId)!;
    if (operation.phase === 'prepared' && !operation.signInSessionKey) return terminate(operationId, 'failed', 'restart_required');
    await currentConnection(operation.connectionId);
    return await transaction({ operationId }, state => {
      const current = own(state.operations, operationId)!;
      if (current.phase !== 'prepared') return outcomeOf(state, current);
      if (current.cancelRequested) return finish(state, current, 'cancelled');
      if (current.owner && (options.ownerAlive ?? localOwnerAlive)(current.owner)) return outcomeOf(state, current);
      const connection = own(state.connections, current.connectionId)!;
      if (current.expiresAt <= now()) return finish(state, current, 'expired');
      if (current.connectionGeneration !== connection.generation || current.signInSessionId !== connection.sessionId) return finish(state, current, 'failed', { error: 'state_changed' });
      checkCooldown(connection);
      if (!preSend) current.phase = 'dispatched'; current.owner = executionOwner;
      return { operation: current, connection };
    });
  }
  async function remoteFailure(operationId: string, error: unknown): Promise<AuthOutcome> {
    const operation = own((await load({ operationId })).operations, operationId)!;
    if (error instanceof AuthFailure) await holdOff(operation.connectionId, error);
    const code = error instanceof AuthFailure ? error.code : 'local_error';
    return await terminate(operationId, AMBIGUOUS.has(code) ? 'uncertain' : 'failed', AMBIGUOUS.has(code) ? 'lost_response' : code);
  }
  async function beginDevice(operationId: string): Promise<SignInStart> {
    const executionOwner = acquireOwner();
    try {
      const claim = await claimSignIn(operationId, executionOwner);
      if (!('operation' in claim)) return { outcome: claim };
      const { operation, connection } = claim, metadata = connection.metadata;
      const endpoint = metadata.authorization!.device_authorization_endpoint!, key = await loadDpopKey(connection.dpopKeyRef);
      const body = new URLSearchParams({ scope: operation.scopes.join(' '), client_id: clientId, client_assertion_type: CLIENT_ASSERTION,
        client_assertion: await assertion('client-authentication', connection.issuer, key, clientId, operationId) });
      let response: Response, value: Record<string, unknown>;
      try { response = await transport.fetch(new Request(endpoint, { method: 'POST', body, headers: { accept: 'application/json' } })); }
      catch { throw new AuthFailure('transport_error'); }
      if (response.status !== 200) { await response.body?.cancel(); throw responseFailure(response, response.status === 429 ? 'rate_limited' : 'token_error'); }
      try { value = parseJson(await response.text()) as Record<string, unknown>; } catch { throw new AuthFailure('invalid_response'); }
      const { device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval = 5 } = value ?? {};
      const hosts = [new URL(connection.issuer).hostname, ...metadata.authorization!.protected_resources.map(resource => new URL(resource).hostname)];
      if (typeof device_code !== 'string' || !device_code || typeof user_code !== 'string' || !user_code || typeof verification_uri !== 'string' || !allowedHost(verification_uri, hosts) ||
        (verification_uri_complete !== undefined && (typeof verification_uri_complete !== 'string' || !allowedHost(verification_uri_complete, hosts))) ||
        typeof expires_in !== 'number' || !Number.isSafeInteger(expires_in) || expires_in <= 0 || expires_in > 86400 || typeof interval !== 'number' || !Number.isSafeInteger(interval) || interval < 1 || interval > 86400) throw new AuthFailure('invalid_response');
      const codeRef = await secrets.stage(device_code), nextPollAt = now() + interval * 1000;
      const outcome = await commit({ operationId }, [codeRef], (state, drop) => {
        const current = own(state.operations, operationId)!;
        if (current.cancelRequested) { drop.push(codeRef); return finish(state, current, 'cancelled'); }
        if (current.phase !== 'dispatched' || own(state.connections, current.connectionId)!.generation !== current.connectionGeneration) { drop.push(codeRef); return finish(state, current, 'failed', { error: 'state_changed' }); }
        current.phase = 'prepared'; delete current.owner; current.expiresAt = Math.min(current.expiresAt, now() + expires_in * 1000);
        current.device = { codeRef, intervalMs: interval * 1000, nextPollAt }; return outcomeOf(state, current);
      });
      if (outcome.status !== 'pending') return { outcome };
      return { outcome, device: { verificationUri: verification_uri, ...(verification_uri_complete === undefined ? {} : { verificationUriComplete: verification_uri_complete }),
        userCode: user_code, organization: { ...metadata.document.organization }, nextPollAt } };
    } catch (error) { return { outcome: await remoteFailure(operationId, error) }; }
    finally { releaseOwner(executionOwner); }
  }
  async function pollDevice(operationId: string): Promise<AuthOutcome> {
    const snapshot = await load({ operationId }), found = own(snapshot.operations, operationId)!;
    if (!found.device) throw new AuthFailure('invalid_operation');
    if (found.expiresAt <= now()) return await terminate(operationId, 'expired');
    const wait = found.device.nextPollAt - now();
    if (wait > 0) return { ...outcomeOf(snapshot, found), retryAfterMs: wait };
    const executionOwner = acquireOwner();
    try {
      const claim = await claimSignIn(operationId, executionOwner);
      if (!('operation' in claim)) return claim;
      const { operation, connection } = claim, code = await secrets.read(operation.device!.codeRef);
      if (!code) return await terminate(operationId, 'failed', 'missing_credential');
      const issuedAt = now(), fields: Record<string, string> = { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: code };
      if (operation.resource) fields.resource = operation.resource;
      let token: TokenResponse;
      try { token = (await tokenRequest(connection.metadata, connection.dpopKeyRef, fields)).token; }
      catch (error) {
        if (error instanceof AuthFailure && ['authorization_pending', 'slow_down', 'rate_limited'].includes(error.code)) {
          await holdOff(connection.id, error);
          return await transaction({ operationId }, state => {
            const current = own(state.operations, operationId)!;
            if (current.phase !== 'dispatched') return outcomeOf(state, current);
            if (current.cancelRequested) return finish(state, current, 'cancelled');
            if (error.code === 'slow_down') current.device!.intervalMs += 5000;
            current.device!.nextPollAt = now() + Math.max(current.device!.intervalMs, Number.isFinite(error.retryAfterMs) ? error.retryAfterMs ?? 0 : 0);
            current.phase = 'prepared'; delete current.owner;
            return { ...outcomeOf(state, current), retryAfterMs: current.device!.nextPollAt - now() };
          });
        }
        if (error instanceof AuthFailure && ['access_denied', 'expired_token'].includes(error.code)) return await terminate(operationId, error.code === 'access_denied' ? 'denied' : 'expired', error.code);
        return await remoteFailure(operationId, error);
      }
      return await acceptSignIn(operationId, token, issuedAt);
    } finally { releaseOwner(executionOwner); }
  }
  async function continueMediated(operationId: string): Promise<AuthOutcome> {
    const executionOwner=acquireOwner();let sensitive:Record<string,string>|null=null;
    try {
      const claim=await claimSignIn(operationId,executionOwner,true);if(!('operation' in claim))return claim;
      const {operation,connection}=claim,mediated=mediatedSignIn(connection.metadata.document);
      if(!mediated||!options.trustedInput)return terminate(operationId,'failed','trusted_input_required');
      const fields=operation.mediated?[{name:'code',label:'One-time code',secret:true}]:mediated.fields;
      try{sensitive=await options.trustedInput.collect({operationId,issuer:connection.issuer,organization:{...connection.metadata.document.organization},fields:structuredClone(fields),...(operation.mediated?{challenge:{id:operation.mediated.challengeId,sentTo:operation.mediated.sentTo,expiresAt:operation.expiresAt}}:{})});}
      catch{return terminate(operationId,'failed','input_unavailable');}
      const values=sensitive;
      if(values===null)return terminate(operationId,'cancelled');
      if(Object.keys(values).length!==fields.length||!fields.every(field=>Object.hasOwn(values,field.name)&&typeof values[field.name]==='string'&&values[field.name].length>0&&values[field.name].length<=4096))return terminate(operationId,'failed','invalid_input');
      const dispatch=await transaction({operationId},state=>{
        const current=own(state.operations,operationId)!,live=own(state.connections,current.connectionId)!;
        if(current.phase!=='prepared'||current.owner?.id!==executionOwner.id||current.cancelRequested)return false;
        if(live.generation!==current.connectionGeneration||current.expiresAt<=now()){finish(state,current,'cancelled');return false;}
        current.phase='dispatched';return true;
      });
      if(!dispatch)return (await api.operation(operationId))!;
      const params:Record<string,string>={grant_type:MEDIATED_GRANT,...(operation.mediated?{sign_in_id:operation.mediated.challengeId,one_time_code:values.code!}:{scope:operation.scopes.join(' '),...values})};
      if(operation.resource)params.resource=operation.resource;
      const issuedAt=now();
      try {
        const {token}=await tokenRequest(connection.metadata,connection.dpopKeyRef,params,operationId);
        return await acceptSignIn(operationId,token,issuedAt);
      } catch(error) {
        if(error instanceof MediatedCodeRequired){
          const challenge=error.challenge;
          if(operation.mediated&&operation.mediated.challengeId!==challenge.id)return terminate(operationId,'failed','invalid_response');
          const sentTo=Object.values(values).some(value=>challenge.sentTo.includes(value))?'The company sent a one-time code.':challenge.sentTo;
          return transaction({operationId},state=>{
            const current=own(state.operations,operationId)!;
            if(current.phase!=='dispatched')return outcomeOf(state,current);
            if(current.cancelRequested)return finish(state,current,'cancelled');
            current.phase='prepared';delete current.owner;current.expiresAt=Math.min(current.expiresAt,challenge.expiresAt);
            current.mediated={challengeId:challenge.id,sentTo};return outcomeOf(state,current);
          });
        }
        if(!(error instanceof AuthFailure))throw error;
        if(['access_denied','invalid_grant','expired_token','cancelled'].includes(error.code))return terminate(operationId,error.code==='expired_token'?'expired':error.code==='cancelled'?'cancelled':'denied',error.code);
        return remoteFailure(operationId,error);
      } finally {for(const name of Object.keys(params))delete params[name];}
    } catch(error){
      if(own((await load({operationId})).operations,operationId)?.phase==='staged')throw error;
      return remoteFailure(operationId,error);
    }
    finally {if(sensitive)for(const name of Object.keys(sensitive))delete sensitive[name];releaseOwner(executionOwner);}
  }

  async function sendAuthorized(connectionId: string, request: Request, target: ConversationTarget, requiredScopes: readonly string[], scheme: 'DPoP' | 'Bearer' = 'DPoP', retryRejected = true, service?: 'mcp' | 'openapi' | 'conversation'): Promise<Response> {
    const url = new URL(request.url), endpoint = new URL(target.endpoint), base = endpoint.pathname.replace(/\/$/, '');
    if (!safeHttps(request.url) || url.origin !== endpoint.origin || (url.pathname !== endpoint.pathname && !url.pathname.startsWith(`${base}/`))) throw new AuthFailure('invalid_target', connectionId);
    let resource = target.resource ?? null;
    const wait = url.searchParams.get('wait');
    const waitMs = wait !== null && /^\d+$/.test(wait) ? Math.min(Number(wait), MAX_WAIT_SECONDS) * 1000 : 0;
    let restarted = false, nonceRetried = false, renewed = false, discovered = false;
    for (;;) {
      const connection = await record(connectionId);
      if (connection.status === 'disconnected') throw new AuthFailure('disconnected', connectionId);
      if (connection.status === 'uncertain') throw new AuthFailure('grant_uncertain', connectionId);
      checkCooldown(connection);
      let credential: CredentialRecord | undefined, token: string | undefined;
      if (connection.status === 'signed_in') {
        if (service && !discovered) {
          try { resource = (await serviceAuthorization(connection.metadata, options.metadata, transport, target.endpoint, { mcp: service === 'mcp' })).resource ?? null; }
          catch { throw new AuthFailure('invalid_target', connectionId); }
          discovered = true;
        }
        try { credential = await credentialFor(connectionId, resource, null); }
        catch (error) { if ((await record(connectionId)).status === 'signed_out') continue; throw error; }
        const value = await secrets.read(credential.secretRef);
        if (value === null) {
          if (renewed) throw new AuthFailure('missing_credential', connectionId);
          renewed = true; await credentialFor(connectionId, resource, credential.secretRef); continue;
        }
        token = value;
      }
      if (!requiredScopes.every(scope => credential?.scopes.includes(scope))) {
        const requirement = await api.authorization(connectionId, requiredScopes);
        if (!renewed && requirement.sufficient) { renewed = true; await renewShared(connectionId, resource); continue; }
        throw new AuthFailure('insufficient_scope', connectionId);
      }
      const headers = new Headers(request.headers);
      for (const name of ['cookie', 'authorization', 'dpop', 'poppy-session']) headers.delete(name);
      if (token !== undefined) {
        headers.set('authorization', `${credential!.tokenType} ${token}`);
        if (credential!.tokenType === 'DPoP') headers.set('dpop', await proof(await loadDpopKey(credential!.dpopKeyRef), request.method, request.url, token));
      }
      headers.set('poppy-session', await sessionHeader(connection, request, token));
      if ((await record(connectionId)).generation !== connection.generation) continue;
      const authorized = new Request(request.clone(), { headers, credentials: 'omit', redirect: 'error' });
      const streaming = request.headers.get('accept')?.split(',').some(value => value.trim().split(';')[0] === 'text/event-stream');
      const response = await (streaming && transport.stream ? transport.stream(authorized) : transport.fetch(authorized, { waitMs }));
      rememberNonce(request.url, response);
      if (response.status === 429 || response.status === 503) await holdOff(connectionId, responseFailure(response, 'rate_limited'));
      if (response.status === 400) {
        let invalid = false; try { invalid = parseProtocolError(parseJson(await response.clone().text())).error === 'invalid_session'; } catch { /* Not a Session refusal. */ }
        if (invalid && !restarted) {
          await response.body?.cancel().catch(() => {}); restarted = true;
          await transaction({ connectionId }, state => {
            const live = own(state.connections, connectionId)!;
            if (live.generation !== connection.generation) return;
            live.sessionId = randomId('ses_'); live.generation++;
            live.slots = Object.fromEntries(Object.entries(live.slots).map(([key, slot]) => [slotKey(live.sessionId, JSON.parse(key)[1]), slot]));
          });
          if (!retryRejected) return response;
          continue;
        }
      }
      if (response.status !== 401 || !retryRejected) return response;
      const challenge = schemeChallenge(response.headers.get('www-authenticate'), credential?.tokenType ?? scheme), error = challenge?.error;
      if (error === 'use_dpop_nonce' && !nonceRetried && response.headers.has('dpop-nonce')) { await response.body?.cancel().catch(() => {}); nonceRetried = true; continue; }
      if (error === 'invalid_token' && credential && !renewed) {
        await response.body?.cancel().catch(() => {}); renewed = true;
        if (service && challenge?.resource_metadata) {
          try { resource = (await serviceAuthorization(connection.metadata, options.metadata, transport, target.endpoint, { mcp: service === 'mcp', metadataUrl: challenge.resource_metadata, refresh: true })).resource ?? null; }
          catch { throw new AuthFailure('invalid_target', connectionId); }
        }
        await credentialFor(connectionId, resource, credential.secretRef); continue;
      }
      return response;
    }
  }

  const api: ClientAuth = {
    async start(domain, input) {
      let metadata: CompanyMetadata;
      try { metadata = await options.metadata.resolveCompany(domain); } catch { throw new AuthFailure('discovery_failed'); }
      const issuer = companyIdentifier(metadata);
      const anonymous = input?.anonymous === true;
      if (input?.accountFrom !== undefined && (anonymous || typeof input.accountFrom !== 'string')) throw new AuthFailure('invalid_account_source');
      const { userId } = await identityFor(issuer, anonymous);
      const epoch = (await load({ issuer })).epoch;
      const dpopKeyRef = await newSessionKey();
      const createdAt = now();
      const id = randomId('con_'), operationId = randomId('op_'), sessionId = randomId('ses_');
      return commit(input?.accountFrom ? { account: { issuer, userId }, history: true } : { issuer, history: true }, [dpopKeyRef], state => {
        // A reset or competing identity since we signed means this session belongs to no current identity.
        if (state.epoch !== epoch || (!anonymous && own(state.identities, issuer)?.userId !== userId)) throw new AuthFailure('state_changed');
        const connection: ConnectionRecord = {
          id, domain, issuer, metadata, userId, dpopKeyRef, sessionId, generation: 1, status: 'signed_out', grantId: null,
          slots: {},
          ...(anonymous ? { anonymous: true } : {}),
        };
        if (input?.accountFrom) {
          const source = own(state.connections, input.accountFrom), grant = source?.grantId ? own(state.grants, source.grantId) : undefined;
          if (!source || source.anonymous || source.issuer !== issuer || source.userId !== userId || source.status !== 'signed_in' || !grant || grant.status !== 'active' || (grant.expiresAt !== null && grant.expiresAt <= now())) throw new AuthFailure('state_changed');
          connection.grantId = grant.id; connection.status = 'signed_in';
        }
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
      const state = await load({ connectionId });
      const found = typeof connectionId === 'string' ? own(state.connections, connectionId) : undefined;
      return found ? publicConnection(state, found) : null;
    },
    async list() {
      const state = await load({ list: true });
      return Object.values(state.connections).map(connection => publicConnection(state, connection));
    },
    async target(connectionId) { return targetOf(await currentConnection(connectionId)); },

    // Direct Sign-In (spec 4.5): the operation binds everything the callback must match before the URL exists.
    async authorization(connectionId, requiredScopes) {
      if (!Array.isArray(requiredScopes) || !requiredScopes.every(scope => typeof scope === 'string' && /^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope))) throw new AuthFailure('invalid_scope', connectionId);
      const connection = await currentConnection(connectionId), state = await load({ connectionId });
      const grantedScopes = publicConnection(state, connection).scopes;
      const grant = connection.grantId ? own(state.grants, connection.grantId) : undefined;
      const methods = signInMethods(connection.metadata);
      const required = [...new Set(requiredScopes)], missingScopes = required.filter(scope => !grantedScopes.includes(scope));
      return { requiredScopes: required, grantedScopes, missingScopes, sufficient: connection.status === 'signed_in' && grant?.status === 'active' && (grant.expiresAt === null || grant.expiresAt > now()) && !missingScopes.length,
        methods, scopeDescriptions: { ...connection.metadata.document.auth?.scopes }, organization: { ...connection.metadata.document.organization } };
    },
    async beginSignIn(connectionId, input) {
      let found = await currentConnection(connectionId);
      if (found.anonymous) {
        await api.signOut(connectionId);
        const regular = await api.start(found.domain); connectionId = regular.connection.id;
        found = await currentConnection(connectionId);
      }
      const method = input?.method ?? 'direct';
      if (!['direct', 'device', 'mediated'].includes(method)) throw new AuthFailure('unsupported_method', connectionId);
      const supported = signInMethods(found.metadata).find(item => item.method === method);
      const authorizationEndpoint = found.metadata.authorization?.authorization_endpoint;
      if (!supported || (method === 'direct' && !authorizationEndpoint) || (method === 'device' && !found.metadata.authorization?.device_authorization_endpoint)) throw new AuthFailure(`${method}_unavailable`, connectionId);
      const { scopes, redirectUri, browserBinding, requiredExistingScopes } = input ?? {};
      if (!Array.isArray(scopes) || !scopes.length || new Set(scopes).size !== scopes.length || !scopes.every(scope => typeof scope === 'string' && (/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope) && (method !== 'mediated' || supported.scopes.includes(scope))))) throw new AuthFailure('invalid_scope', connectionId);
      const requirement = await api.authorization(connectionId, scopes);
      if (requiredExistingScopes !== undefined && (!Array.isArray(requiredExistingScopes) || !requiredExistingScopes.every(scope => requirement.grantedScopes.includes(scope)))) throw new AuthFailure('invalid_scope', connectionId);
      if (requirement.sufficient && !input.force) return { outcome: { operationId: '', status: 'completed', connection: publicConnection(await load({ connectionId }), found), grantedScopes: requirement.grantedScopes, missingScopes: [] } };
      checkCooldown(found);
      if (method === 'mediated' && !options.trustedInput) throw new AuthFailure('trusted_input_required', connectionId);
      if (method === 'direct' && (typeof redirectUri !== 'string' || !registeredRedirect(redirectUri, options.redirectUris, clientId) || CALLBACK_PARAMS.some(name => new URL(redirectUri).searchParams.has(name)))) throw new AuthFailure('invalid_redirect', connectionId);
      // The host derives this from its authenticated browser session; a short value would be guessable.
      if (method === 'direct' && (typeof browserBinding !== 'string' || browserBinding.length < 22)) throw new AuthFailure('invalid_binding', connectionId);
      // Service metadata, rather than an obsolete discovery field, selects narrower tokens.
      const conversation = found.metadata.document.agent?.protocols.find(protocol => protocol.type === 'poppy');
      const resource = conversation ? (await serviceAuthorization(found.metadata, options.metadata, transport, conversation.endpoint)).resource ?? null : null;
      const connection = await record(connectionId);
      // An uncertain grant recovers only through a fresh sign-in; a disconnected connection never signs in again (spec 4.9).
      if (connection.status === 'disconnected' || connection.sessionId === null) throw new AuthFailure('sign_in_unavailable', connectionId);
      const state = b64(crypto.getRandomValues(new Uint8Array(32)));
      const verifier = b64(crypto.getRandomValues(new Uint8Array(32)));
      const sessionKey = (await loadDpopKey(connection.dpopKeyRef)).thumbprint;
      const proofBound = method === 'direct' && await resourceScheme(found.metadata, resource) === 'DPoP';
      const verifierRef = method === 'direct' ? await secrets.stage(verifier) : null;
      const createdAt = now(), operationId = randomId('op_');
      const outcome = await commit({ connectionId, history: true }, [verifierRef], draft => {
        const current = own(draft.connections, connectionId);
        if (!current || current.generation !== connection.generation || current.status !== connection.status || current.sessionId !== connection.sessionId) throw new AuthFailure('state_changed', connectionId);
        pruneHistory(draft);
        const operation: OperationRecord = draft.operations[operationId] = {
          epoch: draft.epoch, id: operationId, kind: 'sign_in', connectionId, connectionGeneration: current.generation, grantId: current.grantId, grantGeneration: null,
          phase: 'prepared', status: 'pending', createdAt, expiresAt: createdAt + SIGN_IN_MS, resource, scopes: [...scopes],
          method, signInSessionId: connection.sessionId!, signInSessionKey: sessionKey, requiredExistingScopes: requiredExistingScopes ?? requirement.grantedScopes,
          direct: method === 'direct' ? { stateHash: sha256(state), verifierRef: verifierRef!, browserHash: sha256(browserBinding!), redirectUri: redirectUri!, issuer: current.issuer, clientId, sessionId: connection.sessionId! } : null,
          staged: null, result: null,
        };
        return outcomeOf(draft, operation);
      });
      if (method === 'device') return beginDevice(outcome.operationId);
      if (method === 'mediated') return { outcome: await continueMediated(outcome.operationId) };
      const url = new URL(authorizationEndpoint!);
      const query = { response_type: 'code', client_id: clientId, redirect_uri: redirectUri!, scope: scopes.join(' '), state, code_challenge: sha256(verifier), code_challenge_method: 'S256' };
      for (const [name, value] of Object.entries(query)) url.searchParams.set(name, value);
      if (proofBound) url.searchParams.set('dpop_jkt', sessionKey);
      if (resource !== null) url.searchParams.set('resource', resource);
      return { outcome, authorizationUrl: url.href };
    },

    async completeSignIn(input) {
      const executionOwner = acquireOwner();
      try {
      const { callbackUrl, browserBinding } = (input ?? {}) as { callbackUrl?: unknown; browserBinding?: unknown };
      const { params, base } = parseCallback(callbackUrl);
      if (typeof browserBinding !== 'string' || !params.state || (!params.code && !params.error) || (params.code !== undefined) === (params.error !== undefined)) throw new AuthFailure('invalid_callback');
      const stateHash = sha256(params.state), browserHash = sha256(browserBinding);
      const snapshot = await load({ callbackHash: stateHash });
      const found = Object.values(snapshot.operations).find(operation => operation.kind === 'sign_in' && operation.epoch === snapshot.epoch && operation.direct?.stateHash === stateHash);
      const direct = found?.direct;
      // A wrong browser, redirect or issuer (mix-up, spec 4.5) leaves the operation untouched so the genuine callback still completes.
      if (!found || !direct || direct.browserHash !== browserHash || !redirectMatches(base, new URL(direct.redirectUri)) || params.iss !== direct.issuer) throw new AuthFailure('invalid_callback');
      checkCooldown(await record(found.connectionId));
      if (found.phase === 'prepared' && !found.signInSessionKey) return terminate(found.id, 'failed', 'restart_required');
      const operationId = found.id;
      const verifier = found.phase === 'prepared' && params.code !== undefined ? await secrets.read(direct.verifierRef) : null;
      const at = now();
      // Only one claimant moves prepared -> dispatched; everyone else gets the recorded progress or result.
      const claim = await transaction({ operationId }, state => {
        const operation = own(state.operations, operationId);
        if (!operation || operation.epoch !== state.epoch) throw new AuthFailure('invalid_callback');
        if (operation.phase !== 'prepared') return outcomeOf(state, operation);
        const connection = own(state.connections, operation.connectionId)!;
        if (connection.generation !== operation.connectionGeneration || connection.sessionId !== operation.signInSessionId) return finish(state, operation, 'failed', { error: 'state_changed' });
        if (at >= operation.expiresAt) return finish(state, operation, 'expired');
        if (params.error !== undefined) return params.error === 'access_denied' ? finish(state, operation, 'denied', { error: 'access_denied' }) : finish(state, operation, 'failed', { error: AUTHORIZE_ERRORS.has(params.error) ? params.error : 'authorization_error' });
        if (verifier === null) return finish(state, operation, 'failed', { error: 'missing_key' });
        operation.phase = 'dispatched'; operation.owner = executionOwner;
        return { connection, operation };
      });
      if (!('operation' in claim)) {
        if (claim.status !== 'pending') await secrets.remove(direct.verifierRef);
        return claim;
      }
      const { connection, operation } = claim;
      const fields: Record<string, string> = { grant_type: 'authorization_code', code: params.code!, redirect_uri: direct.redirectUri, code_verifier: verifier! };
      if (operation.resource !== null) fields.resource = operation.resource;
      const issuedAt = now();
      let token: TokenResponse;
      try { token = (await tokenRequest(connection.metadata, connection.dpopKeyRef, fields)).token; } catch (error) {
        if (error instanceof AuthFailure) await holdOff(connection.id, error);
        // A definite rejection is a failure; a lost or non-OAuth answer may have consumed the code, so it is never resent.
        const definite = error instanceof AuthFailure && !AMBIGUOUS.has(error.code);
        return settle(operationId, direct.verifierRef, definite ? 'failed' : 'uncertain', { error: definite ? error.code : 'lost_response' });
      }
      return await acceptSignIn(operationId, token, issuedAt);
      } finally { releaseOwner(executionOwner); }
    },

    async continueSignIn(operationId) {
      const state = await load({ operationId }), operation = own(state.operations, operationId);
      if (!operation || operation.kind !== 'sign_in') throw new AuthFailure('unknown_operation');
      if (operation.phase === 'terminal' || operation.phase !== 'prepared') return outcomeOf(state, operation);
      return operation.method === 'device' ? pollDevice(operationId) : operation.method === 'mediated' ? continueMediated(operationId) : outcomeOf(state, operation);
    },

    async cancelSignIn(operationId) {
      return commit({ operationId }, [], (state, drop) => {
        const operation = typeof operationId === 'string' ? own(state.operations, operationId) : undefined;
        if (!operation || operation.kind !== 'sign_in' || operation.epoch !== state.epoch) throw new AuthFailure('unknown_operation');
        if (operation.phase === 'terminal') return outcomeOf(state, operation);
        operation.cancelRequested = true; drop.push(...privateRefs(operation));
        if (operation.phase === 'staged') { retire(state, `cln_${operationId}`, own(state.connections, operation.connectionId)!, operation.staged!.refreshRef!); drop.push(operation.staged!.accessRef); }
        if (operation.phase !== 'dispatched') return finish(state, operation, 'cancelled');
        // Keep dispatched work recoverable: cancellation cannot prove whether the issuer acted.
        return operation.result = { operationId, status: 'cancelled', connection: publicConnection(state, own(state.connections, operation.connectionId)!) };
      });
    },

    async operation(operationId) {
      const state = await load({ operationId });
      const found = typeof operationId === 'string' ? own(state.operations, operationId) : undefined;
      return found && found.epoch === state.epoch ? outcomeOf(state, found) : null;
    },

    // Host calls this at startup; it never repeats a remote exchange.
    async recover() {
      const at = now();
      const results: AuthOutcome[] = [];
      let after: string | undefined;
      for (;;) {
        const ids = await store.pendingOperations(after, 100);
        if (!ids.length) return results;
        for (const operationId of ids) {
          const recovered = await commit({ operationId }, [], (state, drop): AuthOutcome | undefined => {
          const operation = own(state.operations, operationId);
          if (!operation || operation.epoch !== state.epoch || operation.phase === 'terminal') return;
          if (operation.owner && (options.ownerAlive ?? localOwnerAlive)(operation.owner)) return;
          let result: AuthOutcome;
          // A fully staged refresh finishes locally; its fences still decide whether it activates.
          if (operation.kind === 'renew') {
            if (operation.phase === 'staged') result = activateRefresh(state, operation, drop);
            else result = operation.phase === 'prepared' ? closeRefresh(state, operation, 'failed', 'interrupted', false, drop) : closeRefresh(state, operation, 'uncertain', 'lost_response', false, drop);
          }
          // The code may have reached the issuer before the crash; only a fresh sign-in is safe.
          else if (operation.phase === 'staged') result = activateSignIn(state, operation, drop);
          else if (operation.phase !== 'prepared') result = finish(state, operation, 'uncertain', { error: 'lost_response' });
          else if (operation.kind === 'sign_in' && !operation.signInSessionKey) result = finish(state, operation, 'failed', { error: 'restart_required' });
          else if (at >= operation.expiresAt) result = finish(state, operation, 'expired');
          else return;
          // Terminal operations never read their verifier again.
          drop.push(...privateRefs(operation));
          return result;
          });
          if (recovered) results.push(recovered);
        }
        after = ids.at(-1);
      }
    },

    async renew(connectionId, input) {
      const { resource = null, scopes } = (input ?? {}) as { resource?: unknown; scopes?: unknown };
      if (resource !== null && (typeof resource !== 'string' || !URL.canParse(resource))) throw new AuthFailure('invalid_target', connectionId);
      if (scopes !== undefined && (!Array.isArray(scopes) || !scopes.length || new Set(scopes).size !== scopes.length || !scopes.every(scope => typeof scope === 'string'))) throw new AuthFailure('invalid_scope', connectionId);
      return renewal(await currentConnection(connectionId), resource, scopes ?? null);
    },

    // Opaque grants have no standard account identifier; revoke all grants for this local User and Company.
    async signOut(connectionId) {
      const selected = await record(connectionId), selection: AuthSelection = selected.anonymous ? { connectionId } : { account: { issuer: selected.issuer, userId: selected.userId } };
      await commit(selection, [], (state, drop) => {
        for (const connection of Object.values(state.connections)) {
          if (connection.status === 'disconnected') continue;
          connection.generation++; connection.status = connection.anonymous ? 'disconnected' : 'signed_out';
          drop.push(...Object.values(connection.slots).map(slot => slot.secretRef)); connection.slots = {};
          if (connection.anonymous) {
            if (connection.sessionSigning) (connection.signingCleanup ??= []).push(connection.sessionSigning.keyRef, connection.sessionSigning.delegationRef);
            delete connection.sessionSigning; (connection.signingCleanup ??= []).push(connection.dpopKeyRef); connection.userId = ''; connection.sessionId = null;
          }
          const grant = connection.grantId === null ? undefined : own(state.grants, connection.grantId);
          if (grant) { retire(state, `cln_${grant.id}`, connection, grant.secretRef); delete state.grants[grant.id]; }
          connection.grantId = null;
          for (const operation of Object.values(state.operations)) {
            if (operation.connectionId !== connection.id || operation.epoch !== state.epoch || operation.phase !== 'prepared') continue;
            finish(state, operation, 'cancelled'); drop.push(...privateRefs(operation));
          }
        }
      });
      return cleanupNow(connectionId);
    },
    retryCleanup: cleanupNow,

    async apiTarget(connectionId, apiUrl, destination) {
      const connection = await currentConnection(connectionId);
      try { return await resolveApiTarget(connection.metadata, options.metadata, transport, apiUrl, destination); } catch { throw new AuthFailure('invalid_target', connectionId); }
    },
    async apiFetch(connectionId, request, target, requiredScopes = []) {
      const expected = await api.apiTarget(connectionId, target.apiUrl, target.endpoint);
      if (expected.kind !== target.kind || expected.issuer !== target.issuer || expected.endpoint !== target.endpoint || expected.resource !== target.resource || expected.scheme !== target.scheme) throw new AuthFailure('invalid_target', connectionId);
      if (expected.kind === 'mcp' && request.url !== expected.endpoint) throw new AuthFailure('invalid_target', connectionId);
      return sendAuthorized(connectionId, request, expected, requiredScopes, expected.scheme, true, expected.kind);
    },
    async joinBrowser(connectionId, returnTo, controller) {
      const connection = await currentConnection(connectionId), endpoint = connection.metadata.document.web?.browser_session_endpoint;
      if (!endpoint || !connection.sessionId || connection.status === 'disconnected' || connection.status === 'uncertain' || controller?.kind !== 'agent-controlled' || typeof controller.loadJoinForm !== 'function' || typeof controller.postForm !== 'function' || typeof controller.navigate !== 'function') throw new AuthFailure('invalid_browser', connectionId);
      try { browserDestination(returnTo, connection.metadata.document.organization.domain); } catch { throw new AuthFailure('invalid_target', connectionId); }
      try {
        const { code } = await controller.loadJoinForm(endpoint);
        if (typeof code !== 'string' || !code || code.length > 256) throw new Error('code');
        const live = await currentConnection(connectionId);
        if (live.generation !== connection.generation || live.dpopKeyRef !== connection.dpopKeyRef || live.status !== connection.status) throw new Error('state changed');
        const authorize=new URL(endpoint);authorize.pathname=authorize.pathname.replace(/\/$/,'')+'/authorize';
        const response=await sendAuthorized(connectionId,new Request(authorize,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({code})}),{issuer:connection.issuer,endpoint},[]);
        if(response.status!==204)throw new AuthFailure('browser_authorization_failed',connectionId);
        await response.body?.cancel();
        await controller.postForm({ url: endpoint, fields: { code }, validateRedirect(status, location) {
          if (status !== 303) throw new AuthFailure('invalid_browser_redirect', connectionId);
          const destination = new URL(location, endpoint).href;
          browserDestination(destination, connection.metadata.document.organization.domain);
          return destination;
        } });
        await controller.navigate(returnTo);
      } catch { throw new AuthFailure('browser_failed', connectionId); }
    },
    async feedback(connectionId, report) {
      validateFeedback(report);
      const connection = await currentConnection(connectionId), endpoint = connection.metadata.document.feedback?.endpoint;
      if (!endpoint) throw new AuthFailure('feedback_unavailable', connectionId);
      const response = await sendAuthorized(connectionId, new Request(endpoint, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(report) }), { issuer: connection.issuer, endpoint }, [], 'DPoP', false);
      try {
        const text = await response.text();
        if (response.status === 202 && text === '') return;
        if (response.status === 200) return parseAlternative(parseJson(text), connection.metadata.document);
      } catch { /* Do not expose company response/parser details. */ }
      throw new AuthFailure('feedback_failed', connectionId);
    },
    async excludedTasks(connectionId) {
      const connection = await currentConnection(connectionId);
      if (!connection.metadata.document.excluded_tasks) return [];
      if (!options.metadata.resolveExcludedTasks) throw new AuthFailure('excluded_tasks_unavailable', connectionId);
      return options.metadata.resolveExcludedTasks(connection.metadata.document);
    },
    async authorizedFetch(connectionId, request, target, requiredScopes = []) {
      const connection = await currentConnection(connectionId), expected = targetOf(connection);
      if (target.issuer !== expected.issuer || target.endpoint !== expected.endpoint || target.resource !== expected.resource) throw new AuthFailure('invalid_target', connectionId);
      return sendAuthorized(connectionId, request, expected, requiredScopes, 'DPoP', true, 'conversation');
    },
  };
  return api;
}
