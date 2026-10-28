/** Optional PoppyKit provider v1. Hosting, human authentication and key custody belong to the operator. */
import { createHash, randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import type { AssertionProvider, ProviderIdentity, IdentitySigner } from './auth/client-auth.js';
import type { MetadataResolver, CompanyMetadata } from './network/discovery.js';
import type { HttpTransport } from './network/transport.js';
import { secureUrl } from './network/transport.js';

type Row = Record<string, any>;
export interface ProviderTransaction {
  get(kind: string, id: string): Row | undefined;
  put(kind: string, id: string, value: Row): void;
  remove(kind: string, id: string): void;
  list(kind: string, prefix: string, limit: number): { id: string; value: Row }[];
}
export type ProviderSelection =
  | { kind: 'enroll'; subjectHash: string; requestHash: string }
  | { kind: 'identity'; enrollmentId: string; issuer: string }
  | { kind: 'operation'; enrollmentId: string; operationId: string }
  | { kind: 'begin'; enrollmentId: string; operationId: string; issuer: string; stateHash?: string; at: number }
  | { kind: 'callback'; stateHash: string }
  | { kind: 'revoke'; enrollmentId: string };
/** Atomic asynchronous I/O around a pure synchronous, selection-bounded callback. */
export interface ProviderStore { transaction<T>(selection: ProviderSelection, action: (tx: ProviderTransaction) => T): Promise<T> }
/** Explicit migration aid for existing local synchronous stores; unsuitable for remote I/O. */
export function adaptLegacyProviderStore(store: { transaction<T>(action: (tx: ProviderTransaction) => T): T }): ProviderStore {
  return { async transaction(_selection, action) { return store.transaction(tx => {
    const result = action(tx);
    if (result && typeof (result as { then?: unknown }).then === 'function') throw new TypeError('provider transaction must be synchronous');
    return structuredClone(result);
  }); } };
}
export interface ResultCipher { seal(value: string): string; open(value: string): string }
export function createResultCipher(key: Uint8Array): ResultCipher {
  if (key.length !== 32) throw new Error('provider encryption key must be 32 bytes');
  const secret = Buffer.from(key);
  return {
    seal(value) { const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', secret, iv); return Buffer.concat([iv, cipher.update(value, 'utf8'), cipher.final(), cipher.getAuthTag()]).toString('base64url'); },
    open(value) { const bytes = Buffer.from(value, 'base64url'), cipher = createDecipheriv('aes-256-gcm', secret, bytes.subarray(0, 12)); cipher.setAuthTag(bytes.subarray(-16)); return Buffer.concat([cipher.update(bytes.subarray(12, -16)), cipher.final()]).toString('utf8'); },
  };
}
export type ProviderErrorCode = 'unauthorized' | 'binding_conflict' | 'expired' | 'consumed' | 'canceled' | 'rate_limited' | 'unavailable' | 'invalid_response';
export class ProviderError extends Error {
  constructor(readonly code: ProviderErrorCode, readonly retryAt?: number) { super(`Provider ${code}`); }
}
export interface ProviderOptions {
  clientId: string; callbackUrl: string; jwksUri: string; clientName: string;
  store: ProviderStore; cipher: ResultCipher; metadata: MetadataResolver;
  signer: IdentitySigner;
  /** Publish new keys before use and retain retired public keys through assertion expiry + skew. */
  publishedKeys?: () => Promise<Record<string, any>[]>;
  /** Validate operator login and CSRF; caller IDs and public setup URLs are never authentication. */
  authenticateEnrollment(request: Request): Promise<{ subject: string; allowedCompanies: string[] } | null>;
  /** Required for browser assertions: independently prove session belongs to this client AND derived user. */
  verifySession?(binding: { clientId: string; userId: string; issuer: string; sessionId: string }): Promise<boolean>;
  now?: () => number; maxEnrollments?: number;
}
const id = () => randomBytes(32).toString('base64url');
const hash = (value: string) => createHash('sha256').update(value).digest('base64url');
function fail(code: ProviderErrorCode): never { throw new ProviderError(code); }
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const text = (value: unknown): string => typeof value === 'string' && value.length > 0 && value.length <= 2048 ? value : fail('binding_conflict');
function exact(value: Row, keys: string[]): void { if (value.version !== 1 || Object.keys(value).some(key => !keys.includes(key))) fail('binding_conflict'); }
function object(value: unknown): Row { if (!value || typeof value !== 'object' || Array.isArray(value)) fail('binding_conflict'); return value as Row; }
function https(value: string): URL { try { return secureUrl(value); } catch { return fail('binding_conflict'); } }
function onDomain(value: string, domain: string): boolean { const host = https(value).hostname; return host === domain || host.endsWith(`.${domain}`); }
function publicKey(value: Row): Row {
  if(value.kty!=='EC'||value.crv!=='P-256'||typeof value.x!=='string'||typeof value.y!=='string'||'d'in value||'k'in value)fail('unavailable');
  return {kty:value.kty,crv:value.crv,x:value.x,y:value.y,kid:text(value.kid),alg:'ES256',use:'sig'};
}

export function createProvider(options: ProviderOptions) {
  const { store, cipher } = options, now = options.now ?? Date.now;
  const client = https(options.clientId);
  if ([options.callbackUrl, options.jwksUri].some(value => https(value).hostname !== client.hostname) || https(options.callbackUrl).search) throw new Error('provider metadata endpoints must share client domain; callback cannot contain query');
  function auth(tx: ProviderTransaction, credential: string, installationId: string): Row {
    const [enrollmentId, secret, extra] = credential.split('.');
    const row = enrollmentId ? tx.get('enrollment', enrollmentId) : undefined;
    if (extra || !row || row.revoked || row.installationId !== installationId || hash(secret ?? '') !== row.verifier) fail('unauthorized');
    return { ...row, enrollmentId };
  }
  function operation(tx: ProviderTransaction, enrollment: Row, operationId: string, allowConsumed = false): Row {
    const row = tx.get('operation', `${enrollment.enrollmentId}:${operationId}`);
    if (!row) fail('binding_conflict');
    if (row.binding.purpose === 'direct' && (typeof row.binding.sessionKey !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(row.binding.sessionKey))) fail('binding_conflict');
    if (row.expiresAt <= now()) fail('expired');
    if (row.status === 'canceled') fail('canceled');
    if (row.status === 'consumed' && !allowConsumed) fail('consumed');
    return row;
  }
  async function verified(domain: string, issuer: string): Promise<CompanyMetadata> {
    const metadata = await options.metadata.resolveCompany(domain);
    if (metadata.authorization?.issuer !== issuer) fail('binding_conflict');
    return metadata;
  }
  function user(tx: ProviderTransaction, visitor: string, issuer: string): string {
    const key = hash(JSON.stringify([visitor, issuer])), existing = tx.get('user', key);
    if (existing) return existing.userId;
    const userId = id(); tx.put('user', key, { userId }); return userId;
  }
  function throttle(tx: ProviderTransaction, enrollment: Row): void {
    const starts: number[] = enrollment.starts.filter((at: number) => at > now() - 60000);
    if (starts.length >= 60) throw new ProviderError('rate_limited', starts[0]! + 60000);
    starts.push(now()); tx.put('enrollment', enrollment.enrollmentId, { ...enrollment, starts });
  }
  const enrollmentId = (credential: string) => credential.split('.')[0] ?? '';
  const selectedOperation = (credential: string, input: Row): ProviderSelection => ({ kind: 'operation', enrollmentId: enrollmentId(credential), operationId: text(input.operationId) });
  async function authorizeCompany(credential: string, input: Row): Promise<void> {
    const domain = text(input.domain); text(input.issuer);
    await store.transaction({ kind: 'identity', enrollmentId: enrollmentId(credential), issuer: input.issuer }, tx => { const enrollment = auth(tx, credential, text(input.installationId)); if (!enrollment.allowedCompanies.includes(domain)) fail('unauthorized'); });
  }
  const api = {
    async enroll(request: Request, input: Row) {
      exact(input, ['version', 'installationId', 'idempotencyKey']);
      const human = await options.authenticateEnrollment(request);
      if (!human?.subject || !human.allowedCompanies.length) fail('unauthorized');
      const installationId = text(input.installationId), key = hash(JSON.stringify([human.subject, text(input.idempotencyKey)]));
      return store.transaction({ kind: 'enroll', subjectHash: hash(human.subject), requestHash: key }, tx => {
        if (tx.get('enrollmentRequest', key)) fail('consumed'); // Credential delivery cannot be replayed from a verifier.
        const subjectKey = hash(human.subject), visitor = tx.get('visitor', subjectKey)?.id ?? id();
        const count = tx.get('capacity', 'enrollments')?.count ?? 0;
        if (count >= (options.maxEnrollments ?? 10000)) throw new ProviderError('rate_limited', now() + 60000);
        tx.put('capacity', 'enrollments', { count: count + 1 });
        tx.put('visitor', subjectKey, { id: visitor });
        const enrollmentId = id(), secret = id();
        tx.put('enrollment', enrollmentId, { installationId, visitor, verifier: hash(secret), allowedCompanies: [...new Set(human.allowedCompanies)], revoked: false, starts: [] });
        tx.put('enrollmentRequest', key, { enrollmentId });
        return { enrollmentId, credential: `${enrollmentId}.${secret}`, clientId: options.clientId, callbackUrl: options.callbackUrl };
      });
    },
    async identity(credential: string, input: Row) {
      exact(input, ['version', 'installationId', 'domain', 'issuer']);
      await authorizeCompany(credential, input);
      const metadata = await verified(text(input.domain), text(input.issuer));
      return store.transaction({ kind: 'identity', enrollmentId: enrollmentId(credential), issuer: input.issuer }, tx => {
        const enrollment = auth(tx, credential, text(input.installationId));
        if (!enrollment.allowedCompanies.includes(metadata.document.organization.domain)) fail('unauthorized');
        return { clientId: options.clientId, userId: user(tx, enrollment.visitor, input.issuer) };
      });
    },
    async begin(credential: string, input: Row) {
      exact(input, ['version', 'installationId', 'operationId', 'domain', 'issuer', 'purpose', 'sessionId', 'sessionKey', 'returnTo', 'state']);
      if (!['client-authentication', 'session', 'browser', 'direct'].includes(input.purpose)) fail('binding_conflict');
      text(input.operationId);
      if (input.sessionId !== undefined) text(input.sessionId);
      await authorizeCompany(credential, input);
      if (input.purpose === 'client-authentication' && (input.sessionId !== undefined || input.returnTo !== undefined)) fail('binding_conflict');
      if (input.purpose !== 'browser' && input.returnTo !== undefined) fail('binding_conflict');
      if (input.purpose !== 'direct' && input.state !== undefined) fail('binding_conflict');
      if (input.purpose === 'direct' && (typeof input.state !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(input.state) || typeof input.sessionKey !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(input.sessionKey))) fail('binding_conflict');
      if (input.purpose !== 'direct' && input.sessionKey !== undefined) fail('binding_conflict');
      if (input.purpose === 'browser' && !input.sessionId) fail('binding_conflict');
      if (input.purpose === 'browser') text(input.returnTo);
      const metadata = await verified(text(input.domain), text(input.issuer));
      if (input.purpose === 'browser' && (!onDomain(input.returnTo, metadata.document.organization.domain) || !metadata.document.web?.browser_session_endpoint)) fail('binding_conflict');
      const identity = await store.transaction({ kind: 'identity', enrollmentId: enrollmentId(credential), issuer: input.issuer }, tx => {
        const enrollment = auth(tx, credential, text(input.installationId));
        if (!enrollment.allowedCompanies.includes(metadata.document.organization.domain)) fail('unauthorized');
        return { enrollment, userId: user(tx, enrollment.visitor, input.issuer) };
      });
      if (input.purpose === 'browser' && !await options.verifySession?.({ clientId: options.clientId, userId: identity.userId, issuer: input.issuer, sessionId: input.sessionId })) fail('unauthorized');
      const binding = { issuer: input.issuer, domain: metadata.document.organization.domain, purpose: input.purpose, sessionKey: input.sessionKey ?? null, sessionId: input.sessionId ?? null, returnTo: input.returnTo ?? null, stateHash: input.state ? hash(input.state) : null, userId: identity.userId, browserEndpoint: metadata.document.web?.browser_session_endpoint ?? null };
      return store.transaction({ kind: 'begin', enrollmentId: enrollmentId(credential), operationId: input.operationId, issuer: input.issuer, ...(binding.stateHash ? { stateHash: binding.stateHash } : {}), at: now() }, tx => {
        const enrollment = auth(tx, credential, text(input.installationId)), key = `${enrollment.enrollmentId}:${text(input.operationId)}`, existing = tx.get('operation', key);
        if (existing) { if (!same(existing.binding, binding)) fail('binding_conflict'); operation(tx, enrollment, input.operationId); return { expiresAt: existing.expiresAt }; }
        const rows = tx.list('operation', `${enrollment.enrollmentId}:`, 1001);
        // Bounded cleanup preserves tombstones until expiry plus clock tolerance.
        for (const row of rows) if (row.value.expiresAt + 30000 <= now()) { tx.remove('operation', row.id); if (row.value.binding.stateHash) tx.remove('state', row.value.binding.stateHash); }
        // A hard retained-row cap keeps every quota/revocation scan complete, including tombstones.
        if (rows.filter(row => row.value.expiresAt + 30000 > now()).length >= 1000) throw new ProviderError('rate_limited', now() + 60000);
        if (rows.filter(row => row.value.expiresAt > now() && ['pending', 'ready'].includes(row.value.status)).length >= 10) throw new ProviderError('rate_limited', now() + 60000);
        const expiresAt = now() + 600000;
        if (binding.stateHash && tx.get('state', binding.stateHash)) fail('binding_conflict');
        tx.put('operation', key, { binding, expiresAt, status: 'pending', result: null, resultHash: null });
        if (binding.stateHash) tx.put('state', binding.stateHash, { enrollmentId: enrollment.enrollmentId, operationId: input.operationId });
        return { expiresAt };
      });
    },
    async assert(credential: string, input: Row) {
      exact(input, ['version', 'installationId', 'operationId', 'purpose']);
      const snapshot = await store.transaction(selectedOperation(credential, input), tx => {
        const enrollment = auth(tx, credential, text(input.installationId)), op = operation(tx, enrollment, text(input.operationId));
        if (op.binding.purpose !== input.purpose || !['client-authentication', 'session', 'browser'].includes(input.purpose)) fail('binding_conflict');
        throttle(tx, enrollment); return { enrollment, op };
      });
      const b = snapshot.op.binding, metadata = await verified(b.domain, b.issuer);
      if (b.browserEndpoint !== (metadata.document.web?.browser_session_endpoint ?? null)) fail('binding_conflict');
      if (b.purpose === 'browser' && !await options.verifySession?.({ clientId: options.clientId, userId: b.userId, issuer: b.issuer, sessionId: b.sessionId })) fail('unauthorized');
      const iat = Math.floor(now() / 1000), exp = iat + 60;
      const claims = { iss: options.clientId, sub: b.purpose === 'client-authentication' ? options.clientId : b.userId, aud: b.purpose === 'browser' ? b.browserEndpoint : b.issuer, iat, exp, jti: id(), ...(b.purpose === 'browser' ? { session_id: b.sessionId, return_to: b.returnTo } : {}) };
      const header = { alg: 'ES256', kid: options.signer.kid, typ: b.purpose === 'client-authentication' ? 'client-authentication+jwt' : b.purpose === 'browser' ? 'poppy-browser+jwt' : 'JWT' };
      const unsigned = `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}`;
      const signature = await options.signer.sign(new TextEncoder().encode(unsigned));
      if (signature.length !== 64) fail('unavailable');
      // A revoke/cancel racing external KMS signing wins before the assertion leaves the provider.
      await store.transaction(selectedOperation(credential, input), tx => { const enrollment = auth(tx, credential, input.installationId), op = operation(tx, enrollment, input.operationId); tx.put('operation', `${enrollment.enrollmentId}:${input.operationId}`, { ...op, status: 'signed' }); });
      return { assertion: `${unsigned}.${Buffer.from(signature).toString('base64url')}`, expiresAt: exp };
    },
    async callback(callbackUrl: string) {
      const url = new URL(callbackUrl), base = new URL(options.callbackUrl);
      if (url.origin !== base.origin || url.pathname !== base.pathname || url.username || url.password || url.hash || ['state', 'iss', 'code', 'error', 'error_description', 'error_uri'].some(key => url.searchParams.getAll(key).length > 1)) fail('binding_conflict');
      const state = text(url.searchParams.get('state')), issuer = text(url.searchParams.get('iss'));
      if (url.searchParams.has('code') === url.searchParams.has('error') || !(url.searchParams.get('code') || url.searchParams.get('error')) || callbackUrl.length > 8192) fail('binding_conflict');
      return store.transaction({ kind: 'callback', stateHash: hash(state) }, tx => {
        const lookup = tx.get('state', hash(state)); if (!lookup) fail('binding_conflict');
        const enrollment = tx.get('enrollment', lookup.enrollmentId); if (!enrollment || enrollment.revoked) fail('unauthorized');
        const op = operation(tx, { enrollmentId: lookup.enrollmentId }, lookup.operationId, true);
        if (op.binding.issuer !== issuer || op.binding.purpose !== 'direct') fail('binding_conflict');
        const fingerprint = hash(callbackUrl);
        if (op.status === 'ready' || op.status === 'consumed') { if (op.resultHash !== fingerprint) fail('binding_conflict'); return { status: op.status }; }
        tx.put('operation', `${lookup.enrollmentId}:${lookup.operationId}`, { ...op, status: 'ready', result: cipher.seal(callbackUrl), resultHash: fingerprint });
        return { status: 'ready' };
      });
    },
    async takeResult(credential: string, input: Row) {
      exact(input, ['version', 'installationId', 'operationId', 'issuer', 'sessionId', 'sessionKey']);
      return store.transaction(selectedOperation(credential, input), tx => {
        const enrollment = auth(tx, credential, text(input.installationId)), op = operation(tx, enrollment, text(input.operationId));
        if (op.binding.issuer !== input.issuer || op.binding.sessionKey !== input.sessionKey || op.binding.purpose !== 'direct') fail('binding_conflict');
        if (op.status !== 'ready') return { status: 'pending' };
        const callbackUrl = cipher.open(op.result);
        tx.put('operation', `${enrollment.enrollmentId}:${input.operationId}`, { ...op, status: 'consumed', result: null });
        return { status: 'completed', callbackUrl };
      });
    },
    async cancel(credential: string, input: Row) {
      exact(input, ['version', 'installationId', 'operationId']);
      return store.transaction(selectedOperation(credential, input), tx => {
        const enrollment = auth(tx, credential, text(input.installationId)), key = `${enrollment.enrollmentId}:${text(input.operationId)}`, op = tx.get('operation', key);
        if (!op) fail('binding_conflict');
        tx.put('operation', key, { ...op, status: 'canceled', result: null }); return { status: 'canceled' };
      });
    },
    async revokeEnrollment(credential: string, input: Row) {
      exact(input, ['version', 'installationId']);
      return store.transaction({ kind: 'revoke', enrollmentId: enrollmentId(credential) }, tx => {
        const enrollment = auth(tx, credential, text(input.installationId)); tx.put('enrollment', enrollment.enrollmentId, { ...enrollment, revoked: true });
        for (const row of tx.list('operation', `${enrollment.enrollmentId}:`, 1000)) tx.put('operation', row.id, { ...row.value, status: 'canceled', result: null });
        return { status: 'revoked' };
      });
    },
    async handle(request: Request): Promise<Response> {
      const headers = { 'cache-control': 'no-store', 'content-type': 'application/json' };
      try {
        if (request.url === options.clientId && request.method === 'GET') return Response.json({ client_id: options.clientId, client_name: options.clientName, jwks_uri: options.jwksUri, redirect_uris: [options.callbackUrl], token_endpoint_auth_method: 'private_key_jwt' }, { headers });
        if (request.url === options.jwksUri && request.method === 'GET') return Response.json({ keys: (options.publishedKeys ? await options.publishedKeys() : [{ ...await options.signer.publicJwk(), kid: options.signer.kid }]).map(publicKey) }, { headers });
        const url = new URL(request.url);
        if (url.origin === new URL(options.callbackUrl).origin && url.pathname === new URL(options.callbackUrl).pathname && request.method === 'GET') { await api.callback(request.url); return Response.json({ status: 'received' }, { headers }); }
        if (request.method !== 'POST' || !request.headers.get('content-type')?.startsWith('application/json')) fail('binding_conflict');
        const reader = request.body?.getReader(); let body = '', bytes = 0;
        const decoder = new TextDecoder('utf-8', { fatal: true });
        if (reader) try {
          for (;;) { const part = await reader.read(); if (part.done) break; bytes += part.value.length; if (bytes > 16384) fail('binding_conflict'); body += decoder.decode(part.value, { stream: true }); }
          body += decoder.decode();
        } catch { fail('binding_conflict'); } finally { await reader.cancel().catch(() => {}); }
        const input = object(JSON.parse(body)); if (input.version !== 1) fail('binding_conflict');
        const action = url.pathname.slice(url.pathname.lastIndexOf('/') + 1), credential = request.headers.get('authorization')?.match(/^Bearer (\S+)$/)?.[1] ?? '';
        const allowed = ['enroll', 'identity', 'begin', 'assert', 'takeResult', 'cancel', 'revokeEnrollment'] as const;
        if (!allowed.includes(action as any)) fail('binding_conflict');
        const result = action === 'enroll' ? await api.enroll(request, input) : await (api[action as Exclude<typeof allowed[number], 'enroll'>] as (credential: string, input: Row) => unknown)(credential, input);
        return Response.json(result, { headers });
      } catch (error) {
        const code = error instanceof ProviderError ? error.code : 'unavailable';
        return Response.json({ error: code, ...(error instanceof ProviderError && error.retryAt ? { retryAt: error.retryAt } : {}) }, { status: code === 'unauthorized' ? 401 : code === 'rate_limited' ? 429 : code === 'unavailable' ? 503 : 409, headers });
      }
    },
  };
  return api;
}

/** Bound trusted adapter: credentials/assertions/results never belong in harness output. */
export function createProviderClient(options: { url: string; installationId: string; credential: () => Promise<string>; transport: HttpTransport; domain: string }) {
  const base = https(options.url); if (base.search || base.hash) throw new Error('provider URL must not contain query/fragment');
  async function call(action: string, input: Row): Promise<Row> {
    const response = await options.transport.fetch(new Request(`${options.url.replace(/\/$/, '')}/${action}`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${await options.credential()}` }, body: JSON.stringify({ version: 1, installationId: options.installationId, ...input }) }));
    let body: Row;
    try { body = object(await response.json()); } catch { throw new ProviderError('invalid_response'); }
    if (!response.ok) throw new ProviderError(['unauthorized','binding_conflict','expired','consumed','canceled','rate_limited'].includes(body.error) ? body.error : 'unavailable', body.retryAt);
    return body;
  }
  const identity: ProviderIdentity['identity'] = async issuer => { const value = await call('identity', { issuer, domain: options.domain }); return { clientId: text(value.clientId), userId: text(value.userId) }; };
  const assert: AssertionProvider['assert'] = async request => {
    await call('begin', { ...request, domain: options.domain });
    const value = await call('assert', { operationId: request.operationId, purpose: request.purpose });
    return { assertion: text(value.assertion), expiresAt: value.expiresAt };
  };
  return { identity, assert, beginDirect: (input: { operationId: string; issuer: string; sessionKey: string; state: string }) => call('begin', { ...input, domain: options.domain, purpose: 'direct' }),
    takeResult: (input: { operationId: string; issuer: string; sessionKey: string }) => call('takeResult', input),
    cancel: (operationId: string) => call('cancel', { operationId }), revokeEnrollment: () => call('revokeEnrollment', {}) };
}

/** Browser enrollment is an optional host service, separate from company consent. Keep verifier/results in trusted custody. */
export function createBrowserEnrollmentClient(options: { url: string; provider: string; company: string; installationId: string; transport: HttpTransport }) {
  const base = https(options.url), provider = https(options.provider);
  if (base.search || base.hash || provider.origin !== base.origin) throw new TypeError('enrollment and provider must share origin');
  async function call(action: string, input: Row): Promise<Row> {
    const response = await options.transport.fetch(new Request(`${base.href.replace(/\/$/, '')}/${action}`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ version: 1, installationId: options.installationId, provider: options.provider, company: options.company, ...input }),
    }));
    const body = object(await response.json());
    if (!response.ok) throw new ProviderError(['unauthorized','binding_conflict','expired','consumed','canceled','rate_limited'].includes(body.error) ? body.error : 'unavailable');
    return body;
  }
  return {
    async start(challenge: string) {
      if (!/^[\w-]{43}$/.test(challenge)) throw new TypeError('enrollment challenge');
      const body = await call('start', { challenge });
      const browser = https(text(body.browserUrl));
      if (browser.origin !== base.origin || typeof body.expiresAt !== 'number' || !/^[\w-]{43}$/.test(body.requestId)) fail('binding_conflict');
      return { requestId: body.requestId as string, browserUrl: browser.href, expiresAt: body.expiresAt as number };
    },
    async status(requestId: string, verifier: string) {
      const body = await call('status', { requestId, verifier });
      if (!['pending','denied','ready'].includes(body.status)) fail('binding_conflict');
      if (body.status !== 'ready') return { status: body.status as 'pending' | 'denied' };
      const clientId = https(text(body.clientId)).href, callbackUrl = https(text(body.callbackUrl)).href;
      if (new URL(clientId).origin !== provider.origin || new URL(callbackUrl).origin !== provider.origin) fail('binding_conflict');
      return { status: 'ready' as const, credential: text(body.credential), clientId, callbackUrl };
    },
    cancel: (requestId: string, verifier: string) => call('cancel', { requestId, verifier }),
  };
}

