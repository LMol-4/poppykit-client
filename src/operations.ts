import { randomBytes } from 'node:crypto';
import { canonical, id as parseId, object, parseJson, retryAfterMilliseconds, validateJson } from './protocol/wire.js';
import type { Json, JsonObject, Message } from './protocol/wire.js';
import { approvalHeader, approvalMetaKey, captureApiOperationRequest, operationRequest, operationExpiry, parseBusinessOperation, requestFingerprint, supportsOperations } from './protocol/operations.js';
import type { BusinessOperation, OperationApproval, OperationRequest } from './protocol/operations.js';

export interface BusinessClientContext {
  companyId: string; companyName: string; clientId: string; userId: string;
  /** Local grant identity when signed in; exact Session identity otherwise. Never a token. */
  authority: string; operations: boolean;
}
export interface BusinessAttempt {
  version: 1; id: string; context: BusinessClientContext; request: OperationRequest; operation: BusinessOperation;
  phase: 'pending_consent' | 'consenting' | 'approved' | 'declined' | 'withdrawn' | 'expired' | 'uncertain' | 'completed';
  consentToken?: string; result?: Json; retryAt?: number;
  headers?: [string, string][];
  messageId: string; withdrawalRequested?: true;
  previousDecisions?: { revision: string; phase: BusinessAttempt['phase'] }[];
}
/** Atomic, cross-process synchronous mutation of one detached attempt; rollback on throw; reject unknown versions. */
export interface BusinessAttemptStore {
  pending(after: string | undefined, limit: number): Promise<string[]>;
  transaction<T>(id: string, action: (slot: { record?: BusinessAttempt }) => T): Promise<T>;
}
export interface TrustedOperationConsent {
  /** Trusted UI only: show companyName and summary as inert literal text, plus all differences. Ask for this operation.
   * This adapter MUST collect the actual user's answer. Never expose it, or a consent result, as a model tool.
   */
  confirm(input: { attemptId: string; companyId: string; companyName: string; summary: string; terms?: JsonObject; differences: string[] }): Promise<'approve' | 'decline'>;
}
export type OperationDelivery = { kind: 'completed'; result: Json } | { kind: 'pending'; retryAfterMs?: number };
export class OperationClientError extends Error {
  constructor(readonly code: string) { super('Business operation ' + code); }
}
export function createOperationClient(options: {
  store: BusinessAttemptStore; context(): Promise<BusinessClientContext>;
  consent: TrustedOperationConsent;
  /** Trusted application comparison, independent of Company/model claims. Return differences to show to the User. */
  checkTerms(request: OperationRequest, operation: BusinessOperation): Promise<string[]>;
  send(attempt: Readonly<BusinessAttempt>, approval: OperationApproval, signal: AbortSignal): Promise<OperationDelivery>;
  now?: () => number;
}) {
  const now = options.now ?? Date.now;
  const sending = new Map<string, Set<AbortController>>();
  const token = () => randomBytes(24).toString('base64url');
  function sameContext(a: BusinessClientContext, b: BusinessClientContext): boolean {
    return a.companyId === b.companyId && a.clientId === b.clientId && a.userId === b.userId && a.authority === b.authority;
  }
  async function context(requireSupport = false): Promise<BusinessClientContext> {
    const value = await options.context();
    if (requireSupport && !value.operations) throw new OperationClientError('not_negotiated');
    return value;
  }
  async function withAttempt<T>(id: string, action: (record: BusinessAttempt) => T): Promise<T> {
    const current = await context();
    return options.store.transaction(id, slot => {
      if (!slot.record || slot.record.version !== 1) throw new OperationClientError('unknown_attempt');
      if (!sameContext(slot.record.context, current)) throw new OperationClientError('owner_changed');
      return action(slot.record);
    });
  }
  async function receive(id: string, request: OperationRequest, value: unknown, headers?: [string, string][]): Promise<BusinessAttempt> {
    parseId(id, 'attempt_id');
    const current = await context(true), operation = parseBusinessOperation(value), binding = operationRequest(request);
    return options.store.transaction(id, slot => {
      if (slot.record) {
        const old = slot.record;
        if (old.version !== 1) throw new OperationClientError('unsupported_version');
        if (!sameContext(old.context, current)) throw new OperationClientError('owner_changed');
        if (canonical(old.operation) === canonical(operation) && requestFingerprint(old.request) === requestFingerprint(binding)) return structuredClone(old);
        if (old.operation.operation_id === operation.operation_id && old.operation.revision === operation.revision) throw new OperationClientError('revision_changed');
        if (['uncertain','completed'].includes(old.phase)) throw new OperationClientError('attempt_uncertain');
      }
      const record: BusinessAttempt = { version: 1, id, context: current, request: binding, operation, phase: operationExpiry(operation.expires_at) <= now() ? 'expired' : 'pending_consent', messageId: token(), ...(headers ? { headers } : {}) };
      if (slot.record) record.previousDecisions = [...(slot.record.previousDecisions ?? []), { revision: slot.record.operation.revision, phase: slot.record.phase }];
      slot.record = record; return structuredClone(record);
    });
  }
  return {
    receive,
    async receiveApi(id: string, request: Request, response: Response): Promise<BusinessAttempt> {
      if (response.status !== 403) throw new OperationClientError('not_operation');
      const body = object(parseJson(await response.clone().text()));
      if (body.error !== 'approval_required') throw new OperationClientError('not_operation');
      const headers = [...request.headers].filter(([key]) => !['authorization','poppy-session','poppy-approval','dpop','cookie','idempotency-key'].includes(key));
      return receive(id, await captureApiOperationRequest(request), body.operation, headers);
    },
    async receiveMcp(id: string, request: Extract<OperationRequest, { channel: 'mcp' }>, result: unknown): Promise<BusinessAttempt> {
      const body = object(result);
      if (body.isError !== true) throw new OperationClientError('not_operation');
      return receive(id, request, object(body.structuredContent).operation);
    },
    async receiveConversation(id: string, request: Extract<OperationRequest, { channel: 'conversation' }>, message: unknown): Promise<BusinessAttempt> {
      const body = object(message);
      if (body.role !== 'company') throw new OperationClientError('not_operation');
      return receive(id, request, body.operation);
    },
    async recover(after?: string, limit = 100): Promise<(BusinessAttempt | { id: string; error: string })[]> {
      const result: (BusinessAttempt | { id: string; error: string })[] = [];
      for (const id of await options.store.pending(after, limit)) {
        try { result.push(await withAttempt(id, record => structuredClone(record))); }
        catch (error) { if (!(error instanceof OperationClientError)) throw error; result.push({ id, error: error.code }); }
      }
      return result;
    },
    get(id: string): Promise<BusinessAttempt> { return withAttempt(id, record => structuredClone(record)); },
    async requestConsent(id: string): Promise<BusinessAttempt> {
      await context(true);
      const selected = await withAttempt(id, record => {
        if (record.phase !== 'pending_consent') throw new OperationClientError('consent_not_pending');
        if (operationExpiry(record.operation.expires_at) <= now()) { record.phase = 'expired'; return structuredClone(record); }
        record.phase = 'consenting'; record.consentToken = token(); return structuredClone(record);
      });
      if (selected.phase === 'expired') return selected;
      let answer: 'approve' | 'decline';
      try {
        const differences = await options.checkTerms(structuredClone(selected.request), structuredClone(selected.operation));
        if (!Array.isArray(differences) || differences.some(value => typeof value !== 'string')) throw new OperationClientError('invalid_terms_check');
        answer = await options.consent.confirm({ attemptId: id, companyId: selected.context.companyId, companyName: selected.context.companyName, summary: selected.operation.summary, ...(selected.operation.terms ? { terms: structuredClone(selected.operation.terms) } : {}), differences });
        if (answer !== 'approve' && answer !== 'decline') throw new OperationClientError('invalid_consent');
      } catch { throw new OperationClientError('consent_interrupted'); }
      return withAttempt(id, record => {
        if (record.phase !== 'consenting' || record.consentToken !== selected.consentToken) throw new OperationClientError('consent_withdrawn');
        delete record.consentToken;
        record.phase = operationExpiry(record.operation.expires_at) <= now() ? 'expired' : answer === 'approve' ? 'approved' : 'declined';
        return structuredClone(record);
      });
    },
    /** Explicitly dismiss the old UI first. Its late callback is fenced; a fresh answer is required. */
    resumeConsent(id: string): Promise<BusinessAttempt> {
      return withAttempt(id, record => { if (record.phase !== 'consenting') throw new OperationClientError('consent_not_interrupted'); delete record.consentToken; record.phase = 'pending_consent'; return structuredClone(record); });
    },
    withdraw(id: string): Promise<BusinessAttempt> {
      for (const controller of sending.get(id) ?? []) controller.abort();
      return withAttempt(id, record => {
        if (record.phase === 'uncertain') { record.withdrawalRequested = true; return structuredClone(record); }
        if (!['pending_consent','consenting','approved'].includes(record.phase)) throw new OperationClientError('already_sent');
        delete record.consentToken; record.phase = 'withdrawn'; return structuredClone(record);
      });
    },
    async retry(id: string): Promise<BusinessAttempt> {
      await context(true);
      const controller = new AbortController(), active = sending.get(id) ?? new Set<AbortController>(); active.add(controller); sending.set(id, active);
      try {
      const selected = await withAttempt(id, record => {
        if (record.withdrawalRequested) throw new OperationClientError('approval_withdrawn');
        if (!['approved','uncertain'].includes(record.phase)) throw new OperationClientError('not_approved');
        if (record.retryAt && record.retryAt > now()) throw new OperationClientError('retry_later');
        if (record.phase === 'approved' && operationExpiry(record.operation.expires_at) <= now()) { record.phase = 'expired'; return structuredClone(record); }
        // Commit before dispatch. Crash/timeout recovery retains this exact approval, request and message ID.
        record.phase = 'uncertain'; return structuredClone(record);
      });
      if (selected.phase === 'expired') return selected;
      let outcome: OperationDelivery;
      try {
        controller.signal.throwIfAborted();
        await withAttempt(id, record => { if (record.withdrawalRequested) controller.abort(); });
        controller.signal.throwIfAborted();
        outcome = await options.send(selected, { operation_id: selected.operation.operation_id, revision: selected.operation.revision }, controller.signal);
      }
      catch { return withAttempt(id, record => structuredClone(record)); }
      return withAttempt(id, record => {
        if (record.phase === 'completed') return structuredClone(record);
        if (outcome.kind === 'completed') { validateJson(outcome.result); record.result = structuredClone(outcome.result); record.phase = 'completed'; }
        else if (outcome.retryAfterMs !== undefined) record.retryAt = Math.min(Number.MAX_SAFE_INTEGER, now() + outcome.retryAfterMs);
        return structuredClone(record);
      });
      } finally { active.delete(controller); if (!active.size) sending.delete(id); }
    },
    /** Trusted host lookup of actual business state; an operation returned on retry is not reconciliation. */
    async reconcile(id: string, lookup: (attempt: Readonly<BusinessAttempt>) => Promise<OperationDelivery>): Promise<BusinessAttempt> {
      const selected = await withAttempt(id, record => { if (record.phase !== 'uncertain') throw new OperationClientError('not_uncertain'); return structuredClone(record); });
      const outcome = await lookup(selected);
      return withAttempt(id, record => {
        if (record.phase === 'completed') return structuredClone(record);
        if (outcome.kind === 'completed') { validateJson(outcome.result); record.result = structuredClone(outcome.result); record.phase = 'completed'; }
        return structuredClone(record);
      });
    },
  };
}
export function approvedApiRequest(attempt: BusinessAttempt, approval: OperationApproval, signal?: AbortSignal): Request {
  if (attempt.request.channel !== 'api') throw new OperationClientError('wrong_channel');
  const headers = new Headers(attempt.headers); headers.delete('idempotency-key'); headers.set('poppy-approval', approvalHeader(approval));
  return new Request(attempt.request.url, { method: attempt.request.method, headers, signal, body: attempt.request.body === null ? null : Buffer.from(attempt.request.body, 'base64'), redirect: 'manual' });
}
export function approvedMcpParams(attempt: BusinessAttempt, approval: OperationApproval): JsonObject {
  if (attempt.request.channel !== 'mcp') throw new OperationClientError('wrong_channel');
  return { name: attempt.request.name, arguments: structuredClone(attempt.request.arguments), _meta: { [approvalMetaKey]: approval as JsonObject } };
}
export function approvedConversationMessage(attempt: BusinessAttempt, approval: OperationApproval): Message {
  if (attempt.request.channel !== 'conversation') throw new OperationClientError('wrong_channel');
  return { id: attempt.messageId, author: { type: 'agent' }, approval };
}
/** Adapters must use verified SDK channel targets and current authorization; a conversation acceptance is still pending work. */
export function createOperationSender(channels: {
  api(request: Request, context: BusinessClientContext): Promise<Response>;
  mcp(url: string, params: JsonObject, signal: AbortSignal, context: BusinessClientContext): Promise<JsonObject>;
  conversation(request: Extract<OperationRequest, { channel: 'conversation' }>, message: Message, signal: AbortSignal, context: BusinessClientContext): Promise<void>;
}) {
  return async (attempt: Readonly<BusinessAttempt>, approval: OperationApproval, signal: AbortSignal): Promise<OperationDelivery> => {
    if (attempt.request.channel === 'api') {
      const response = await channels.api(approvedApiRequest(attempt, approval, signal), attempt.context);
      if (response.status === 202 || !response.ok) { await response.body?.cancel(); return { kind: 'pending', retryAfterMs: retryAfterMilliseconds(response.headers.get('retry-after'), Date.now()) }; }
      return { kind: 'completed', result: { status: response.status, headers: [...response.headers].filter(([name]) => !['set-cookie','authorization','poppy-session','dpop'].includes(name)), body: Buffer.from(await response.arrayBuffer()).toString('base64') } };
    }
    if (attempt.request.channel === 'mcp') {
      const result = await channels.mcp(attempt.request.url, approvedMcpParams(attempt, approval), signal, attempt.context);
      if (result.isError === true) return { kind: 'pending' };
      return { kind: 'completed', result };
    }
    await channels.conversation(attempt.request, approvedConversationMessage(attempt, approval), signal, attempt.context);
    return { kind: 'pending' };
  };
}
export { supportsOperations };
