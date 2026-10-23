import { createHash } from 'node:crypto';
import type { ProviderSelection, ProviderTransaction } from './provider.js';

type Row = Record<string, any>;
export const providerUserKey = (visitor: string, issuer: string) => createHash('sha256').update(JSON.stringify([visitor, issuer])).digest('base64url');

/** Enforces the same aggregate boundary for local, remote and custom stores. */
export function scopedProviderTransaction(selection: ProviderSelection, raw: ProviderTransaction): ProviderTransaction {
  let enrollmentId = 'enrollmentId' in selection ? selection.enrollmentId : undefined;
  let operationId = 'operationId' in selection ? selection.operationId : undefined;
  if (selection.kind === 'callback') {
    const lookup = raw.get('state', selection.stateHash);
    enrollmentId = lookup?.enrollmentId; operationId = lookup?.operationId;
  }
  const enrollment = enrollmentId ? raw.get('enrollment', enrollmentId) : undefined;
  const userKey = 'issuer' in selection && enrollment ? providerUserKey(enrollment.visitor, selection.issuer) : undefined;
  const states = new Set<string>();
  if (selection.kind === 'callback') states.add(selection.stateHash);
  if (selection.kind === 'begin') {
    if (selection.stateHash) states.add(selection.stateHash);
    for (const row of raw.list('operation', `${enrollmentId}:`, 1001)) if (row.value.binding?.stateHash) states.add(row.value.binding.stateHash);
  }
  let createdEnrollment: string | undefined;
  const check = (kind: string, id: string, write = false) => {
    let allowed = false;
    if (selection.kind === 'enroll') {
      allowed = (kind === 'capacity' && id === 'enrollments') || (kind === 'visitor' && id === selection.subjectHash) || (kind === 'enrollmentRequest' && id === selection.requestHash);
      if (kind === 'enrollment' && write && (!createdEnrollment || createdEnrollment === id) && !raw.get(kind, id)) { createdEnrollment = id; allowed = true; }
    } else {
      allowed = (kind === 'enrollment' && id === enrollmentId) || (kind === 'user' && id === userKey) || (kind === 'state' && states.has(id));
      if (kind === 'operation') allowed = (selection.kind === 'begin' || selection.kind === 'revoke') ? id.startsWith(`${enrollmentId}:`) : id === `${enrollmentId}:${operationId}`;
    }
    if (!allowed) throw new TypeError('provider access outside selection');
  };
  return {
    get(kind, id) { check(kind, id); return raw.get(kind, id); },
    put(kind, id, value) { check(kind, id, true); raw.put(kind, id, value); },
    remove(kind, id) { check(kind, id); raw.remove(kind, id); },
    list(kind, prefix, limit) {
      if (!['begin', 'revoke'].includes(selection.kind) || kind !== 'operation' || prefix !== `${enrollmentId}:` || !Number.isSafeInteger(limit) || limit < 1 || limit > 1001) throw new TypeError('provider list outside selection');
      return raw.list(kind, prefix, limit);
    },
  };
}

export function providerMemoryTransaction(rows: Map<string, Row>): ProviderTransaction {
  const key = (kind: string, id: string) => JSON.stringify([kind, id]);
  return {
    get: (kind, id) => rows.get(key(kind, id)),
    put: (kind, id, value) => { rows.set(key(kind, id), value); },
    remove: (kind, id) => { rows.delete(key(kind, id)); },
    list: (kind, prefix, limit) => [...rows].map(([key, value]) => ({ key: JSON.parse(key) as [string, string], value })).filter(row => row.key[0] === kind && row.key[1].startsWith(prefix)).sort((a, b) => a.key[1].localeCompare(b.key[1])).slice(0, limit).map(row => ({ id: row.key[1], value: row.value })),
  };
}
