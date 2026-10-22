import { randomUUID } from 'node:crypto';
import { hostname } from 'node:os';

export interface OperationOwner { host: string; pid: number; id: string }
const active = new Set<string>();
export function acquireOwner(): OperationOwner {
  const owner = { host: hostname(), pid: process.pid, id: randomUUID() };
  active.add(owner.id);
  return owner;
}
export function releaseOwner(owner: OperationOwner): void { active.delete(owner.id); }
/** Unknown remote owners and permission failures are conservatively live. */
export function localOwnerAlive(owner: OperationOwner): boolean {
  if (owner.host !== hostname()) return true;
  if (owner.pid === process.pid) return active.has(owner.id);
  try { process.kill(owner.pid, 0); return true; }
  catch (error) { return (error as NodeJS.ErrnoException).code !== 'ESRCH'; }
}
