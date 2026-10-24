import type { ClientAuthState } from './client-auth.js';

/** A connection aggregate includes its grants, operations and cleanup; never other connections. */
export type AuthSelection = ({ connectionId: string } | { operationId: string } | { issuer: string } | { callbackHash: string } | { list: true }) & { history?: true };
export interface AuthStore {
  read(selection: AuthSelection): Promise<ClientAuthState>;
  transaction<T>(selection: AuthSelection, change: (draft: ClientAuthState) => T): Promise<T>;
  /** Ascending IDs strictly after the cursor. Includes only nonterminal operations. */
  pendingOperations(after: string | undefined, limit: number): Promise<string[]>;
}
