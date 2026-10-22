// Reads the DPoP challenge from a WWW-Authenticate header (RFC 9110 11.6.1, spec 6); other schemes' params are ignored.
const TOKEN = /[A-Za-z0-9!#$%&'*+.^_`|~-]+/y;
export function dpopChallenge(header: string | null): { error?: string; scope?: string; extension?: string; conversation_id?: string } | undefined {
  if (!header) return undefined;
  let i = 0;
  let current: { scheme: string; params: Record<string, string> } | undefined;
  let found: { error?: string; scope?: string } | undefined;
  const skip = (chars: RegExp) => { while (i < header.length && chars.test(header[i])) i++; };
  while (i < header.length) {
    skip(/[\s,]/);
    TOKEN.lastIndex = i;
    const match = TOKEN.exec(header);
    if (!match) { i++; continue; }
    i += match[0].length;
    const afterToken = i;
    skip(/\s/);
    if (header[i] !== '=' || !current) {
      if (header[i] === '=') { i = afterToken; skip(/[=\s]/); continue; } // token68 or stray param before any scheme
      current = { scheme: match[0].toLowerCase(), params: {} };
      if (current.scheme === 'dpop') found = current.params;
      i = afterToken;
      continue;
    }
    i++; skip(/\s/);
    let value = '';
    if (header[i] === '"') {
      i++;
      while (i < header.length && header[i] !== '"') { if (header[i] === '\\') i++; value += header[i] ?? ''; i++; }
      i++;
    } else {
      TOKEN.lastIndex = i;
      value = TOKEN.exec(header)?.[0] ?? '';
      i += value.length;
    }
    const name = match[0].toLowerCase();
    if (current.scheme === 'dpop' && ['error', 'scope', 'extension', 'conversation_id'].includes(name)) current.params[name] = value;
  }
  return found;
}

export interface AuthChallenge { error?: string; requiredScopes: string[]; extensions: string[]; conversationId?: string }
// Combine independent detail channels: a sparse JSON error must not erase header scopes/extensions.
export function authChallenge(header: string | null, body?: unknown): AuthChallenge {
  const challenge = dpopChallenge(header), json = body && typeof body === 'object' && !Array.isArray(body) ? body as Record<string, unknown> : {};
  const scopes = [challenge?.scope, json.scope].flatMap(value => typeof value === 'string' ? value.split(' ').filter(scope => /^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope)) : []);
  const extensions = [challenge?.extension, json.extension].filter((value): value is string => typeof value === 'string' && value.length <= 512 && /^(?:[A-Za-z0-9._-]+|(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\/[A-Za-z0-9._~-]+(?:\/[A-Za-z0-9._~-]+)*)$/.test(value));
  const safe = new Set(['sign_in_required', 'insufficient_scope', 'invalid_token', 'invalid_dpop_proof', 'use_dpop_nonce', 'extension_required', 'rate_limited', 'invalid_scope']);
  const error = [challenge?.error, json.error].find((value): value is string => typeof value === 'string' && safe.has(value));
  const conversationId = [json.conversation_id, challenge?.conversation_id].find((value): value is string => typeof value === 'string' && value.length > 0 && value.length <= 256);
  return { ...(error ? { error } : {}), requiredScopes: [...new Set(scopes)], extensions: [...new Set(extensions)], ...(conversationId ? { conversationId } : {}) };
}
