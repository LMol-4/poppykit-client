// Reads the DPoP challenge from a WWW-Authenticate header (RFC 9110 11.6.1, spec 6); other schemes' params are ignored.
const TOKEN = /[A-Za-z0-9!#$%&'*+.^_`|~-]+/y;
export function dpopChallenge(header: string | null): { error?: string; scope?: string } | undefined {
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
    if (current.scheme === 'dpop' && (name === 'error' || name === 'scope')) current.params[name] = value;
  }
  return found;
}
