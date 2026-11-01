import { createHash } from 'node:crypto';
export interface CredentialFingerprint { length: number; hint: number; digest: string; expiresAt: number }
const digest = (text: string) => createHash('sha256').update(text).digest('hex');
// Rolling prefix hashes only select candidates; SHA-256 confirms every match.
const width = 8, base = 31;
const hint = (text: string, span = width) => { let result = 0; for (let i = 0; i < Math.min(span, text.length); i++) result = (Math.imul(result, base) + text.charCodeAt(i)) >>> 0; return result; };
export class CredentialEchoGuard {
  readonly fingerprints = new Map<string, CredentialFingerprint>();
  private readonly widths = new Set<number>();
  readonly live = new Map<string, string>();
  private readonly candidates = new Map<number, Map<number, Set<string>>>();
  constructor(readonly reject: () => never, readonly clientId = '', readonly now = Date.now) {}
  private proof(value: string): boolean {
    for (let offset = value.indexOf('eyJ'); offset >= 0; offset = value.indexOf('eyJ', offset + 3)) {
      const jwt = /^(eyJ[A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.[A-Za-z0-9_-]+/.exec(value.slice(offset));
      if (!jwt) continue;
      try {
        const header = JSON.parse(Buffer.from(jwt[1], 'base64url').toString('utf8'));
        if (['dpop+jwt','poppy-session+jwt','pap-delegation+jwt'].includes(header.typ)) return true;
        const claims = JSON.parse(Buffer.from(jwt[2], 'base64url').toString('utf8'));
        if (this.clientId && claims.iss === this.clientId && claims.sub === this.clientId && claims.aud && claims.jti && claims.exp) return true;
      } catch { /* Ordinary business strings are not credentials merely because they contain dots. */ }
    }
    return false;
  }
  add(values: readonly CredentialFingerprint[]) {
    for (const [key, value] of this.fingerprints) if (value.expiresAt <= this.now()) {
      this.fingerprints.delete(key);
      const lengths = this.candidates.get(value.hint), hashes = lengths?.get(value.length);
      hashes?.delete(key);
      if (!hashes?.size) lengths?.delete(value.length);
      if (!lengths?.size) this.candidates.delete(value.hint);
    }
    for (const value of values) if (value.expiresAt > this.now() && (this.fingerprints.get(value.digest)?.expiresAt ?? 0) < value.expiresAt) {
      if (!Number.isSafeInteger(value.length) || value.length < 1 || !Number.isSafeInteger(value.expiresAt) || !Number.isSafeInteger(value.hint) || !/^[a-f0-9]{64}$/.test(value.digest)) throw new Error('Invalid credential fingerprint');
      this.fingerprints.set(value.digest, value);
      this.widths.add(Math.min(width, value.length));
      let lengths = this.candidates.get(value.hint); if (!lengths) this.candidates.set(value.hint, lengths = new Map());
      let hashes = lengths.get(value.length); if (!hashes) lengths.set(value.length, hashes = new Set());
      hashes.add(value.digest);
    }
  }
  remember(values: readonly string[], expiresAt = Number.MAX_SAFE_INTEGER) {
    const added = values.filter(value => value.length > 0 && !this.proof(value)).map(value => ({length:value.length,hint:hint(value),digest:digest(value),expiresAt}));
    this.add(added); return added;
  }
  private text(value: string): void {
    for (let depth = 0; depth < 4; depth++) {
      if (this.proof(value) || [...this.live.values()].some(secret => value.includes(secret))) this.reject();
      for (const span of this.widths) {
        let rolling = hint(value, span), power = 1;
        for (let i = 1; i < span; i++) power = Math.imul(power, base);
        for (let offset = 0; offset + span <= value.length; offset++) {
          const lengths = this.candidates.get(rolling);
          if (lengths) for (const [length, hashes] of lengths) if (offset + length <= value.length) {
            const hash = digest(value.slice(offset, offset + length));
            if (hashes.has(hash) && (this.fingerprints.get(hash)?.expiresAt ?? 0) > this.now()) this.reject();
          }
          rolling = (Math.imul(rolling - Math.imul(value.charCodeAt(offset), power), base) + value.charCodeAt(offset + span)) >>> 0;
        }
      }
      let decoded = value;
      try { decoded = decodeURIComponent(decoded); } catch { /* Literal percent signs are valid text. */ }
      decoded = decoded.replace(/\\u([0-9a-f]{4})/gi, (_, hex: string) => String.fromCharCode(parseInt(hex, 16))).replace(/\\(["\\/])/g, '$1');
      if (decoded === value) break;
      value = decoded;
    }
  }
  check = (value: unknown): void => {
    if (typeof value === 'string') {
      this.text(value);
      // API operation receipts store their exact response bytes as base64.
      if (value.length >= 12 && value.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(value)) this.text(Buffer.from(value, 'base64').toString('utf8'));
    } else if (value && typeof value === 'object') for (const [key, item] of Object.entries(value)) { this.text(key); this.check(item); }
  };
}

/** The transport already bounds bytes/time. Inspect before any consumer can persist company content. */
export async function protectCompanyResponse(response: Response, check: (value: unknown) => void): Promise<Response> {
  check([...response.headers]);
  if (!response.body) return response;
  const init = { status: response.status, statusText: response.statusText, headers: response.headers };
  if (response.headers.get('content-type')?.split(';')[0].trim() !== 'text/event-stream') {
    const bytes = await response.arrayBuffer(), text = new TextDecoder().decode(bytes);
    check(text);
    let parsed: unknown;
    try { parsed = JSON.parse(text); } catch { /* Non-JSON company responses remain unchanged. */ }
    check(parsed);
    return new Response(bytes, init);
  }
  // Hold each complete frame until its decoded data passes; never expose a rejected partial frame.
  const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', { fatal: true }), encoder = new TextEncoder();
  let buffer = '', frame = '', partial = '', messageId: unknown;
  const body = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        for (;;) {
          const end = buffer.search(/[\r\n]/);
          if (end >= 0 && !(buffer[end] === '\r' && end === buffer.length - 1)) {
            const line = buffer.slice(0, end), width = buffer[end] === '\r' && buffer[end + 1] === '\n' ? 2 : 1;
            frame += buffer.slice(0, end + width); buffer = buffer.slice(end + width);
            if (Buffer.byteLength(frame) > 1048576) throw new Error('Company stream frame limit');
            if (line) continue;
            check(frame);
            const lines = frame.split(/\r\n|\r|\n/), data = lines.filter(line => line.startsWith('data:')).map(line => line.slice(5).replace(/^ /, '')).join('\n');
            let value: Record<string, unknown> | undefined;
            try { value = JSON.parse(data); } catch { /* The protocol parser handles malformed frames. */ }
            check(value);
            if (lines.some(line => /^event: ?text-delta$/.test(line)) && typeof value?.text === 'string') {
              if (messageId !== value.message_id) { partial = ''; messageId = value.message_id; }
              partial += value.text;
              if (Buffer.byteLength(partial) > 1048576) throw new Error('Company stream message limit');
              check(partial);
            } else if (value?.type === 'message') { partial = ''; messageId = undefined; }
            controller.enqueue(encoder.encode(frame)); frame = ''; return;
          }
          if (Buffer.byteLength(frame) + Buffer.byteLength(buffer) > 1048576) throw new Error('Company stream frame limit');
          const item = await reader.read();
          if (item.done) { buffer += decoder.decode(); if (buffer.endsWith('\r')) { buffer += '\n'; continue; } check(frame + buffer); controller.close(); reader.releaseLock(); return; }
          buffer += decoder.decode(item.value, { stream: true });
        }
      } catch (error) { await reader.cancel().catch(() => {}); reader.releaseLock(); controller.error(error); }
    },
    async cancel(reason) { await reader.cancel(reason); reader.releaseLock(); },
  }, { highWaterMark: 0 });
  return new Response(body, init);
}
