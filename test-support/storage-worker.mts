import assert from 'node:assert/strict';
import type {OutboundRecord} from '../dist/conversation.js';
import { expectValue, publicEcJwk } from './assertions.mjs';
import { SqliteAuthStore, SqliteConversationStore } from '../dist/sqlite.js';
import { createClientAuth, createMetadataResolver } from '../dist/index.js';
import { createFakeCompany, fakeTransport } from '../tests/auth/fake-issuer.mjs';
import { DatabaseSync } from 'node:sqlite';
import { PostgresAuthStore,PostgresConversationStore } from '../dist/postgres.js';
import { testPool } from './postgres.mjs';
const pool=process.env.D1_POSTGRES==='1'?testPool():undefined;

const [mode, path] = process.argv.slice(2);
const key = { connectionId: 'c', issuer: 'https://issuer.test/one', endpoint: 'https://company.test/conversations' };
const row:OutboundRecord = { ...key, id: 'message', target: null, request: { message: { id: 'message', author: { type: 'agent' }, text: 'hello' } }, fingerprint: 'same', phase: 'pending' };
const pause = () => new Promise(() => { setInterval(() => {}, 1000); });
if (mode === 'prepare') {
  const store = pool?new PostgresConversationStore(pool,path):new SqliteConversationStore(path);
  await store.prepareOutbound(key, row); await store.close();
  expectValue(process.send).call(process, { ready: true });
} else if (mode === 'before-commit') {
  const store = pool?new PostgresAuthStore(pool,path):new SqliteAuthStore(path);
  await store.transaction({ issuer: 'uncommitted' }, state => {
    state.identities.uncommitted = { userId: 'u', dpopKeyRef: 'reference' };
    expectValue(process.send).call(process, { ready: true });
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
  });
} else {
  const store = pool?new PostgresAuthStore(pool,path):new SqliteAuthStore(path);
  const secrets = new Map();
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = { ...await publicEcJwk(pair.publicKey), kid: 'test-key', alg: 'ES256' };
  const identity = { kid: jwk.kid, publicJwk: async () => jwk, sign: async (input:Uint8Array) => new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new Uint8Array(input))) };
  const clientId = 'https://agent.test/client.json', redirectUri = 'https://agent.test/callback', browserBinding = 'browser-binding-for-test-only';
  const company = createFakeCompany({ jwks: { keys: [jwk] }, clientId, redirectUris: [redirectUri], now: Date.now });
  const transport = fakeTransport(company);
  const auth = createClientAuth({ namespace: 'process-test', localUserId: 'user', clientId, redirectUris: [redirectUri], identity, store,
    secrets: { async stage(value) { const id = crypto.randomUUID(); secrets.set(id, value); return id; }, async read(id) { return secrets.get(id) ?? null; }, async remove(id) { secrets.delete(id); } },
    transport, metadata: createMetadataResolver(transport) });
  if (mode === 'recover') {
    const results = await auth.recover(); await store.close();
    expectValue(process.send).call(process, { results: results.map(r => ({ status: r.status, operationId: r.operationId })) });
  } else {
    const { connection } = await auth.start(company.domain);
    const begun = await auth.beginSignIn(connection.id, { scopes: ['orders:read'], redirectUri, browserBinding });
    const callbackUrl = company.authorize(expectValue(begun.authorizationUrl), { account: 'account' });
    if (mode === 'rotation') await auth.completeSignIn({ callbackUrl, browserBinding });
    const handle = company.handle;
    company.handle = async (request, options) => {
      const response = await handle(request, options);
      if (request.url === company.tokenEndpoint) {
        const active = Object.values((await store.read({ connectionId: connection.id })).operations).find(record => record.phase === 'dispatched');
        // Synthetic external side effect commits independently of SDK completion.
        const external = new DatabaseSync(path + '.external');
        external.exec('CREATE TABLE IF NOT EXISTS effects (id TEXT PRIMARY KEY)');
        external.prepare('INSERT INTO effects VALUES (?)').run(expectValue(active).id);
        external.close();
        expectValue(process.send).call(process,{ ready: true, operationId: expectValue(active).id });
        await pause();
      }
      return response;
    };
    if (mode === 'rotation') await auth.renew(connection.id);
    else await auth.completeSignIn({ callbackUrl, browserBinding });
  }
}

await pool?.end();
