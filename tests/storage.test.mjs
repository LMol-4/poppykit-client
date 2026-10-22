import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { SqliteAuthStore, SqliteConversationStore } from '../dist/sqlite.js';
import { MemoryConversationStore } from '../dist/memory.js';
import { createConversationClient } from '../dist/index.js';

const key = { connectionId: 'c', issuer: 'https://issuer.test/one', endpoint: 'https://company.test/conversations' };
const row = { ...key, id: 'message', target: null, request: { message: { id: 'message', sender: 'agent', text: 'hello' } }, fingerprint: 'same', phase: 'pending' };
const directories = [];
after(async () => { for (const dir of directories) await rm(dir, { recursive: true, force: true }); });
async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'poppy-storage-'));
  directories.push(dir);
  return join(dir, 'state.db');
}
function worker(t, mode, path) {
  const child = fork(new URL('../test-support/storage-worker.mjs', import.meta.url), [mode, path], { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  const exited = once(child, 'exit');
  let errors = ''; child.stderr.on('data', b => { errors += b; });
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) { child.kill(); await once(child, 'exit'); } });
  const message = new Promise((resolve, reject) => { child.once('message', resolve); child.once('error', reject); child.once('exit', code => { if (code) reject(new Error(errors)); }); });
  return { child, message, exited };
}
for (const durable of [false, true]) test(`outbound and checkpoint domain contract (${durable ? 'SQLite' : 'memory'})`, async t => {
  const store = durable ? new SqliteConversationStore(await fixture(t)) : new MemoryConversationStore();
  t.after(() => store.close?.());
  const first = await store.prepareOutbound(key, row); first.request.message.text = 'mutated';
  assert.equal((await store.getOutbound(key, row.id)).request.message.text, 'hello');
  assert.equal((await store.prepareOutbound(key, { ...row, fingerprint: 'conflict' })).fingerprint, 'same');
  assert.equal(await store.getOutbound({ ...key, issuer: 'https://issuer.test/two' }, row.id), undefined);
  const checkpoint = { connectionId: key.connectionId, issuer: key.issuer, conversationId: 'conversation', name: 'reader', cursor: 'a' };
  await store.advanceCheckpoint(key, checkpoint, [undefined]);
  await store.advanceCheckpoint(key, { ...checkpoint, cursor: 'b' }, [undefined]);
  assert.equal(await store.getCheckpoint(key, checkpoint.conversationId, checkpoint.name), 'a');
  let sent = 0;
  const client = createConversationClient({ ...key, endpoint: 'https://other.test/conversations', store, clock: { now: Date.now }, authorizedRequest: async () => { sent++; throw new Error('must not send'); } });
  await assert.rejects(client.retry(row.id), { code: 'invalid_target' });
  assert.equal(sent, 0);
});

test('two real processes prepare one durable receipt, retained after termination before dispatch', { timeout: 15000 }, async t => {
  const path = await fixture(t);
  const a = worker(t, 'prepare', path), b = worker(t, 'prepare', path);
  await Promise.all([a.message, b.message]);
  await Promise.all([a.exited, b.exited]);
  const store = new SqliteConversationStore(path); t.after(() => store.close());
  assert.deepEqual(await store.getOutbound(key, row.id), row);
  const db = new DatabaseSync(path); assert.equal(db.prepare('SELECT count(*) AS n FROM outbound').get().n, 1); db.close();
});

test('termination before commit rolls back auth records', { timeout: 15000 }, async t => {
  const path = await fixture(t), a = worker(t, 'before-commit', path);
  await a.message; a.child.kill(); await once(a.child, 'exit');
  const store = new SqliteAuthStore(path); t.after(() => store.close());
  assert.deepEqual((await store.read({ issuer: 'uncommitted' })).identities, {});
  await assert.rejects(store.transaction({ issuer: 'bad' }, async () => {}), /async auth transaction/);
  await assert.rejects(store.transaction({ issuer: 'bad' }, state => { state.identities.bad = { userId: undefined }; }), /non-JSON/);
});

test('live authentication survives another process; owner death after external effect becomes uncertain', { timeout: 20000 }, async t => {
  const path = await fixture(t), active = worker(t, 'exchange', path);
  const started = await active.message;
  assert.deepEqual((await worker(t, 'recover', path).message).results, []);
  active.child.kill(); await once(active.child, 'exit');
  assert.deepEqual((await worker(t, 'recover', path).message).results, [{ operationId: started.operationId, status: 'uncertain' }]);
  assert.deepEqual((await worker(t, 'recover', path).message).results, []);
  const external = new DatabaseSync(path + '.external');
  assert.equal(external.prepare('SELECT count(*) AS n FROM effects').get().n, 1); external.close();
});
