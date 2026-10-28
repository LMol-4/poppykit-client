import type {OutboundRecord} from '../dist/conversation.js';
import type {OperationRecord} from '../dist/auth/client-auth.js';
import { expectValue } from '../test-support/assertions.mjs';
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { fork,type SpawnOptions } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { SqliteAuthStore, SqliteConversationStore } from '../dist/sqlite.js';
import { MemoryConversationStore } from '../dist/memory.js';
import { createConversationClient } from '../dist/index.js';

const key = { connectionId: 'c', issuer: 'https://issuer.test/one', endpoint: 'https://company.test/conversations' };
const row:OutboundRecord = { ...key, id: 'message', target: null, request: { message: { id: 'message', author: { type: 'agent' }, text: 'hello' } }, fingerprint: 'same', phase: 'pending' };
test('old pending outbox survives reopen but cannot dispatch or be rewritten under its ID', async t => {
  const path=await fixture(t), first=new SqliteConversationStore(path);
  const legacy={...row,request:{message:{id:row.id,sender:'agent',text:'hello'}},fingerprint:'accepted-or-uncertain-original'};
  await first.prepareOutbound(key,legacy as unknown as OutboundRecord);first.close();
  const store=new SqliteConversationStore(path);t.after(()=>store.close());let calls=0;
  const client=createConversationClient({...key,store,clock:{now:Date.now},authorizedRequest:async()=>{calls++;throw new Error('must not send');}});
  await assert.rejects(client.retry(row.id),{code:'legacy_message_uncertain'});
  await assert.rejects(client.start(row.request.message),{code:'message_id_conflict'});
  assert.equal(calls,0);assert.deepEqual(await store.getOutbound(key,row.id),legacy);
});
test('explicit SQLite retry removal preserves other destinations',async t=>{
  const store=new SqliteConversationStore(await fixture(t));t.after(()=>store.close());
  await store.prepareOutbound(key,row);
  assert.throws(()=>store.removeOutbound({...key,endpoint:'https://other.test/conversations'},row.id),/binding/);
  assert.equal(expectValue((await store.getOutbound(key,row.id))).fingerprint,'same');
  store.removeOutbound(key,row.id);assert.equal(await store.getOutbound(key,row.id),undefined);
  store.removeOutbound(key,row.id);
  const other={...key,endpoint:'https://other.test/conversations'};await store.prepareOutbound(other,{...row,endpoint:other.endpoint});
  assert.throws(()=>store.removeOutbound(key,row.id),/binding/);assert.ok(await store.getOutbound(other,row.id));
});
const directories: string[] = [];
after(async () => { for (const dir of directories) await rm(dir, { recursive: true, force: true }); });
async function fixture(t: test.TestContext) {
  const dir = await mkdtemp(join(tmpdir(), 'poppy-storage-'));
  directories.push(dir);
  return join(dir, 'state.db');
}
function worker(t: test.TestContext, mode: string, path: string) {
  const options:SpawnOptions={windowsHide:true,stdio:['ignore','ignore','pipe','ipc']};
  const child = fork(new URL('../test-support/storage-worker.mjs', import.meta.url), [mode,path],options);
  const exited = once(child, 'exit');
  let errors = ''; expectValue(child.stderr).on('data', b => { errors += b; });
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) { child.kill(); await once(child, 'exit'); } });
  const message = new Promise<{results?:unknown[];operationId?:string}>((resolve, reject) => { child.once('message', value=>{assert.ok(value&&typeof value==='object');resolve(value);}); child.once('error', reject); child.once('exit', code => { if (code) reject(new Error(errors)); }); });
  return { child, message, exited };
}
for (const durable of [false, true]) test(`outbound and checkpoint domain contract (${durable ? 'SQLite' : 'memory'})`, async t => {
  const store = durable ? new SqliteConversationStore(await fixture(t)) : new MemoryConversationStore();
  t.after(() => {if('close' in store)store.close();});
  const first = await store.prepareOutbound(key, row); first.request.message.text = 'mutated';
  assert.equal(expectValue((await store.getOutbound(key, row.id))).request.message.text, 'hello');
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

for (const durable of [false, true]) test(`settlement is detached, terminal and destination-bound (${durable ? 'SQLite' : 'memory'})`,async t=>{
  const store=durable?new SqliteConversationStore(await fixture(t)):new MemoryConversationStore();
  t.after(()=>{if('close' in store)store.close();});
  await store.prepareOutbound(key,row);
  const accepted:Pick<OutboundRecord,'phase'|'response'|'error'>={phase:'accepted',response:{conversation_id:'conversation',status:'idle',responder:'agent'}};
  for(const changed of [{...key,endpoint:'https://other.test/conversations'},{...key,issuer:'https://issuer.test/two'},{...key,connectionId:'other'}])await assert.rejects(store.settleOutbound(changed,row.id,accepted),/binding/);
  assert.equal(expectValue(await store.getOutbound(key,row.id)).phase,'pending');
  await store.settleOutbound(key,row.id,accepted);
  expectValue(accepted.response).status='closed';
  const saved=expectValue(await store.getOutbound(key,row.id));assert.equal(saved.phase,'accepted');assert.equal(expectValue(saved.response).status,'idle');
  expectValue(saved.response).status='closed';
  await store.settleOutbound(key,row.id,{phase:'rejected',error:{code:'conversation_closed',status:409}});
  assert.deepEqual(await store.getOutbound(key,row.id),{...row,phase:'accepted',response:{conversation_id:'conversation',status:'idle',responder:'agent'}});
  const denied={...row,id:'denied'};await store.prepareOutbound(key,denied);
  const error={code:'invalid_request',status:400};await store.settleOutbound(key,denied.id,{phase:'rejected',error});error.code='mutated';
  await store.settleOutbound(key,denied.id,accepted);
  assert.deepEqual(await store.getOutbound(key,denied.id),{...denied,phase:'rejected',error:{code:'invalid_request',status:400}});
  const checkpoint={connectionId:key.connectionId,issuer:key.issuer,conversationId:'conversation',name:'reader',cursor:'a'};
  const otherEndpoint={...key,endpoint:'https://other.test/conversations'},otherIssuer={...key,issuer:'https://issuer.test/two'};
  for(const destination of [key,otherEndpoint,otherIssuer])await store.advanceCheckpoint(destination,{...checkpoint,issuer:destination.issuer},[undefined]);
  await store.resetCheckpoint(key,checkpoint.conversationId,checkpoint.name);
  assert.equal(await store.getCheckpoint(key,checkpoint.conversationId,checkpoint.name),undefined);
  for(const destination of [otherEndpoint,otherIssuer])assert.equal(await store.getCheckpoint(destination,checkpoint.conversationId,checkpoint.name),'a');
});

test('bounded auth cleanup preserves pending, uncertain and unexpired history',async t=>{
  const store=new SqliteAuthStore(await fixture(t));t.after(()=>store.close());
  const operation=(id:string,createdAt:number,phase:OperationRecord['phase'],status:OperationRecord['status']):OperationRecord=>({
    id,createdAt,phase,status,epoch:'epoch',kind:'sign_in',connectionId:key.connectionId,connectionGeneration:0,grantId:null,grantGeneration:null,expiresAt:1000,resource:null,scopes:[],direct:null,staged:null,result:null,
  });
  const records=[operation('pending',1,'dispatched','pending'),operation('uncertain',2,'terminal','uncertain'),operation('completed',10,'terminal','completed'),operation('denied',20,'terminal','denied'),operation('boundary',50,'terminal','completed')];
  await store.transaction({issuer:key.issuer},state=>{for(const record of records)state.operations[record.id]=record;});
  for(const [before,limit] of [[NaN,1],[Infinity,1],[50,0],[50,1001],[50,1.5]])await assert.rejects(store.cleanup(before,limit),/cleanup limit/);
  assert.equal(await store.cleanup(50,1),1);
  assert.deepEqual((await store.read({operationId:'completed'})).operations,{});
  assert.ok((await store.read({operationId:'denied'})).operations.denied);
  assert.equal(await store.cleanup(50,1),1);assert.equal(await store.cleanup(50,1),0);
  for(const id of ['pending','uncertain','boundary'])assert.deepEqual((await store.read({operationId:id})).operations[id],records.find(record=>record.id===id));
  assert.deepEqual(await store.pendingOperations(undefined,100),['pending']);
});

test('two real processes prepare one durable receipt, retained after termination before dispatch', { timeout: 15000 }, async t => {
  const path = await fixture(t);
  const a = worker(t, 'prepare', path), b = worker(t, 'prepare', path);
  await Promise.all([a.message, b.message]);
  await Promise.all([a.exited, b.exited]);
  const store = new SqliteConversationStore(path); t.after(() => store.close());
  assert.deepEqual(await store.getOutbound(key, row.id), row);
  const db = new DatabaseSync(path); assert.equal(expectValue(db.prepare('SELECT count(*) AS n FROM outbound').get()).n, 1); db.close();
});

test('termination before commit rolls back auth records', { timeout: 15000 }, async t => {
  const path = await fixture(t), a = worker(t, 'before-commit', path);
  await a.message; a.child.kill(); await once(a.child, 'exit');
  const store = new SqliteAuthStore(path); t.after(() => store.close());
  assert.deepEqual((await store.read({ issuer: 'uncommitted' })).identities, {});
  await assert.rejects(store.transaction({ issuer: 'bad' }, async () => {}), /async auth transaction/);
  await assert.rejects(store.transaction({ issuer: 'bad' }, state => { Object.assign(state.identities,{bad:{userId:undefined}}); }), /non-JSON/);
});

for (const mode of ['exchange', 'rotation']) test(`live ${mode} survives another process; owner death after external effect becomes uncertain`, { timeout: 20000 }, async t => {
  const path = await fixture(t), active = worker(t, mode, path);
  const started = await active.message;
  assert.deepEqual((await worker(t, 'recover', path).message).results, []);
  active.child.kill(); await once(active.child, 'exit');
  assert.deepEqual((await worker(t, 'recover', path).message).results, [{ operationId: started.operationId, status: 'uncertain' }]);
  assert.deepEqual((await worker(t, 'recover', path).message).results, []);
  const external = new DatabaseSync(path + '.external');
  assert.equal(expectValue(external.prepare('SELECT count(*) AS n FROM effects').get()).n, 1); external.close();
});
