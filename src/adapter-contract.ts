import test from 'node:test';
import assert from 'node:assert/strict';
import type { ConversationStore } from './conversation-store.js';
import type { OutboundRecord } from './conversation.js';
import type { ProviderStore } from './provider.js';
export type ClientConversationAdapterFixture = () => Promise<{ store: ConversationStore; second: ConversationStore; close(): Promise<void> }>;
export type ProviderAdapterFixture = () => Promise<{ store: ProviderStore; second: ProviderStore; close(): Promise<void> }>;

/** Run against two handles sharing a fresh namespace; real engine/process tests remain the host's responsibility. */
export function runClientConversationAdapterContract(fixture: ClientConversationAdapterFixture): void {
  test('client adapter contract: atomic receipt preparation, terminal settlement and checkpoint compare-and-swap',async()=>{
    const f=await fixture();
    try {
      const key={connectionId:'contract',issuer:'https://issuer.example/one',endpoint:'https://company.example/conversations'};
      const row:OutboundRecord={...key,id:'message',fingerprint:'original',phase:'pending',target:null,request:{message:{id:'message',sender:'agent',text:'hello'}}};
      const saved=await Promise.all([f.store.prepareOutbound(key,row),f.second.prepareOutbound(key,{...row,fingerprint:'changed'})]);
      assert.equal(saved[0].fingerprint,saved[1].fingerprint);
      saved[0].request.message.text='mutated';assert.equal((await f.second.getOutbound(key,row.id))?.request.message.text,'hello');
      await f.store.settleOutbound(key,row.id,{phase:'accepted',response:{conversation_id:'conversation',status:'idle',responder:'agent'}});
      await f.second.settleOutbound(key,row.id,{phase:'rejected',error:{code:'invalid_request',status:400}});
      assert.equal((await f.store.getOutbound(key,row.id))?.phase,'accepted');
      await assert.rejects(f.store.settleOutbound({...key,endpoint:'https://other.example/conversations'},row.id,{phase:'accepted'}));
      assert.equal(await f.store.getOutbound({...key,issuer:'https://issuer.example/two'},row.id),undefined);
      const checkpoint={connectionId:key.connectionId,issuer:key.issuer,conversationId:'conversation',name:'consumer',cursor:'one'};
      await Promise.all([f.store.advanceCheckpoint(key,checkpoint,[undefined]),f.second.advanceCheckpoint(key,{...checkpoint,cursor:'two'},[undefined])]);
      const current=await f.store.getCheckpoint(key,'conversation','consumer');assert.ok(current==='one'||current==='two');
      await f.second.advanceCheckpoint(key,{...checkpoint,cursor:'stale'},[undefined]);assert.equal(await f.store.getCheckpoint(key,'conversation','consumer'),current);
    } finally {await f.close();}
  });
}

export function runProviderAdapterContract(fixture: ProviderAdapterFixture): void {
  test('provider adapter contract: capacity races, detached results, rollback and selection boundaries',async()=>{
    const f=await fixture(),selection={kind:'enroll',subjectHash:'subject',requestHash:'request'} as const;
    try {
      await Promise.all(Array.from({length:10},(_,i)=>(i%2?f.store:f.second).transaction(selection,tx=>{tx.put('capacity','enrollments',{count:(tx.get('capacity','enrollments')?.count??0)+1});})));
      const result=await f.store.transaction(selection,tx=>tx.get('capacity','enrollments'));
      assert.equal(result?.count,10);result!.count=999;
      await assert.rejects(f.store.transaction(selection,tx=>{tx.put('capacity','enrollments',{count:0});throw new Error('rollback');}),/rollback/);
      await assert.rejects(f.store.transaction(selection,async tx=>{tx.put('capacity','enrollments',{count:0});}),/synchronous/);
      await assert.rejects(f.store.transaction(selection,tx=>tx.get('enrollment','foreign')),/outside selection/);
      assert.equal((await f.second.transaction(selection,tx=>tx.get('capacity','enrollments')))?.count,10);
    } finally {await f.close();}
  });
}
