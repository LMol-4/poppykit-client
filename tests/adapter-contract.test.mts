import { mkdtemp,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { runClientConversationAdapterContract,runProviderAdapterContract } from '../dist/adapter-contract.js';
import { SqliteConversationStore } from '../dist/sqlite.js';
import { SqliteProviderStore } from '../dist/provider-sqlite.js';
import { PostgresConversationStore } from '../dist/postgres.js';
import { PostgresProviderStore } from '../dist/provider-postgres.js';
import { MemoryConversationStore } from '../dist/memory.js';
import { testPool } from '../test-support/postgres.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { adaptLegacyProviderStore } from '../dist/provider.js';
test('legacy local provider migration rejects thenables before the legacy store commits',async()=>{
  let commits=0;
  const adapter=adaptLegacyProviderStore({transaction(action){const result=action({get:()=>undefined,put:()=>{},remove:()=>{},list:()=>[]});commits++;return result;}});
  const selection={kind:'enroll',subjectHash:'subject',requestHash:'request'} as const;
  await assert.rejects(adapter.transaction(selection,async()=>({value:1})),/synchronous/);assert.equal(commits,0);
  assert.deepEqual(await adapter.transaction(selection,()=>({value:1})),{value:1});assert.equal(commits,1);
});

runClientConversationAdapterContract(async()=>{const store=new MemoryConversationStore();return {store,second:store,close:async()=>{}};});
runClientConversationAdapterContract(async()=>{
  const dir=await mkdtemp(join(tmpdir(),'poppy-client-contract-')),path=join(dir,'db.sqlite');
  const store=new SqliteConversationStore(path),second=new SqliteConversationStore(path);
  return {store,second,close:async()=>{store.close();second.close();await rm(dir,{recursive:true});}};
});
runProviderAdapterContract(async()=>{
  const dir=await mkdtemp(join(tmpdir(),'poppy-provider-contract-')),path=join(dir,'db.sqlite');
  const store=new SqliteProviderStore(path),second=new SqliteProviderStore(path);
  return {store,second,close:async()=>{store.close();second.close();await rm(dir,{recursive:true});}};
});
if(process.env.D1_POSTGRES==='1') {
  runClientConversationAdapterContract(async()=>{const pool=testPool(),namespace=(process.env.D1_NAMESPACE??'d1')+':'+randomUUID();const store=new PostgresConversationStore(pool,namespace),second=new PostgresConversationStore(pool,namespace);return {store,second,close:async()=>{await store.close();await second.close();await pool.end();}};});
  runProviderAdapterContract(async()=>{const pool=testPool(),namespace=(process.env.D1_NAMESPACE??'d1')+':'+randomUUID();const store=new PostgresProviderStore(pool,namespace),second=new PostgresProviderStore(pool,namespace);return {store,second,close:async()=>{await store.close();await second.close();await pool.end();}};});
}
