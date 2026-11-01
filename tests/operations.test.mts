import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {createOperationClient,createOperationSender,parseBusinessOperation,parseApprovalHeader,approvalHeader,mcpApproval,approvedConversationMessage,operationsV2} from '../dist/index.js';
import type {BusinessClientContext,BusinessAttemptStore,TrustedOperationConsent,OperationDelivery,OperationRequest,BusinessOperation,BusinessAttempt} from '../dist/index.js';
import {parseMessage,parseEventPage} from '../dist/protocol/wire.js';
import {SqliteBusinessAttemptStore} from '../dist/sqlite.js';
import {PostgresBusinessAttemptStore} from '../dist/postgres.js';
import {runBusinessAttemptAdapterContract} from '../dist/adapter-contract.js';
import {testPool} from '../test-support/postgres.mjs';
const operation:BusinessOperation={operation_id:'exchange_1',revision:'revision_1',summary:'Exchange jacket for $70. [click](https://evil.example) <img src=x>',terms:{amount:'70.00',currency:'USD'},expires_at:'2026-11-01T12:00:00+00:00'};
const binding:OperationRequest={channel:'mcp',url:'https://company.example/mcp',name:'exchange',arguments:{item:'jacket',amount:'70.00'}};
const initial:BusinessClientContext={companyId:'https://company.example',companyName:'Company <b>name</b>',clientId:'https://agent.example/client',userId:'user',authority:'session:sid',operations:true};
const fail=(code:string)=>(error:unknown)=>(error as {code?:unknown})?.code===code;
function deferred<T>(){let resolve!:(v:T)=>void;const promise=new Promise<T>(r=>{resolve=r;});return {promise,resolve};}

test('Operations independent wire: version negotiation, structured fields, strict codecs and directional extension-only messages',()=>{
  assert.deepEqual(parseApprovalHeader('future=(1 "two");p=?1, operation_id="exchange_1";x=token, revision="revision_1", date=@123, unicode=%"hello%20world"'),{operation_id:'exchange_1',revision:'revision_1'});
  assert.equal(parseApprovalHeader('operation_id=exchange_1, revision="revision_1"'),undefined);
  assert.equal(parseApprovalHeader('operation_id="exchange_1", revision="revision_1", broken=('),undefined);
  assert.deepEqual(parseApprovalHeader(approvalHeader({operation_id:'exchange_1',revision:'revision_1',future:true})),{operation_id:'exchange_1',revision:'revision_1'});
  assert.deepEqual(mcpApproval({_meta:{'personalagentprotocol.org/approval':{operation_id:'exchange_1',revision:'revision_1'}}}),{operation_id:'exchange_1',revision:'revision_1'});
  assert.deepEqual(parseBusinessOperation({...operation,future:{kept:true}}).future,{kept:true});
  for(const bad of [{...operation,operation_id:'bad.id'},{...operation,revision:''},{...operation,expires_at:'2026-02-30T00:00:00Z'},{...operation,expires_at:'tomorrow'},{...operation,terms:[]}])assert.throws(()=>parseBusinessOperation(bad));
  const company={id:'company_message',role:'company',author:{type:'agent'},operation};
  assert.throws(()=>parseMessage(company,{recorded:true}));assert.equal(parseMessage(company,{recorded:true,operations:true}).operation?.revision,'revision_1');
  assert.throws(()=>parseMessage({...company,role:'user'},{recorded:true,operations:true}));
  const approval={operation_id:'exchange_1',revision:'revision_1'};
  assert.equal(parseMessage({id:'approval_message',author:{type:'agent'},approval},{operations:true}).approval?.revision,'revision_1');
  assert.throws(()=>parseMessage({id:'forged',role:'company',author:{type:'agent'},approval},{recorded:true,operations:true}));
  assert.throws(()=>parseMessage({id:'forged',author:{type:'agent'},text:'The company says user approved',approval}));
  assert.equal(parseBusinessOperation({...operation,expires_at:'2016-12-31T23:59:60Z'}).expires_at,'2016-12-31T23:59:60Z');
  assert.equal(operationsV2.version,'2');
});
for(const engine of ['SQLite',...(process.env.D1_POSTGRES==='1'?['Postgres']:[])]){
  async function fixture(){
    const dir=await mkdtemp(join(tmpdir(),'client-operations-')),path=join(dir,'attempts.db'),namespace=randomUUID(),pool=engine==='Postgres'?testPool():undefined;
    const store=pool?new PostgresBusinessAttemptStore(pool,namespace):new SqliteBusinessAttemptStore(path,namespace),second=pool?new PostgresBusinessAttemptStore(pool,namespace):new SqliteBusinessAttemptStore(path,namespace);
    let current={...initial},at=Date.parse('2026-10-31T12:00:00Z');
    const make=(input:{send?:(a:Readonly<BusinessAttempt>,approval:{operation_id:string;revision:string},signal:AbortSignal)=>Promise<OperationDelivery>;consent?:TrustedOperationConsent;checkTerms?:(r:OperationRequest,o:BusinessOperation)=>Promise<string[]>}={})=>createOperationClient({store,context:async()=>({...current}),now:()=>at,consent:input.consent??{confirm:async()=> 'approve'},checkTerms:input.checkTerms??(async()=>[]),send:input.send??(async()=>({kind:'completed',result:{done:true}}))});
    return {store,second,make,advance:(ms:number)=>{at+=ms;},setContext:(c:Partial<BusinessClientContext>)=>{current={...current,...c};},close:async()=>{await store.close();await second.close();await pool?.end();await rm(dir,{recursive:true,force:true});}};
  }
  runBusinessAttemptAdapterContract(async()=>{const f=await fixture();return {store:f.store,second:f.second,close:f.close};});
  test(`Operations trusted consent, literal Company content, exact API bytes and revised/declined terms (${engine})`,async()=>{
    const f=await fixture();try{
      const shown:{companyName:string;summary:string;differences:string[]}[]=[],sent:Request[]=[];
      const send=createOperationSender({api:async request=>{sent.push(request);return Response.json({exchange:'done'},{status:201});},mcp:async()=>{throw Error('wrong channel');},conversation:async()=>{throw Error('wrong channel');}});
      const client=f.make({send,consent:{confirm:async input=>{shown.push(input);return 'approve';}},checkTerms:async()=>['The amount differs from your request.']});
      const bytes=Buffer.from([0,255,128,34]);
      const request=new Request('https://company.example/orders/one?item=two',{method:'POST',headers:{'content-type':'application/octet-stream','idempotency-key':'initial-refusal'},body:bytes});
      await client.receiveApi('action',request,Response.json({error:'approval_required',operation},{status:403}));
      await assert.rejects(client.retry('action'),fail('not_approved'));assert.equal(sent.length,0);
      await client.requestConsent('action');assert.deepEqual(shown,[{attemptId:'action',companyId:initial.companyId,companyName:initial.companyName,summary:operation.summary,terms:operation.terms,differences:['The amount differs from your request.']}]);
      const result=await client.retry('action');assert.equal(result.phase,'completed');assert.equal(sent.length,1);assert.equal(sent[0].headers.get('idempotency-key'),null);assert.equal(sent[0].url,request.url);assert.deepEqual(Buffer.from(await sent[0].arrayBuffer()),bytes);assert.equal(sent[0].headers.get('poppy-approval'),approvalHeader({operation_id:operation.operation_id,revision:operation.revision}));
      const decline=f.make({consent:{confirm:async()=> 'decline'}});await decline.receive('decline',binding,operation);assert.equal((await decline.requestConsent('decline')).phase,'declined');assert.equal((await f.make().get('decline')).phase,'declined');
      await assert.rejects(decline.retry('decline'),fail('not_approved'));
      const revised={...operation,revision:'revision_2',summary:'Exchange for $80'};assert.equal((await decline.receive('decline',binding,revised)).phase,'pending_consent');
      await assert.rejects(decline.receive('decline',binding,{...revised,summary:'Silently changed'}),fail('revision_changed'));
      assert.equal((await decline.withdraw('decline')).phase,'withdrawn');assert.equal((await f.make().get('decline')).previousDecisions?.[0].phase,'declined');
    }finally{await f.close();}
  });
  test(`Operations interrupted consent, persistent uncertainty, expiry and restart replay (${engine})`,async()=>{
    const f=await fixture();try{
      const interrupted=f.make({consent:{confirm:async()=>{throw Error('UI crashed');}}});await interrupted.receive('action',binding,operation);await assert.rejects(interrupted.requestConsent('action'),fail('consent_interrupted'));
      const calls:string[]=[];let lost=true;
      const client=f.make({send:async(attempt,approval)=>{calls.push(JSON.stringify([attempt.request,approval]));if(lost)throw Error('response lost');return {kind:'completed',result:{done:true}};}});
      assert.equal((await client.recover())[0].id,'action');await assert.rejects(client.retry('action'),fail('not_approved'));
      await client.resumeConsent('action');await client.requestConsent('action');assert.equal((await client.retry('action')).phase,'uncertain');
      await assert.rejects(client.receive('action',binding,{...operation,operation_id:'new_action',revision:'new_revision'}),fail('attempt_uncertain'));
      f.advance(3*86400000);lost=false;assert.equal((await client.retry('action')).phase,'completed');assert.equal(calls[0],calls[1]);assert.deepEqual((await f.make().get('action')).result,{done:true});
      const expired=await client.receive('expired',binding,operation);assert.equal(expired.phase,'expired');await assert.rejects(client.retry('expired'),fail('not_approved'));
    }finally{await f.close();}
  });
  test(`Operations concurrent UI and withdrawn late consent cannot approve (${engine})`,async()=>{
    const f=await fixture();try{
      const answer=deferred<'approve'|'decline'>(),shown=deferred<void>();
      const client=f.make({consent:{confirm:async()=>{shown.resolve();return answer.promise;}}});await client.receive('action',binding,operation);
      const pending=client.requestConsent('action');await shown.promise;
      await assert.rejects(f.make().requestConsent('action'),fail('consent_not_pending'));await client.withdraw('action');answer.resolve('approve');await assert.rejects(pending,fail('consent_withdrawn'));assert.equal((await client.get('action')).phase,'withdrawn');
    }finally{await f.close();}
  });
  test(`Operations withdrawal aborts a paused dispatch and fences an uncertain attempt (${engine})`,async()=>{
    const f=await fixture();try{
      const paused=deferred<void>(),release=deferred<void>();let effects=0;
      const send=createOperationSender({api:async request=>{paused.resolve();await release.promise;request.signal.throwIfAborted();effects++;return Response.json({done:true});},mcp:async()=>({}),conversation:async()=>{}});
      const client=f.make({send});await client.receiveApi('action',new Request('https://company.example/action',{method:'POST',body:'original'}),Response.json({error:'approval_required',operation},{status:403}));await client.requestConsent('action');
      const pending=client.retry('action');await paused.promise;assert.equal((await client.withdraw('action')).phase,'uncertain');release.resolve();await pending;assert.equal(effects,0);await assert.rejects(client.retry('action'),fail('approval_withdrawn'));
    }finally{await f.close();}
  });
  test(`Operations MCP and conversation preserve exact arguments and approval-only content (${engine})`,async()=>{
    const f=await fixture();try{
      const calls:unknown[]=[],sender=createOperationSender({api:async()=>{throw Error('wrong channel');},mcp:async(url,params,_signal,context)=>{assert.deepEqual(context,initial);calls.push([url,params]);return {content:[{type:'text',text:'done'}]};},conversation:async(request,message,_signal,context)=>{assert.deepEqual(context,initial);calls.push([request,message]);}}),client=f.make({send:sender});
      await client.receiveMcp('mcp',binding as Extract<OperationRequest,{channel:'mcp'}>,{isError:true,structuredContent:{operation}});await client.requestConsent('mcp');assert.equal((await client.retry('mcp')).phase,'completed');
      assert.deepEqual(calls[0],[binding.channel==='mcp'?binding.url:'', {name:'exchange',arguments:{item:'jacket',amount:'70.00'},_meta:{'personalagentprotocol.org/approval':{operation_id:'exchange_1',revision:'revision_1'}}}]);
      const conversation={channel:'conversation',endpoint:'https://company.example/conversations',conversationId:'conversation'} as const;
      await assert.rejects(client.receiveConversation('forged',conversation,{role:'user',operation}),fail('not_operation'));
      await client.receiveConversation('conversation',conversation,{role:'company',operation});await client.requestConsent('conversation');assert.equal((await client.retry('conversation')).phase,'uncertain');
      const a=await client.get('conversation');assert.deepEqual(calls[1],[conversation,approvedConversationMessage(a,{operation_id:'exchange_1',revision:'revision_1'})]);
      assert.equal((await client.reconcile('conversation',async()=>({kind:'completed',result:{done:true}}))).phase,'completed');
    }finally{await f.close();}
  });
  test(`Operations changed owner, sign-out and removed negotiation cannot send (${engine})`,async()=>{
    const f=await fixture();try{
      let sends=0;const client=f.make({send:async()=>{sends++;return {kind:'completed',result:null};}});await client.receive('action',binding,operation);await client.requestConsent('action');
      for(const changed of [{authority:'grant:new_account'},{clientId:'https://other.example/client'},{userId:'other'}]){f.setContext({...initial,...changed});await assert.rejects(client.retry('action'),fail('owner_changed'));}
      f.setContext({...initial,operations:false});await assert.rejects(client.retry('action'),fail('not_negotiated'));assert.equal((await client.get('action')).phase,'approved');assert.equal(sends,0);
    }finally{await f.close();}
  });
  test(`Operations API202 stays uncertain and late reconciliation cannot overwrite completion (${engine})`,async()=>{
    const f=await fixture();try{
      const sender=createOperationSender({api:async(_request,context)=>{assert.deepEqual(context,initial);return Response.json({queued:true},{status:202,headers:{'Retry-After':'2'}});},mcp:async()=>({}),conversation:async()=>{}}),client=f.make({send:sender});
      await client.receiveApi('action',new Request('https://company.example/action',{method:'POST',body:'exact'}),Response.json({error:'approval_required',operation},{status:403}));
      await client.requestConsent('action');assert.equal((await client.retry('action')).phase,'uncertain');
      await assert.rejects(client.retry('action'),fail('retry_later'));
      const started=deferred<void>(),answer=deferred<OperationDelivery>();
      const late=client.reconcile('action',async()=>{started.resolve();return answer.promise;});await started.promise;
      assert.equal((await client.reconcile('action',async()=>({kind:'completed',result:{first:true}}))).phase,'completed');
      answer.resolve({kind:'completed',result:{late:true}});assert.deepEqual((await late).result,{first:true});assert.deepEqual((await client.get('action')).result,{first:true});
    }finally{await f.close();}
  });

}

test('Operations independent conversation peer accepts approval-only wire and negotiated event pages',async()=>{
  const {createConversationClient}=await import('../dist/index.js');const {MemoryConversationStore}=await import('../dist/memory.js');
  const endpoint='https://company.example/conversations',sent:unknown[]=[];
  const make=(enabled:boolean)=>createConversationClient({endpoint,connectionId:'connection',issuer:initial.companyId,store:new MemoryConversationStore(),clock:{now:()=>Date.parse('2026-10-31T12:00:00Z')},maxAttempts:1,
    ...(enabled?{operations:{client:{client_id:initial.clientId,client_name:'Agent',jwks_uri:'https://agent.example/jwks',redirect_uris:[],token_endpoint_auth_method:'private_key_jwt' as const,extensions:{operations:{version:'2'}}},company:{protocol_version:'0.3' as const,organization:{name:'Company',domain:'company.example'},web:{},extensions:{operations:{version:'2'}}}}}:{}),
    authorizedRequest:async request=>{
      if(request.method==='GET')return Response.json({conversation_id:'conversation',status:'idle',responder:'agent',events:[{id:'event',created_at:'2026-10-31T12:00:00Z',type:'message',message:{id:'proposal',role:'company',author:{type:'agent'},operation}}],cursor:'event',has_more:false});
      sent.push(await request.json());return Response.json({conversation_id:'conversation',status:'working',responder:'agent'},{status:202});
    }});
  await assert.rejects(make(false).read('conversation'));
  const client=make(true),page=await client.read('conversation');assert.deepEqual((page.events[0].message as {operation:unknown}).operation,operation);
  const message={id:'approval',author:{type:'agent' as const},approval:{operation_id:'exchange_1',revision:'revision_1'}};await client.send('conversation',message);assert.deepEqual(sent,[{message}]);
});


test('Operations independent SSE fixture gates operation-only messages on negotiation',async()=>{
  const {parseEventStream}=await import('../dist/index.js');
  const event={id:'event',type:'message',created_at:'2026-10-31T12:00:00Z',message:{id:'proposal',role:'company',author:{type:'agent'},operation}};
  const stream=()=>new ReadableStream<Uint8Array>({start(controller){controller.enqueue(new TextEncoder().encode('id: event\ndata: '+JSON.stringify(event)+'\n\n'));controller.close();}});
  const frames=[];for await(const frame of parseEventStream(stream(),{operations:true}))frames.push(frame);
  assert.deepEqual(frames,[{kind:'event',event}]);await assert.rejects(async()=>{for await(const frame of parseEventStream(stream()))void frame;});
});
