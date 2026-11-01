import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, createHash } from 'node:crypto';
import { compactVerify, decodeJwt, decodeProtectedHeader, importJWK } from 'jose';
import { createClientAuth, initialClientAuthState } from '../../dist/auth/client-auth.js';
import type { AuthStore, TrustedInput, ClientAuthOptions } from '../../dist/auth/client-auth.js';
import { createMetadataResolver } from '../../dist/network/discovery.js';
import { SqliteAuthStore } from '../../dist/sqlite.js';
import { PostgresAuthStore } from '../../dist/postgres.js';
import { testPool } from '../../test-support/postgres.mjs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { publicEcJwk } from '../../test-support/assertions.mjs';

async function peer(options:{mediated?:boolean;codeRequired?:boolean;input?:TrustedInput;endpoint?:string;resourceMetadata?:(request:Request)=>Response|Promise<Response>;store?:AuthStore;password?:string;sentTo?:string}={}) {
  const clientId='https://agent.example/client.json',issuer='https://auth.shop.example',endpoint=options.endpoint??'https://shop.example/conversations',redirect='https://agent.example/callback';
  const root=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),rootJwk=await publicEcJwk(root.publicKey);
  let state=initialClientAuthState(),tokenCount=0,at=1790900000000,deny=false,lose=false;let resourceReply:((request:Request)=>Response)|undefined,beforeRefresh:(()=>Promise<void>)|undefined;
  const vault=new Map<string,string>(),forms:URLSearchParams[]=[],resourceRequests:Request[]=[],revoked:string[]=[],jti=new Set<string>();
  const memory:AuthStore={async read(){return structuredClone(state);},async transaction(_selection,change){const draft=structuredClone(state),result=change(draft);state=draft;return structuredClone(result);},async pendingOperations(){return Object.values(state.operations).filter(row=>row.phase!=='terminal').map(row=>row.id);}};
  const backing=options.store??memory;
  const store:AuthStore={async read(selection){const value=await backing.read(selection);state=value;return value;},async transaction(selection,change){const result=await backing.transaction(selection,change);state=await backing.read({list:true});return result;},pendingOperations:(after,limit)=>backing.pendingOperations(after,limit)};
  const transport={async fetch(request:Request){
    if(request.url==='https://shop.example/.well-known/poppy.json')return Response.json({protocol_version:'0.3',organization:{name:'Independent OAuth Company',domain:'shop.example'},agent:{protocols:[{type:'poppy',endpoint}]},...(options.mediated?{extensions:{'mediated-sign-in':{version:'1',fields:[{name:'password',label:'Password',secret:true}],scopes:['orders:read']}}}:{})});
    if(request.url==='https://shop.example/.well-known/oauth-protected-resource')return Response.json({resource:'https://shop.example',authorization_servers:[issuer]});
    if(request.url===issuer+'/.well-known/oauth-authorization-server')return Response.json({issuer,token_endpoint:issuer+'/token',revocation_endpoint:issuer+'/revoke',authorization_endpoint:issuer+'/authorize',protected_resources:['https://shop.example'],grant_types_supported:['refresh_token','authorization_code',...(options.mediated?['https://personalagentprotocol.org/grant/mediated-sign-in']:[])]});
    if(request.url.includes('/.well-known/oauth-protected-resource/'))return options.resourceMetadata?.(request)??new Response(null,{status:404});
    if(request.url===issuer+'/token'){
      assert.equal(request.headers.get('poppy-session'),null);assert.equal(request.headers.get('dpop'),null,'Bearer-only issuer does not advertise DPoP');
      const form=new URLSearchParams(await request.text());forms.push(form);tokenCount++;if(form.get('grant_type')==='refresh_token')await beforeRefresh?.();
      const assertion=form.get('client_assertion');assert.ok(assertion);await compactVerify(assertion,await importJWK(rootJwk,'ES256'),{algorithms:['ES256']});
      const claims=decodeJwt(assertion);assert.equal(claims.iss,clientId);assert.equal(claims.sub,clientId);assert.equal(claims.aud,issuer);assert.equal(jti.has(claims.jti!),false);jti.add(claims.jti!);
      if(deny)return Response.json({error:'invalid_grant'},{status:400});
      if(form.get('grant_type')==='https://personalagentprotocol.org/grant/mediated-sign-in'){
        if(!form.has('sign_in_id')){assert.equal(form.get('password'),options.password??'private-password');assert.equal(form.get('scope'),'orders:read');if(options.codeRequired)return Response.json({error:'code_required',sign_in_id:'signin_1',sent_to:options.sentTo??'Your phone',expires_in:60},{status:400});}
        else{assert.equal(form.get('sign_in_id'),'signin_1');assert.equal(form.get('one_time_code'),'123456');assert.equal(form.has('scope'),false);assert.equal(form.has('password'),false);}
      }
      if(lose)throw new Error('synthetic lost token response');
      return Response.json({access_token:'access-'+tokenCount,token_type:'Bearer',refresh_token:'refresh-'+tokenCount,scope:'orders:read'});
    }
    if(request.url===issuer+'/revoke'){revoked.push(new URLSearchParams(await request.text()).get('token')!);return new Response(null,{status:200});}
    assert.equal(request.url,endpoint);const authorization=request.headers.get('authorization');if(authorization)assert.ok(authorization.startsWith('Bearer access-'));assert.equal(request.headers.get('dpop'),null);
    const jwt=request.headers.get('poppy-session');assert.ok(jwt);const header=decodeProtectedHeader(jwt),delegation=decodeJwt(header.pap_dlg as string);await compactVerify(header.pap_dlg as string,await importJWK(rootJwk,'ES256'));
    const key=(delegation.cnf as {jwk:Record<string,string>}).jwk;await compactVerify(jwt,await importJWK(key,'ES256'));
    const claims=decodeJwt(jwt);assert.equal(claims.ath,authorization?createHash('sha256').update(authorization.slice(7)).digest('base64url'):undefined);assert.ok(Object.values(state.connections).some(connection=>connection.sessionId===claims.sid));
    resourceRequests.push(request.clone());return resourceReply?.(request)??Response.json({ok:true});
  }};
  const config:ClientAuthOptions={namespace:'accounts',localUserId:'one-user',clientId,redirectUris:[redirect],identity:{kid:'root',publicJwk:async()=>rootJwk,sign:async input=>new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},root.privateKey,new Uint8Array(input)))},store,secrets:{async stage(secret){const ref=randomUUID();vault.set(ref,secret);return ref;},async read(ref){return vault.get(ref)??null;},async remove(ref){vault.delete(ref);}},transport,metadata:createMetadataResolver(transport,{now:()=>at}),now:()=>at,trustedInput:options.input};
  const auth=createClientAuth(config);
  const started=await auth.start('shop.example');
  const direct=async(id=started.connection.id)=>{
    const begun=await auth.beginSignIn(id,{method:'direct',scopes:['orders:read'],redirectUri:redirect,browserBinding:'trusted-browser-binding-1234567890',force:true});
    const url=new URL(begun.authorizationUrl!),callback=new URL(redirect);assert.equal(url.searchParams.has('dpop_jkt'),false,'Bearer authorization codes must not be bound to an unsent proof key');callback.search=new URLSearchParams({state:url.searchParams.get('state')!,iss:issuer,code:'independent-code'}).toString();return auth.completeSignIn({callbackUrl:callback.href,browserBinding:'trusted-browser-binding-1234567890'});
  };
  return {auth,started,direct,forms,vault,store,resourceRequests,revoked,beforeRefresh:(hook:typeof beforeRefresh)=>{beforeRefresh=hook;},newAuth:()=>createClientAuth(config),reply:(value:typeof resourceReply)=>{resourceReply=value;},raw:()=>state,tokenCount:()=>tokenCount,deny:()=>{deny=true;},lose:()=>{lose=true;},advance:(ms:number)=>{at+=ms;},send:async()=>auth.authorizedFetch(started.connection.id,new Request(endpoint,{method:'POST',body:'{}'}),await auth.target(started.connection.id))};
}

test('independent Bearer OAuth peer permits absent expiry and scope recommendations while Session signing binds the token',async()=>{
  const f=await peer();assert.equal(f.tokenCount(),0);const signed=await f.direct();assert.equal(signed.status,'completed');assert.equal(signed.connection.status,'signed_in');
  assert.equal((await f.send()).status,200);assert.equal(f.forms[0]!.get('grant_type'),'authorization_code');
  f.advance(31000);assert.equal((await f.send()).status,200);assert.equal(f.forms[1]!.get('grant_type'),'refresh_token');
});

test('mediated OAuth continuation uses trusted input and clears credential/code objects',async()=>{
  const values:Record<string,string>[]=[];const f=await peer({mediated:true,codeRequired:true,input:{async collect(request){assert.equal(request.organization.domain,'shop.example');const value:Record<string,string>=request.challenge?{code:'123456'}:{password:'private-password'};values.push(value);return value;}}});
  const first=await f.auth.beginSignIn(f.started.connection.id,{method:'mediated',scopes:['orders:read']});assert.equal(first.outcome.status,'pending');assert.ok(values.every(value=>Object.keys(value).length===0));
  const signed=await f.auth.continueSignIn(first.outcome.operationId);assert.equal(signed.status,'completed');assert.ok(values.every(value=>Object.keys(value).length===0));assert.equal((await f.send()).status,200);
});

test('failed replacement preserves the earlier grant and lost exchanges remain uncertain without replay',async()=>{
  const f=await peer({mediated:true,input:{async collect(){return {password:'private-password'};}}});const signed=await f.direct();const before=f.raw().connections[signed.connection.id]!.grantId;
  f.deny();const rejected=await f.auth.beginSignIn(signed.connection.id,{method:'mediated',scopes:['orders:read'],force:true});assert.equal(rejected.outcome.status,'denied');assert.equal(f.raw().connections[signed.connection.id]!.grantId,before);
  const lost=await peer();lost.lose();const result=await lost.direct();assert.equal(result.status,'uncertain');const calls=lost.tokenCount();await lost.auth.recover();assert.equal(lost.tokenCount(),calls);
});


test('service metadata selects exact query-bearing resources and stale challenges refresh once',async()=>{
  const endpoint='https://shop.example/conversations?tenant=a';let specific=false,fetches=0;
  const f=await peer({endpoint,resourceMetadata(request){fetches++;assert.equal(request.url,'https://shop.example/.well-known/oauth-protected-resource/conversations?tenant=a');assert.equal(request.headers.get('authorization'),null);return specific?Response.json({resource:endpoint,authorization_servers:['https://auth.shop.example']}):new Response(null,{status:404});}});
  await f.direct();assert.equal(f.forms[0]!.has('resource'),false,'404 uses a default account token');
  specific=true;let attempts=0;
  f.reply(()=>++attempts===1?new Response(null,{status:401,headers:{'www-authenticate':`Bearer error="invalid_token", resource_metadata="https://shop.example/.well-known/oauth-protected-resource/conversations?tenant=a"`}}):Response.json({ok:true}));
  assert.equal((await f.auth.authorizedFetch(f.started.connection.id,new Request(endpoint,{method:'POST',body:'original'}),await f.auth.target(f.started.connection.id))).status,200);
  assert.equal(fetches,2,'cached metadata is revalidated after the challenge');assert.equal(attempts,2);assert.equal(f.forms[1]!.get('grant_type'),'refresh_token');assert.equal(f.forms[1]!.get('resource'),endpoint);
  assert.deepEqual(await Promise.all(f.resourceRequests.map(request=>request.text())),['original','original']);
  assert.equal(decodeJwt(f.resourceRequests[1]!.headers.get('poppy-session')!).htu,'https://shop.example/conversations');
});

test('service discovery failures and foreign resource authority never downgrade to a default token',async()=>{
  for(const response of [()=>new Response('offline',{status:503}),()=>Response.json(null),()=>Response.json({resource:'https://shop.example/conversations',authorization_servers:['https://other.example']}),()=>Response.json({resource:'https://shop.example/other',authorization_servers:['https://auth.shop.example']})]){
    const f=await peer({resourceMetadata:response});await assert.rejects(f.direct());assert.equal(f.tokenCount(),0);assert.equal(f.resourceRequests.length,0);
  }
});


for(const engine of ['SQLite',...(process.env.D1_POSTGRES==='1'?['Postgres']:[])])test(`shared account grants rotate independently of Sessions and sign-out revokes all local grants (${engine})`,async t=>{
  const dir=await mkdtemp(join(tmpdir(),'poppy-shared-account-')),pool=engine==='Postgres'?testPool():undefined;
  const store=pool?new PostgresAuthStore(pool,'shared-'+randomUUID()):new SqliteAuthStore(join(dir,'auth.db'));
  t.after(async()=>{await store.close();await pool?.end();await rm(dir,{recursive:true,force:true});});
  const f=await peer({store});await f.direct();
  const a=f.started.connection.id,b=(await f.auth.start('shop.example',{accountFrom:a})).connection;
  assert.notEqual(b.sessionId,f.started.connection.sessionId);assert.equal(b.status,'signed_in');
  const before=await store.read({connectionId:b.id});assert.equal(before.connections[a]!.grantId,before.connections[b.id]!.grantId,'selectors include shared-grant peers');
  const restarted=f.newAuth();assert.equal((await restarted.authorizedFetch(b.id,new Request('https://shop.example/conversations'),await restarted.target(b.id))).status,200);
  assert.equal(f.forms.at(-1)!.get('grant_type'),'refresh_token');
  await f.direct(a);assert.equal(f.revoked.length,0,'replacing one Session grant preserves the peers still using its predecessor');
  const c=(await f.auth.start('shop.example')).connection;await f.direct(c.id);
  const signed=await store.read({account:{issuer:'https://auth.shop.example',userId:before.connections[b.id]!.userId}});assert.equal(Object.keys(signed.grants).length,3);
  const result=await restarted.signOut(b.id);assert.equal(result.cleanup,'complete');assert.equal(new Set(f.revoked).size,3,'every distinct local refresh grant is revoked');
  const after=await store.read({account:{issuer:'https://auth.shop.example',userId:before.connections[b.id]!.userId}});
  assert.equal(Object.keys(after.grants).length,0);assert.ok(Object.values(after.connections).every(row=>row.status==='signed_out'&&row.grantId===null&&Object.keys(row.slots).length===0));
  assert.equal(after.connections[b.id]!.sessionId,b.sessionId,'sign-out preserves signed-out Session continuity');
  assert.equal((await restarted.authorizedFetch(a,new Request('https://shop.example/conversations'),await restarted.target(a))).status,200);
});

test('invalid_grant and ambiguous rotation fence every Session sharing the grant',async()=>{
  for(const failure of ['invalid','lost']){
    const f=await peer();await f.direct();const a=f.started.connection.id,b=(await f.auth.start('shop.example',{accountFrom:a})).connection;
    if(failure==='invalid')f.deny();else f.lose();
    const send=()=>f.auth.authorizedFetch(b.id,new Request('https://shop.example/conversations'),{issuer:'https://auth.shop.example',endpoint:'https://shop.example/conversations'});
    if(failure==='invalid')assert.equal((await send()).status,200);else await assert.rejects(send());
    assert.equal((await f.auth.get(a))!.status,failure==='invalid'?'signed_out':'uncertain');assert.equal((await f.auth.get(b.id))!.status,failure==='invalid'?'signed_out':'uncertain');
    if(failure==='lost'){const calls=f.tokenCount();await f.auth.recover();assert.equal(f.tokenCount(),calls,'uncertain refresh is never replayed');}
  }
});


test('a replaced initiating Session cannot hide a lost rotation from its shared-grant peers',async()=>{
  const f=await peer();await f.direct();const a=f.started.connection.id,b=(await f.auth.start('shop.example',{accountFrom:a})).connection;
  let arrived!:()=>void,release!:()=>void;const entered=new Promise<void>(resolve=>{arrived=resolve;}),gate=new Promise<void>(resolve=>{release=resolve;});
  f.beforeRefresh(async()=>{arrived();await gate;});f.advance(31000);
  const refreshing=f.send().catch(error=>error);await entered;
  await f.direct(a);f.lose();release();await refreshing;
  assert.equal((await f.auth.get(a))!.status,'signed_in','replacement grant remains valid');assert.equal((await f.auth.get(b.id))!.status,'uncertain','peer cannot reuse an ambiguously rotated grant');
});


test('general service metadata accepts omitted and empty authorization-server lists',async()=>{
  for(const authorization_servers of [undefined,[]]){
    const f=await peer({resourceMetadata:()=>Response.json({resource:'https://shop.example/conversations',...(authorization_servers?{authorization_servers}:{})})});
    assert.equal((await f.direct()).status,'completed');assert.equal(f.forms[0]!.get('resource'),'https://shop.example/conversations');assert.equal((await f.send()).status,200);
  }
});

test('fresh sign-in activates a new sid while rejected replacement retains the previous Session',async()=>{
  const f=await peer(),initial=f.started.connection.sessionId;
  const first=await f.direct();assert.notEqual(first.connection.sessionId,initial);const sid=first.connection.sessionId;
  f.deny();assert.equal((await f.direct()).status,'failed');assert.equal((await f.auth.get(first.connection.id))!.sessionId,sid);
  const g=await peer();await g.direct();const before=(await g.auth.get(g.started.connection.id))!.sessionId;
  await g.auth.signOut(g.started.connection.id);assert.equal((await g.auth.get(g.started.connection.id))!.sessionId,before);
  assert.notEqual((await g.direct()).connection.sessionId,before,'a previously signed-in sid cannot carry a new opaque account');
});


test('legacy prepared exchange cancellation retains private cleanup references before pruning',async()=>{
  const f=await peer(),id=f.started.connection.id;
  const pending=await f.auth.beginSignIn(id,{scopes:['orders:read'],redirectUri:'https://agent.example/callback',browserBinding:'trusted-browser-binding-1234567890'});
  const raw=f.raw(),ref=raw.operations[pending.outcome.operationId]!.direct!.verifierRef;raw.version=2;assert.ok(f.vault.has(ref));
  const auth=f.newAuth();assert.equal((await auth.operation(pending.outcome.operationId))!.status,'cancelled');
  assert.ok(f.raw().connections[id]!.signingCleanup!.includes(ref));assert.ok(f.vault.has(ref));
  assert.equal((await auth.retryCleanup(id)).cleanup,'complete');assert.equal(f.vault.has(ref),false);
});


test('mediated activation failure keeps the staged grant recoverable without resending credentials',async()=>{
  const input={password:'private-password'},f=await peer({mediated:true,input:{async collect(){return input;}}}),transaction=f.store.transaction.bind(f.store);let fail=true;
  f.store.transaction=(selection,change)=>transaction(selection,state=>{if(fail&&Object.values(state.operations).some(row=>row.phase==='staged')){fail=false;throw new Error('activation-crash');}return change(state);});
  await assert.rejects(f.auth.beginSignIn(f.started.connection.id,{method:'mediated',scopes:['orders:read']}),/activation-crash/);assert.deepEqual(input,{});
  const staged=Object.values(f.raw().operations).find(row=>row.phase==='staged');assert.ok(staged?.staged?.refreshRef);assert.ok(f.vault.has(staged.staged.refreshRef));
  assert.equal((await f.newAuth().recover())[0]!.status,'completed');assert.equal(f.tokenCount(),1,'staged recovery performs no credential exchange');
});

test('a short secret echoed by a Company hint is never shown back or persisted',async()=>{
  const f=await peer({mediated:true,codeRequired:true,password:'a',sentTo:'Company echoes a',input:{async collect(request):Promise<Record<string,string>>{if(request.challenge){assert.equal(request.challenge.sentTo,'The company sent a one-time code.');return {code:'123456'};}return {password:'a'};}}});
  const result=await f.auth.beginSignIn(f.started.connection.id,{method:'mediated',scopes:['orders:read']});assert.equal(result.outcome.status,'pending');assert.ok(!JSON.stringify(f.raw()).includes('Company echoes a'));assert.equal((await f.auth.continueSignIn(result.outcome.operationId)).status,'completed');
});

test('approved operation context refuses authority replacement during service discovery',async()=>{
  let hold=false,entered!:()=>void,release!:()=>void;
  const ready=new Promise<void>(r=>entered=r),gate=new Promise<void>(r=>release=r);
  const f=await peer({resourceMetadata:async()=>{if(hold){entered();await gate;}return new Response(null,{status:404});}});
  await f.direct();const id=f.started.connection.id,connection=f.raw().connections[id]!;
  const expected={companyId:connection.issuer,companyName:'Company',clientId:'https://agent.example/client.json',userId:connection.userId,authority:'grant:'+connection.grantId,operations:true};
  f.advance(61000);hold=true;
  const sending=f.auth.authorizedFetch(id,new Request('https://shop.example/conversations',{method:'POST',body:'approved-request'}),await f.auth.target(id),[],expected).catch(error=>error);
  await ready;await f.auth.signOut(id);release();
  assert.equal((await sending).code,'business_owner_changed');assert.equal(f.resourceRequests.length,0,'a saved approval cannot dispatch under replacement authorization');
});
