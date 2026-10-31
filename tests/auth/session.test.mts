import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { calculateJwkThumbprint, compactVerify, decodeJwt, decodeProtectedHeader, importJWK } from 'jose';
import { createClientAuth, initialClientAuthState } from '../../dist/auth/client-auth.js';
import type { AuthStore, SecretStore } from '../../dist/auth/client-auth.js';
import { createMetadataResolver } from '../../dist/network/discovery.js';
import { publicEcJwk } from '../../test-support/assertions.mjs';

async function fixture(operations?: {company:string;client:string}) {
  const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),jwk=await publicEcJwk(pair.publicKey);
  const clientId='https://independent-agent.example/client.json',endpoint='https://shop.example/conversations';
  let state=initialClientAuthState(),at=1790900000000,refuse=0,alwaysRefuse=false,failRemoval:string|null=null;
  const vault=new Map<string,string>(),requests:Request[]=[],jtis=new Set<string>();
  const store:AuthStore={async read(){return structuredClone(state);},async transaction(_selection,change){const draft=structuredClone(state),result=change(draft);state=draft;return structuredClone(result);},async pendingOperations(){return [];}};
  const secrets:SecretStore={async stage(secret){const ref=randomUUID();vault.set(ref,secret);return ref;},async read(ref){return vault.get(ref)??null;},async remove(ref){if(ref===failRemoval)throw new Error('synthetic vault deletion failure');vault.delete(ref);}};
  const transport={async fetch(request:Request){
    if(request.url===clientId)return Response.json({client_id:clientId,client_name:'Independent agent',jwks_uri:'https://independent-agent.example/jwks',redirect_uris:[],token_endpoint_auth_method:'private_key_jwt',...(operations?{extensions:{operations:{version:operations.client}}}:{})});
    if(request.url==='https://shop.example/.well-known/poppy.json')return Response.json({...(operations?{extensions:{operations:{version:operations.company}}}:{}),protocol_version:'0.3',organization:{name:'Independent issuerless Company',domain:'shop.example'},agent:{protocols:[{type:'poppy',endpoint}]},web:{browser_session_endpoint:'https://shop.example/browser?route=1'}});
    if(request.url==='https://shop.example/.well-known/oauth-protected-resource')return new Response(null,{status:404});
    assert.ok([endpoint,'https://shop.example/browser/authorize?route=1'].includes(request.url));assert.equal(request.headers.get('authorization'),null);assert.equal(request.headers.get('dpop'),null);assert.equal(request.headers.get('cookie'),null);
    const jwt=request.headers.get('poppy-session');assert.ok(jwt);const header=decodeProtectedHeader(jwt),delegation=header.pap_dlg;assert.equal(typeof delegation,'string');
    const delegated=await compactVerify(delegation as string,await importJWK(jwk,'ES256'),{algorithms:['ES256']});
    const payload=JSON.parse(new TextDecoder().decode(delegated.payload));assert.equal(payload.iss,clientId);assert.deepEqual(Object.keys(payload).sort(),['cnf','exp','iat','iss','jti']);assert.equal(payload.iat%1800,0);assert.equal(payload.exp,payload.iat+3600);
    assert.equal(header.typ,'poppy-session+jwt');assert.equal(header.kid,await calculateJwkThumbprint(payload.cnf.jwk));
    await compactVerify(jwt,await importJWK(payload.cnf.jwk,'ES256'),{algorithms:['ES256']});
    const claims=decodeJwt(jwt);assert.equal(claims.aud,'https://shop.example');assert.equal(claims.htm,'POST');assert.equal(claims.htu,request.url.split('?')[0]);assert.equal(claims.ath,undefined);
    assert.equal(jtis.has(claims.jti!),false);jtis.add(claims.jti!);requests.push(request.clone());
    if(alwaysRefuse||refuse-->0)return Response.json({error:'invalid_session'},{status:400});
    if(request.url.includes('/browser/authorize')){assert.deepEqual(Object.keys(await request.clone().json()),['code']);return new Response(null,{status:204});}
    return Response.json({ok:true});
  }};
  const auth=createClientAuth({namespace:'sessions',localUserId:'local-user',clientId,redirectUris:[],store,secrets,transport,metadata:createMetadataResolver(transport,{now:()=>at}),now:()=>at,
    identity:{kid:'root',publicJwk:async()=>jwk,sign:async input=>new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},pair.privateKey,new Uint8Array(input)))}});
  const start=await auth.start('shop.example');
  const send=async(id=start.connection.id)=>auth.authorizedFetch(id,new Request(endpoint,{method:'POST',body:'{}'}),await auth.target(id));
  return {auth,start,send,requests,vault,raw:()=>state,advance:(ms:number)=>{at+=ms;},refuseOnce:()=>{refuse=1;},refuseAlways:()=>{alwaysRefuse=true;},failRemoval:(ref:string|null)=>{failRemoval=ref;}};
}

test('issuerless Sessions sign independently verified requests without acquiring OAuth tokens',async()=>{
  const f=await fixture();assert.equal(f.requests.length,0);assert.equal(f.start.connection.issuer,'https://shop.example');
  await Promise.all([f.send(),f.send()]);assert.equal(f.requests.length,2);
  const first=decodeJwt(f.requests[0]!.headers.get('poppy-session')!),second=decodeJwt(f.requests[1]!.headers.get('poppy-session')!);
  assert.equal(first.sid,second.sid);assert.equal(first.sub,second.sub);assert.notEqual(first.jti,second.jti);
  const other=await f.auth.start('shop.example');await f.send(other.connection.id);
  const third=decodeJwt(f.requests[2]!.headers.get('poppy-session')!);assert.equal(third.sub,first.sub);assert.notEqual(third.sid,first.sid);
});

test('invalid_session restarts once with fresh signatures and then returns a repeated refusal',async()=>{
  const f=await fixture();f.refuseOnce();assert.equal((await f.send()).status,200);assert.equal(f.requests.length,2);
  assert.notEqual(decodeJwt(f.requests[0]!.headers.get('poppy-session')!).sid,decodeJwt(f.requests[1]!.headers.get('poppy-session')!).sid);
  f.refuseAlways();assert.equal((await f.send()).status,400);assert.equal(f.requests.length,4,'one restart per invocation, no retry loop');
});

test('failed old-key deletion retains cleanup references and never deletes the committed replacement',async()=>{
  const f=await fixture();await f.send();const old=f.raw().connections[f.start.connection.id]!.sessionSigning!;
  f.failRemoval(old.keyRef);f.advance(3600001);assert.equal((await f.send()).status,200);
  const current=f.raw().connections[f.start.connection.id]!;assert.notEqual(current.sessionSigning!.keyRef,old.keyRef);assert.ok(f.vault.has(current.sessionSigning!.keyRef));
  assert.ok(current.signingCleanup!.includes(old.keyRef));assert.equal((await f.send()).status,200);
  f.failRemoval(null);await f.send();assert.equal(f.raw().connections[current.id]!.signingCleanup,undefined);assert.equal(f.vault.has(old.keyRef),false);
});

test('anonymous Sessions have separate identity and signing keys and become unusable when ended',async()=>{
  const f=await fixture();await f.send();const regular=decodeJwt(f.requests[0]!.headers.get('poppy-session')!);
  const anonymous=await f.auth.start('shop.example',{anonymous:true});await f.send(anonymous.connection.id);
  const privateClaims=decodeJwt(f.requests[1]!.headers.get('poppy-session')!);assert.notEqual(privateClaims.sub,regular.sub);
  const privateHeader=decodeProtectedHeader(f.requests[1]!.headers.get('poppy-session')!);assert.notEqual(privateHeader.kid,decodeProtectedHeader(f.requests[0]!.headers.get('poppy-session')!).kid);
  await f.auth.signOut(anonymous.connection.id);await assert.rejects(f.send(anonymous.connection.id),{code:'disconnected'});
  assert.equal(f.raw().connections[anonymous.connection.id]!.userId,'');
});


test('browser joining authorizes the own-browser code in a signed agent request before code-only submission',async()=>{
  const f=await fixture(),events:string[]=[];
  await f.auth.joinBrowser(f.start.connection.id,'https://shop.example/account',{kind:'agent-controlled',async loadJoinForm(url){assert.equal(url,'https://shop.example/browser?route=1');events.push('load');return {code:'own_browser_code'};},async postForm(input){assert.equal(f.requests.length,1);assert.equal(f.requests[0]!.url,'https://shop.example/browser/authorize?route=1');assert.deepEqual(input.fields,{code:'own_browser_code'});events.push('post');assert.equal(input.validateRedirect(303,'/'),'https://shop.example/');assert.throws(()=>input.validateRedirect(307,'/'));assert.throws(()=>input.validateRedirect(303,'https://other.example/'));},async navigate(url){assert.equal(url,'https://shop.example/account');events.push('navigate');}});
  assert.deepEqual(events,['load','post','navigate']);
});

test('browser authorization bounds Session recovery before submitting its one own-browser code',async()=>{
  const f=await fixture();f.refuseOnce();let submitted=0,loaded=0;
  const controller={kind:'agent-controlled' as const,async loadJoinForm(){return {code:'own_browser_code_'+(++loaded)};},async postForm(){submitted++;},async navigate(){}};
  await f.auth.joinBrowser(f.start.connection.id,'https://shop.example/account',controller);
  assert.equal(f.requests.length,2);assert.equal(loaded,1);assert.equal(submitted,1);
  assert.notEqual((await f.auth.get(f.start.connection.id))!.sessionId,f.start.connection.sessionId);
});

test('businessContext binds verified metadata and keeps authentication work separate',async()=>{
  const f=await fixture({company:'2',client:'2'}),c=await f.auth.businessContext(f.start.connection.id);
  assert.equal(c.operations,true);assert.equal(c.companyId,'https://shop.example');assert.equal(c.authority,'session:'+f.start.connection.sessionId);assert.equal(c.userId,f.raw().connections[f.start.connection.id].userId);
  const unsupported=await fixture({company:'2',client:'1'});assert.equal((await unsupported.auth.businessContext(unsupported.start.connection.id)).operations,false);
});
