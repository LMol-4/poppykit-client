import type {ProviderOptions} from '../dist/provider.js';
import {createMetadataResolver} from '../dist/index.js';
import { expectValue, publicEcJwk } from '../test-support/assertions.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import type { ProviderRaceAction } from '../test-support/provider-worker.mjs';
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from 'jose';
import { createProvider, createProviderClient, createResultCipher, createBrowserEnrollmentClient } from '../dist/provider.js';
import { SqliteProviderStore } from '../dist/provider-sqlite.js';
import { PostgresProviderStore } from '../dist/provider-postgres.js';
import { testPool } from '../test-support/postgres.mjs';

const issuer='https://company.example/issuer', domain='company.example', clientId='https://identity.example/client.json', callbackUrl='https://identity.example/callback';
test('browser enrollment keeps verifier in request bodies and rejects foreign response identity',async()=>{
  const sent:Request[]=[];let foreign=false;
  const enrollment=createBrowserEnrollmentClient({url:'https://identity.example/enrollment',provider:'https://identity.example/v1',company:domain,installationId:'installation',transport:{async fetch(request){sent.push(request.clone());return Response.json(request.url.endsWith('/start')?{requestId:'r'.repeat(43),browserUrl:'https://identity.example/approve?id=public',expiresAt:Date.now()+300000}:{status:'ready',credential:'PRIVATE_ENROLLMENT',clientId:foreign?'https://foreign.example/client.json':clientId,callbackUrl});}}});
  const started=await enrollment.start('c'.repeat(43));assert.equal(started.requestId,'r'.repeat(43));
  const ready=await enrollment.status(started.requestId,'PRIVATE_VERIFIER');assert.equal(ready.status,'ready');
  assert.ok(sent.every(request=>!request.url.includes('PRIVATE')&&!request.headers.has('authorization')));
  assert.equal((await sent[1].json()).verifier,'PRIVATE_VERIFIER');
  foreign=true;await assert.rejects(enrollment.status(started.requestId,'PRIVATE_VERIFIER'),{code:'binding_conflict'});
  assert.throws(()=>createBrowserEnrollmentClient({url:'https://foreign.example/enroll',provider:'https://identity.example/v1',company:domain,installationId:'installation',transport:{fetch:async()=>new Response()}}));
});
async function fixture() {
  const dir=mkdtempSync(join(tmpdir(),'provider-')), path=join(dir,'provider.sqlite');
  const pool=process.env.D1_POSTGRES==='1'?testPool():undefined, namespace=(process.env.D1_NAMESPACE??'d1')+':'+path;
  const store=pool?new PostgresProviderStore(pool,namespace):new SqliteProviderStore(path);
  let at=1000000, subject='alice', allowSession=true;
  const key=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const publicJwk=await publicEcJwk(key.publicKey);
  const metadata={...createMetadataResolver({async fetch(){throw new Error('unexpected metadata fetch');}}),resolveCompany:async(d:string)=>{assert.equal(d,domain);return {url:'https://company.example/.well-known/poppy.json',document:{protocol_version:'0.2' as const,organization:{domain,name:'Generic'},web:{browser_session_endpoint:'https://company.example/join'}},authorization:{issuer,token_endpoint:issuer+'/token',revocation_endpoint:issuer+'/revoke',poppy_domains:[domain]}};}};
  const options:ProviderOptions={clientId,callbackUrl,jwksUri:'https://identity.example/jwks',clientName:'Generic provider',store,cipher:createResultCipher(randomBytes(32)),metadata,now:()=>at,
    authenticateEnrollment:async request =>request.headers.get('x-human')==='authenticated'?{subject,allowedCompanies:[domain]}:null,
    verifySession:async (b: { sessionId: string; }) =>allowSession&&b.sessionId==='owned',
    signer:{kid:'key-1',publicJwk:async()=>publicJwk,sign:async (bytes:Uint8Array) =>new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key.privateKey,new Uint8Array(bytes)))}};
  const api=createProvider(options), req=new Request('https://identity.example/v1/enroll',{headers:{'x-human':'authenticated'}});
  async function enroll(installationId='install-a'){return api.enroll(req,{version:1,installationId,idempotencyKey:randomBytes(20).toString('hex')});}
  return {api,options,store,path,dir,enroll,second:()=>pool?new PostgresProviderStore(pool,namespace):new SqliteProviderStore(path),persisted:async()=>pool?Buffer.from(JSON.stringify((await pool.query('SELECT body FROM poppy_provider.records WHERE ns=$1',[namespace])).rows)):readFileSync(path),setSubject:(v: string) =>subject=v,setTime:(v: number) =>at=v,setSession:(v: boolean) =>allowSession=v,close:async()=>{await store.close();await pool?.end();rmSync(dir,{recursive:true,force:true});}};
}
test('authenticated enrollment, visitor/issuer identity and installation isolation',async()=>{
  const f=await fixture();try{
    await assert.rejects(f.api.enroll(new Request(clientId),{version:1,installationId:'a',idempotencyKey:'key'}),{code:'unauthorized'});
    const a=await f.enroll(), b=await f.enroll('install-b');
    const identity=(credential: string,installationId: string)=>f.api.identity(credential,{version:1,installationId,domain,issuer});
    assert.deepEqual(await identity(a.credential,'install-a'),await identity(b.credential,'install-b'));
    await assert.rejects(identity(a.credential,'install-b'),{code:'unauthorized'});
    f.setSubject('bob');const c=await f.enroll('install-c');assert.notDeepEqual(await identity(a.credential,'install-a'),await identity(c.credential,'install-c'));
    const response=await f.api.handle(new Request('https://identity.example/v1/enroll',{method:'POST',headers:{'content-type':'application/json','x-human':'authenticated'},body:JSON.stringify({version:2,installationId:'a',idempotencyKey:'other'})}));assert.equal(response.status,409);assert.equal(response.headers.get('cache-control'),'no-store');
  }finally{await f.close();}
});
test('constrained signing rejects claims, purposes, companies and unverified browser sessions',async()=>{
  const f=await fixture();try{
    const a=await f.enroll(), binding={version:1,installationId:'install-a',operationId:'sign',domain,issuer,purpose:'session'};
    for(const change of [{subject:'attacker'},{audience:'https://evil.example'},{purpose:'raw'},{issuer:'https://evil.example'},{domain:'evil.example'}])await assert.rejects(f.api.begin(a.credential,{...binding,...change}));
    await f.api.begin(a.credential,binding);
    const result=await f.api.assert(a.credential,{version:1,installationId:'install-a',operationId:'sign',purpose:'session'});
    const payload=decodeJwt(result.assertion);assert.equal(payload.aud,issuer);assert.equal(payload.iss,clientId);assert.equal(expectValue(payload.exp)-expectValue(payload.iat),60);assert.ok(expectValue(payload.jti).length>=22);assert.equal(decodeProtectedHeader(result.assertion).typ,'JWT');
    await jwtVerify(result.assertion,await importJWK(await f.options.signer.publicJwk(),'ES256'),{issuer:clientId,audience:issuer,currentDate:new Date(1000000)});
    await assert.rejects(f.api.assert(a.credential,{version:1,installationId:'install-a',operationId:'sign',purpose:'client-authentication'}),{code:'binding_conflict'});
    await assert.rejects(f.api.begin(a.credential,{...binding,purpose:'browser',operationId:'browser',sessionId:'other',returnTo:'https://company.example/'}),{code:'unauthorized'});
    await assert.rejects(f.api.begin(a.credential,{...binding,purpose:'browser',operationId:'browser',sessionId:'owned',returnTo:'https://evil.example/'}),{code:'binding_conflict'});
    await f.api.begin(a.credential,{...binding,purpose:'browser',operationId:'browser',sessionId:'owned',returnTo:'https://company.example/'});
    const browser=await f.api.assert(a.credential,{version:1,installationId:'install-a',operationId:'browser',purpose:'browser'});assert.equal(decodeProtectedHeader(browser.assertion).typ,'poppy-browser+jwt');
    f.setSession(false);await assert.rejects(f.api.assert(a.credential,{version:1,installationId:'install-a',operationId:'browser',purpose:'browser'}),{code:'unauthorized'});
    await assert.rejects(f.api.takeResult(a.credential,{version:1,installationId:'install-a',operationId:'sign',issuer,sessionId:null}),{code:'binding_conflict'});
  }finally{await f.close();}
});
test('callback results encrypted, correlated, atomic, one time; restart, replay, cancel and expiry',async()=>{
  const f=await fixture();try{
    const a=await f.enroll(),b=await f.enroll('install-b'),state=randomBytes(32).toString('base64url');
    const input={version:1,installationId:'install-a',operationId:'direct',issuer,domain,purpose:'direct',sessionId:'session-a',state};
    await f.api.begin(a.credential,input);
    await assert.rejects(f.api.begin(b.credential,{...input,installationId:'install-b'}),{code:'binding_conflict'});
    const callback=`${callbackUrl}?state=${state}&iss=${encodeURIComponent(issuer)}&code=PRIVATE_CODE`;
    await assert.rejects(f.api.callback(callback.replace(encodeURIComponent(issuer),'https%3A%2F%2Fevil.example')),{code:'binding_conflict'});
    await f.api.callback(callback);await f.api.callback(callback);
    await assert.rejects(f.api.callback(callback.replace('PRIVATE_CODE','OTHER')),{code:'binding_conflict'});
    const take={version:1,installationId:'install-a',operationId:'direct',issuer,sessionId:'session-a'};
    await assert.rejects(f.api.takeResult(a.credential,{...take,sessionId:'other'}),{code:'binding_conflict'});
    await assert.rejects(f.api.takeResult(b.credential,{...take,installationId:'install-b'}),{code:'binding_conflict'});
    await assert.rejects(f.api.takeResult(a.credential,{...take,installationId:'install-b'}),{code:'unauthorized'});
    assert.equal((await f.persisted()).includes(Buffer.from('PRIVATE_CODE')),false);
    const second=f.second();try{const resumed=createProvider({...f.options,store:second});assert.equal((await resumed.takeResult(a.credential,take)).callbackUrl,callback);await assert.rejects(f.api.takeResult(a.credential,take),{code:'consumed'});await assert.rejects(f.api.callback(callback),{code:'consumed'});}finally{await second.close();}
    await f.api.begin(a.credential,{...input,operationId:'cancel',state:randomBytes(32).toString('base64url')});await f.api.cancel(a.credential,{version:1,installationId:'install-a',operationId:'cancel'});
    await assert.rejects(f.api.takeResult(a.credential,{...take,operationId:'cancel'}),{code:'canceled'});
    f.setTime(1600001);await assert.rejects(f.api.takeResult(a.credential,take),{code:'expired'});
  }finally{await f.close();}
});

test('operation retries retain original binding and expiry without extending authorization',async()=>{
  const f=await fixture();try{
    const a=await f.enroll(),state=randomBytes(32).toString('base64url'),input={version:1,installationId:'install-a',operationId:'idempotent',issuer,domain,purpose:'direct',sessionId:'owned',state};
    const started=await f.api.begin(a.credential,input);f.setTime(1100000);
    assert.deepEqual(await f.api.begin(a.credential,input),started);
    for(const change of [{sessionId:'another'},{state:randomBytes(32).toString('base64url')}])await assert.rejects(f.api.begin(a.credential,{...input,...change}),{code:'binding_conflict'});
    f.setTime(started.expiresAt);await assert.rejects(f.api.begin(a.credential,input),{code:'expired'});
  }finally{await f.close();}
});

test('expired callback tombstones retain state through grace and cleanup cannot remove live operations',async()=>{
  const f=await fixture();try{
    const a=await f.enroll(),state=randomBytes(32).toString('base64url'),input={version:1,installationId:'install-a',operationId:'old',issuer,domain,purpose:'direct',sessionId:'owned',state};
    const old=await f.api.begin(a.credential,input);
    f.setTime(old.expiresAt+29999);
    await assert.rejects(f.api.begin(a.credential,{...input,operationId:'too-soon'}),{code:'binding_conflict'});
    const liveState=randomBytes(32).toString('base64url');await f.api.begin(a.credential,{...input,operationId:'live',state:liveState});
    f.setTime(old.expiresAt+30000);
    const replacementState=randomBytes(32).toString('base64url');await f.api.begin(a.credential,{...input,operationId:'replacement',state:replacementState});
    const oldCallback=`${callbackUrl}?state=${state}&iss=${encodeURIComponent(issuer)}&code=PRIVATE`;
    await assert.rejects(f.api.callback(oldCallback),{code:'binding_conflict'});
    const replacementCallback=`${callbackUrl}?state=${replacementState}&iss=${encodeURIComponent(issuer)}&code=NEW`;assert.equal((await f.api.callback(replacementCallback)).status,'ready');
    const take={version:1,installationId:'install-a',operationId:'replacement',issuer,sessionId:'owned'};
    assert.equal((await f.api.takeResult(a.credential,take)).callbackUrl,replacementCallback);
    await assert.rejects(f.api.takeResult(a.credential,{...take,operationId:'old'}),{code:'binding_conflict'});
    assert.equal((await f.api.callback(`${callbackUrl}?state=${liveState}&iss=${encodeURIComponent(issuer)}&code=LIVE`)).status,'ready');
    assert.equal((await f.api.takeResult(a.credential,{...take,operationId:'live'})).status,'completed');
  }finally{await f.close();}
});
test('revocation races KMS signing; issued assertions remain cryptographically valid',async()=>{
  const f=await fixture();try{
    const a=await f.enroll();await f.api.begin(a.credential,{version:1,installationId:'install-a',operationId:'sign',domain,issuer,purpose:'client-authentication'});
    const input={version:1,installationId:'install-a',operationId:'sign',purpose:'client-authentication'};
    const issued=await f.api.assert(a.credential,input);
    let release!:()=>void,started!:()=>void;const ready=new Promise<void>(r=>started=r),gate=new Promise<void>(r=>release=r),sign=f.options.signer.sign;
    const racing=createProvider({...f.options,signer:{...f.options.signer,sign:async bytes=>{started();await gate;return sign(bytes);}}});
    const pending=racing.assert(a.credential,input);await ready;await f.api.revokeEnrollment(a.credential,{version:1,installationId:'install-a'});release();await assert.rejects(pending,{code:'unauthorized'});
    await jwtVerify(issued.assertion,await importJWK(await f.options.signer.publicJwk(),'ES256'),{currentDate:new Date(1000000)});
    await assert.rejects(f.api.assert(a.credential,input),{code:'unauthorized'});
    assert.equal(decodeJwt(issued.assertion).exp,1060); // Revoke is not company token revocation or JWT retraction.
  }finally{await f.close();}
});
test('bound HTTP client uses authenticated versioned handlers without raw-byte signing',async()=>{
  const f=await fixture();try{const a=await f.enroll();const transport={fetch:(req: Request) =>f.api.handle(req)};const client=createProviderClient({url:'https://identity.example/v1',domain,installationId:'install-a',credential:async()=>a.credential,transport});assert.equal((await client.identity(issuer)).clientId,clientId);const result=await client.assert({operationId:'from-sdk',issuer,purpose:'session'});assert.equal(decodeJwt(result.assertion).aud,issuer);
    const unsafe=createProvider({...f.options,publishedKeys:async()=>[{...await f.options.signer.publicJwk(),kid:'key',d:'PRIVATE_KEY'}]});const response=await unsafe.handle(new Request('https://identity.example/jwks'));assert.equal(response.status,503);assert.ok(!(await response.text()).includes('PRIVATE_KEY'));
  }finally{await f.close();}
});
test('authentication and policy precede metadata; malformed sessions never reach session hook',async()=>{
  const f=await fixture();try{
    let resolves=0,hooks=0;const original=f.options.metadata.resolveCompany;
    const api=createProvider({...f.options,metadata:{...f.options.metadata,resolveCompany:async d=>{resolves++;return original(d);}},verifySession:async()=>{hooks++;return true;}});
    const a=await f.enroll(),base={version:1,installationId:'install-a',operationId:'browser',issuer,domain,purpose:'browser',sessionId:'owned',returnTo:'https://company.example/'};
    for(const input of [{...base,installationId:'wrong'},{...base,domain:'evil.example'}])await assert.rejects(api.begin(a.credential,input));
    await assert.rejects(api.identity('invalid',{version:1,installationId:'install-a',issuer,domain}));
    for(const sessionId of [{},[],false,1,'', 'x'.repeat(2049)]){
      const response=await api.handle(new Request('https://identity.example/v1/begin',{method:'POST',headers:{'content-type':'application/json',authorization:`Bearer ${a.credential}`},body:JSON.stringify({...base,sessionId})}));assert.equal(response.status,409);
    }
    assert.equal(resolves,0);assert.equal(hooks,0);
  }finally{await f.close();}
});
test('tombstone flooding cannot hide quota records or ciphertext from revocation',async()=>{
  const f=await fixture();try{
    const a=await f.enroll(),base={version:1,installationId:'install-a',domain,issuer,purpose:'session'};
    // Install retained tombstones through the same store contract to reach the hard cap quickly.
    await f.store.transaction({kind:'begin',enrollmentId:a.enrollmentId,operationId:'seed',issuer,at:1000000},tx=>{for(let i=0;i<999;i++)tx.put('operation',`${a.enrollmentId}:a${i.toString().padStart(4,'0')}`,{binding:{stateHash:null},expiresAt:1600000,status:'canceled',result:null});});
    const state=randomBytes(32).toString('base64url');await f.api.begin(a.credential,{...base,operationId:'\uffffx',purpose:'direct',sessionId:'owned',state});
    await f.api.callback(`${callbackUrl}?state=${state}&iss=${encodeURIComponent(issuer)}&code=PRIVATE`);
    await assert.rejects(f.api.begin(a.credential,{...base,operationId:'zz-overflow'}),{code:'rate_limited'});
    await f.api.revokeEnrollment(a.credential,{version:1,installationId:'install-a'});
    const rows=await f.store.transaction({kind:'revoke',enrollmentId:a.enrollmentId},tx=>tx.list('operation',`${a.enrollmentId}:`,1001));assert.equal(rows.length,1000);assert.ok(rows.every(row=>row.value.result===null&&row.value.status==='canceled'));
  }finally{await f.close();}
});
test('real processes atomically race result consumption and revoke against callback',async()=>{
  const f=await fixture();try{
    const a=await f.enroll(),state=randomBytes(32).toString('base64url'),base={version:1,installationId:'install-a',operationId:'race',issuer,domain,purpose:'direct',sessionId:'owned',state};await f.api.begin(a.credential,base);
    const callback=`${callbackUrl}?state=${state}&iss=${encodeURIComponent(issuer)}&code=PRIVATE_RACE`;await f.api.callback(callback);
    const worker=(action:ProviderRaceAction)=>new Promise<{status?:string;error?:string}>((resolve,reject)=>{
      const child=spawn(process.execPath,[fileURLToPath(new URL('../test-support/provider-worker.mjs',import.meta.url))],{env:{...process.env,DB_PATH:f.path,TASK:JSON.stringify(action)},windowsHide:true});let out='',err='';child.stdout.on('data',d=>out+=d);child.stderr.on('data',d=>err+=d);child.on('error',reject);child.on('close',code=>{try{
        assert.equal(code,0,err);const result:unknown=JSON.parse(out);assert.ok(result&&typeof result==='object');
        if('status' in result){assert.ok(typeof result.status==='string');resolve({status:result.status});}
        else{assert.ok('error' in result&&typeof result.error==='string');resolve({error:result.error});}
      }catch(e){reject(e);}});
    });
    const take:ProviderRaceAction={action:'take',credential:a.credential,body:{version:1,installationId:'install-a',operationId:'race',issuer,sessionId:'owned'}};
    const results=await Promise.all([worker(take),worker(take)]);assert.equal(results.filter(r=>r.status==='completed').length,1);assert.equal(results.filter(r=>r.error==='consumed').length,1);
    const secondState=randomBytes(32).toString('base64url');await f.api.begin(a.credential,{...base,operationId:'race2',state:secondState});
    await Promise.all([worker({action:'callback',callback:`${callbackUrl}?state=${secondState}&iss=${encodeURIComponent(issuer)}&code=PRIVATE`}),worker({action:'revoke',credential:a.credential,body:{version:1,installationId:'install-a'}})]);
    assert.ok((await f.store.transaction({kind:'revoke',enrollmentId:a.enrollmentId},tx=>tx.list('operation',`${a.enrollmentId}:`,1000))).every(row=>row.value.result===null));
  }finally{await f.close();}
});

test('Unicode operation IDs retain bindings, count towards quotas and clear ciphertext on revoke',async()=>{
  const f=await fixture();try{
    const a=await f.enroll(),states=[randomBytes(32).toString('base64url'),randomBytes(32).toString('base64url')];
    for(const [i,operationId] of ['\uffffx','😀'].entries()){
      const input={version:1,installationId:'install-a',operationId,domain,issuer,purpose:'direct',sessionId:'owned',state:states[i]};
      const started=await f.api.begin(a.credential,input);assert.deepEqual(await f.api.begin(a.credential,input),started);
      await f.api.callback(`${callbackUrl}?state=${states[i]}&iss=${encodeURIComponent(issuer)}&code=PRIVATE_UNICODE`);
    }
    for(let i=0;i<8;i++)await f.api.begin(a.credential,{version:1,installationId:'install-a',operationId:'ascii-'+i,domain,issuer,purpose:'session'});
    await assert.rejects(f.api.begin(a.credential,{version:1,installationId:'install-a',operationId:'overflow',domain,issuer,purpose:'session'}),{code:'rate_limited'});
    await f.api.revokeEnrollment(a.credential,{version:1,installationId:'install-a'});
    const rows=await f.store.transaction({kind:'revoke',enrollmentId:a.enrollmentId},tx=>tx.list('operation',`${a.enrollmentId}:`,1001));
    assert.equal(rows.length,10);assert.ok(rows.every(row=>row.value.result===null&&row.value.status==='canceled'));
  }finally{await f.close();}
});
