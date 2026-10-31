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
import type { PostgresConnection } from '../dist/provider-postgres.js';
import { testPool } from '../test-support/postgres.mjs';

const issuer='https://company.example/issuer', domain='company.example', clientId='https://identity.example/client.json', callbackUrl='https://identity.example/callback';
test('Direct custody rejects absent/malformed keys and incompatible saved callbacks', async () => {
  const f = await fixture();
  try {
    const a = await f.enroll(), state = randomBytes(32).toString('base64url');
    const input = { version: 1, installationId: 'install-a', operationId: 'legacy', domain, issuer, purpose: 'direct', state, sessionId: 'local-id' };
    for (const sessionKey of [undefined, '', 'short', ['k'.repeat(43)]]) await assert.rejects(f.api.begin(a.credential, { ...input, sessionKey }), { code: 'binding_conflict' });
    await f.api.begin(a.credential, { ...input, sessionKey: 'k'.repeat(43) });
    await f.store.transaction({ kind: 'operation', enrollmentId: a.enrollmentId, operationId: input.operationId }, tx => {
      const key = `${a.enrollmentId}:${input.operationId}`, op = tx.get('operation', key)!;
      delete op.binding.sessionKey; tx.put('operation', key, op);
    });
    const callback = `${callbackUrl}?state=${state}&iss=${encodeURIComponent(issuer)}&code=PRIVATE`;
    await assert.rejects(f.api.callback(callback), { code: 'binding_conflict' });
    await assert.rejects(f.api.takeResult(a.credential, { version: 1, installationId: 'install-a', operationId: input.operationId, issuer, sessionKey: 'k'.repeat(43) }), { code: 'binding_conflict' });
  } finally { await f.close(); }
});
test('Direct custody records an explicit unbound OAuth code without accepting an absent legacy binding',async()=>{
  const f=await fixture();try{
    const a=await f.enroll(),state=randomBytes(32).toString('base64url'),input={version:1,installationId:'install-a',operationId:'unbound',domain,issuer,purpose:'direct',state,sessionKey:null};
    await f.api.begin(a.credential,input);const callback=`${callbackUrl}?state=${state}&iss=${encodeURIComponent(issuer)}&code=PRIVATE_UNBOUND`;await f.api.callback(callback);
    const take={version:1,installationId:'install-a',operationId:'unbound',issuer,sessionKey:null};
    await assert.rejects(f.api.takeResult(a.credential,{...take,sessionKey:'k'.repeat(43)}),{code:'binding_conflict'});
    assert.equal((await f.api.takeResult(a.credential,take)).callbackUrl,callback);await assert.rejects(f.api.takeResult(a.credential,take),{code:'consumed'});
  }finally{await f.close();}
});
test('HTTP decoding preserves split Unicode and rejects malformed, truncated and oversized bytes before enrollment', async () => {
  const f = await fixture();
  try {
    let calls = 0;
    const api = createProvider({ ...f.options, authenticateEnrollment: async request => { calls++; return f.options.authenticateEnrollment(request); } });
    const post = (action: string, bytes: Uint8Array, credential = '') => api.handle(new Request(`https://identity.example/v1/${action}`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-human': 'authenticated', authorization: `Bearer ${credential}` },
      body: new ReadableStream({ start(controller) { for (const byte of bytes) controller.enqueue(Uint8Array.of(byte)); controller.close(); } }), duplex: 'half',
    } as RequestInit));
    const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
    for (const bytes of [Uint8Array.of(0xc3, 0x28), Uint8Array.of(0xe2, 0x98), new Uint8Array(16385).fill(32)]) {
      const response = await post('enroll', bytes); assert.equal(response.status, 409); assert.deepEqual(await response.json(), { error: 'binding_conflict' });
    }
    assert.equal(calls, 0);
    const installationId = 'device-☘😀', operationId = 'op-☘😀';
    const response = await post('enroll', encode({ version: 1, installationId, idempotencyKey: 'split-utf8' }));
    assert.equal(response.status, 200); const enrollment = await response.json();
    assert.equal(calls, 1);
    const begun = await post('begin', encode({ version: 1, installationId, operationId, domain, issuer, purpose: 'client-authentication' }), enrollment.credential);
    assert.equal(begun.status, 200);
    assert.ok((await f.api.assert(enrollment.credential, { version: 1, installationId, operationId, purpose: 'client-authentication' })).assertion);
  } finally { await f.close(); }
});
test('independent HTTP success and denial callbacks ignore unknown fields while preserving recognized bindings', async () => {
  const f = await fixture();
  try {
    const enrollment = await f.enroll();
    for (const denied of [false, true]) {
      const state = randomBytes(32).toString('base64url'), operationId = `oauth-${denied}`;
      await f.api.begin(enrollment.credential, { version: 1, installationId: 'install-a', operationId, domain, issuer, purpose: 'direct', sessionKey: 'k'.repeat(43), sessionId: 'owned', state });
      const callback = new URL(callbackUrl);
      callback.search = new URLSearchParams({ state, iss: issuer, ...(denied ? { error: 'access_denied', error_description: 'PRIVATE_DETAIL', error_uri: 'https://company.example/error' } : { code: 'PRIVATE_CODE' }), extra: 'ignored' }).toString();
      for (const bad of [callback.href + '&code=duplicate', callback.href + '&error=duplicate', callback.href + '&state=duplicate', callback.href.replace(encodeURIComponent(issuer), 'https%3A%2F%2Fforeign.example')]) {
        assert.equal((await f.api.handle(new Request(bad))).status, 409);
      }
      assert.equal((await f.api.handle(new Request(callback))).status, 200);
      const result = await f.api.takeResult(enrollment.credential, { version: 1, installationId: 'install-a', operationId, issuer, sessionKey: 'k'.repeat(43), sessionId: 'owned' });
      assert.equal(result.callbackUrl, callback.href);
    }
  } finally { await f.close(); }
});
test('provider client classifies malformed JSON without exposing its contents',async()=>{
  const client=createProviderClient({url:'https://identity.example/v1',domain,installationId:'test',credential:async()=> 'PRIVATE_CREDENTIAL',transport:{fetch:async()=>new Response('PRIVATE_NOT_JSON',{status:200})}});
  await assert.rejects(client.identity(issuer),error=>{assert.equal((error as {code:string}).code,'invalid_response');assert.ok(!String(error).includes('PRIVATE'));return true;});
});
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
  const metadata={...createMetadataResolver({async fetch(){throw new Error('unexpected metadata fetch');}}),resolveCompany:async(d:string)=>{assert.equal(d,domain);return {url:'https://company.example/.well-known/poppy.json',document:{protocol_version:'0.3' as const,organization:{domain,name:'Generic'},web:{browser_session_endpoint:'https://company.example/join'}},authorization:{issuer,token_endpoint:issuer+'/token',revocation_endpoint:issuer+'/revoke',protected_resources:[`https://${domain}`],grant_types_supported:['urn:ietf:params:oauth:grant-type:jwt-bearer','refresh_token']}};}};
  const options:ProviderOptions={clientId,callbackUrl,jwksUri:'https://identity.example/jwks',clientName:'Generic provider',store,cipher:createResultCipher(randomBytes(32)),metadata,now:()=>at,
    authenticateEnrollment:async request =>request.headers.get('x-human')==='authenticated'?{subject,allowedCompanies:[domain]}:null,
    signer:{kid:'key-1',publicJwk:async()=>publicJwk,sign:async (bytes:Uint8Array) =>new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key.privateKey,new Uint8Array(bytes)))}};
  const api=createProvider(options), req=new Request('https://identity.example/v1/enroll',{headers:{'x-human':'authenticated'}});
  async function enroll(installationId='install-a'){return api.enroll(req,{version:1,installationId,idempotencyKey:randomBytes(20).toString('hex')});}
  return {api,options,store,path,dir,pool,namespace,enroll,second:()=>pool?new PostgresProviderStore(pool,namespace):new SqliteProviderStore(path),persisted:async()=>pool?Buffer.from(JSON.stringify((await pool.query('SELECT body FROM poppy_provider.records WHERE ns=$1',[namespace])).rows)):readFileSync(path),setSubject:(v: string) =>subject=v,setTime:(v: number) =>at=v,setSession:(v: boolean) =>allowSession=v,close:async()=>{await store.close();await pool?.end();rmSync(dir,{recursive:true,force:true});}};
}
if (process.env.D1_POSTGRES === '1') test('provider explicitly enlists a separate host transaction and rolls back delivery without pool fallback', async () => {
  const f = await fixture(), ownerPool = testPool();
  assert.ok(f.pool);
  const unavailablePool = new Proxy(f.pool, { get(target, property, receiver) {
    if (property === 'connect') return () => { throw new Error('provider pool is unavailable'); };
    return Reflect.get(target, property, receiver);
  } });
  const participant = new PostgresProviderStore(unavailablePool, f.namespace);
  const provider = createProvider({ ...f.options, store: participant });
  let escaped: Promise<unknown> | undefined, release!: () => void, expiredHandle: PostgresConnection | undefined;
  const host = async <T,>(action: (connection: PostgresConnection) => Promise<T>): Promise<T> => {
    const client = await ownerPool.connect(); let active = true;
    const connection: PostgresConnection = { query: async (sql, values) => {
      if (!active) throw new Error('expired host transaction');
      return client.query(sql, values);
    } };
    try { await client.query('BEGIN'); const result = await action(connection); await client.query('COMMIT'); return result; }
    catch (error) { await client.query('ROLLBACK'); throw error; }
    finally { active = false; client.release(); }
  };
  const marker = (connection: PostgresConnection, id: string) => connection.query('INSERT INTO poppy_provider.records(ns,kind,id,body) VALUES($1,$2,$3,$4)', [f.namespace, 'host-receipt', id, '{}']);
  try {
    const a = await f.enroll(), state = randomBytes(32).toString('base64url');
    const input = { version: 1, installationId: 'install-a', operationId: 'atomic', domain, issuer, purpose: 'direct', sessionKey: 'k'.repeat(43), sessionId: 'owned', state };
    await f.api.begin(a.credential, input);
    const callback = `${callbackUrl}?state=${state}&iss=${encodeURIComponent(issuer)}&code=PRIVATE_ATOMIC_CODE`;
    const take = { version: 1, installationId: 'install-a', operationId: 'atomic', issuer, sessionKey: 'k'.repeat(43), sessionId: 'owned' };
    await ownerPool.query('INSERT INTO poppy_provider.records(ns,kind,id,body) VALUES($1,$2,$3,$4)', [f.namespace, 'host-decision', 'chosen', '{"approved":true}']);
    await assert.rejects(provider.callback(callback), /provider pool is unavailable/);
    await assert.rejects(host(connection => participant.withTransaction(connection, async () => {
      await marker(connection, 'issuer-code'); await provider.callback(callback); await marker(connection, 'delivery-receipt');
      throw new Error('host interruption');
    })), /host interruption/);
    assert.equal((await ownerPool.query("SELECT count(*) AS n FROM poppy_provider.records WHERE ns=$1 AND kind='host-receipt'", [f.namespace])).rows[0].n, '0');
    assert.equal((await ownerPool.query("SELECT count(*) AS n FROM poppy_provider.records WHERE ns=$1 AND kind='host-decision'", [f.namespace])).rows[0].n, '1');
    assert.equal((await f.api.takeResult(a.credential, take)).status, 'pending');
    await host(connection => participant.withTransaction(connection, async () => {
      expiredHandle = connection;
      await marker(connection, 'issuer-code'); assert.equal((await provider.callback(callback)).status, 'ready'); await marker(connection, 'delivery-receipt');
      const gate = new Promise<void>(resolve => { release = resolve; });
      escaped = gate.then(() => provider.callback(callback));
    }));
    release(); assert.ok(escaped); await assert.rejects(escaped, /expired Postgres transaction/);
    await assert.rejects(participant.withTransaction(expiredHandle!, async () => {}), /expired host transaction/);
    assert.equal((await ownerPool.query("SELECT count(*) AS n FROM poppy_provider.records WHERE ns=$1 AND kind='host-receipt'", [f.namespace])).rows[0].n, '2');
    assert.equal((await f.api.takeResult(a.credential, take)).callbackUrl, callback);
    await host(connection => participant.withTransaction(connection, async () => { assert.equal((await provider.callback(callback)).status, 'consumed'); }));
    await assert.rejects(f.api.takeResult(a.credential, take), { code: 'consumed' });
    const raw = await ownerPool.connect();
    try { await assert.rejects(participant.withTransaction(raw, async () => {}), /SAVEPOINT can only be used in transaction blocks/); }
    finally { raw.release(); }
  } finally { await participant.close(); await ownerPool.end(); await f.close(); }
});
test('authenticated enrollment, visitor/issuer identity and installation isolation',async()=>{
  const f=await fixture();try{
    await assert.rejects(f.api.enroll(new Request(clientId),{version:1,installationId:'a',idempotencyKey:'key'}),{code:'unauthorized'});
    const a=await f.enroll(), b=await f.enroll('install-b');
    const identity=(credential: string,installationId: string)=>f.api.identity(credential,{version:1,installationId,domain,issuer});
    const first=await identity(a.credential,'install-a'),second=await identity(b.credential,'install-b');
    assert.equal(first.userId,second.userId);assert.notEqual(first.clientId,second.clientId);
    await assert.rejects(identity(a.credential,'install-b'),{code:'unauthorized'});
    f.setSubject('bob');const c=await f.enroll('install-c');assert.notDeepEqual(await identity(a.credential,'install-a'),await identity(c.credential,'install-c'));
    const response=await f.api.handle(new Request('https://identity.example/v1/enroll',{method:'POST',headers:{'content-type':'application/json','x-human':'authenticated'},body:JSON.stringify({version:2,installationId:'a',idempotencyKey:'other'})}));assert.equal(response.status,409);assert.equal(response.headers.get('cache-control'),'no-store');
  }finally{await f.close();}
});
test('constrained signing rejects claims, purposes, companies and unverified browser sessions',async()=>{
  const f=await fixture();try{
    const a=await f.enroll(), binding={version:1,installationId:'install-a',operationId:'sign',domain,issuer,purpose:'client-authentication'};
    for(const change of [{subject:'attacker'},{audience:'https://evil.example'},{purpose:'raw'},{issuer:'https://evil.example'},{domain:'evil.example'}])await assert.rejects(f.api.begin(a.credential,{...binding,...change}));
    await f.api.begin(a.credential,binding);
    const result=await f.api.assert(a.credential,{version:1,installationId:'install-a',operationId:'sign',purpose:'client-authentication'});
    const payload=decodeJwt(result.assertion);assert.equal(payload.aud,issuer);assert.equal(payload.iss,a.clientId);assert.equal(expectValue(payload.exp)-expectValue(payload.iat),60);assert.ok(expectValue(payload.jti).length>=22);assert.equal(decodeProtectedHeader(result.assertion).typ,'client-authentication+jwt');
    await jwtVerify(result.assertion,await importJWK(await f.options.signer.publicJwk(),'ES256'),{issuer:a.clientId,audience:issuer,currentDate:new Date(1000000)});
    await assert.rejects(f.api.assert(a.credential,{version:1,installationId:'install-a',operationId:'sign',purpose:'session'}),{code:'binding_conflict'});
    for (const sessionId of ['other','owned']) await assert.rejects(f.api.begin(a.credential,{...binding,purpose:'browser',operationId:'browser',sessionId,returnTo:'https://company.example/'}),{code:'binding_conflict'});
    await assert.rejects(f.api.assert(a.credential,{version:1,installationId:'install-a',operationId:'sign',purpose:'browser'}),{code:'binding_conflict'});
    await assert.rejects(f.api.takeResult(a.credential,{version:1,installationId:'install-a',operationId:'sign',issuer,sessionKey:'k'.repeat(43),sessionId:null}),{code:'binding_conflict'});
  }finally{await f.close();}
});
test('callback results encrypted, correlated, atomic, one time; restart, replay, cancel and expiry',async()=>{
  const f=await fixture();try{
    const a=await f.enroll(),b=await f.enroll('install-b'),state=randomBytes(32).toString('base64url');
    const input={version:1,installationId:'install-a',operationId:'direct',issuer,domain,purpose:'direct',sessionKey:'k'.repeat(43),sessionId:'session-a',state};
    await f.api.begin(a.credential,input);
    await assert.rejects(f.api.begin(b.credential,{...input,installationId:'install-b'}),{code:'binding_conflict'});
    const callback=`${callbackUrl}?state=${state}&iss=${encodeURIComponent(issuer)}&code=PRIVATE_CODE`;
    await assert.rejects(f.api.callback(callback.replace(encodeURIComponent(issuer),'https%3A%2F%2Fevil.example')),{code:'binding_conflict'});
    await f.api.callback(callback);await f.api.callback(callback);
    await assert.rejects(f.api.callback(callback.replace('PRIVATE_CODE','OTHER')),{code:'binding_conflict'});
    const take={version:1,installationId:'install-a',operationId:'direct',issuer,sessionKey:'k'.repeat(43),sessionId:'session-a'};
    await assert.rejects(f.api.takeResult(a.credential,{...take,sessionKey:'x'.repeat(43)}),{code:'binding_conflict'});
    await assert.rejects(f.api.takeResult(b.credential,{...take,installationId:'install-b'}),{code:'binding_conflict'});
    await assert.rejects(f.api.takeResult(a.credential,{...take,installationId:'install-b'}),{code:'unauthorized'});
    assert.equal((await f.persisted()).includes(Buffer.from('PRIVATE_CODE')),false);
    const second=f.second();try{const resumed=createProvider({...f.options,store:second});assert.equal((await resumed.takeResult(a.credential,take)).callbackUrl,callback);await assert.rejects(f.api.takeResult(a.credential,take),{code:'consumed'});assert.equal((await f.api.callback(callback)).status,'consumed');await assert.rejects(f.api.callback(callback.replace('PRIVATE_CODE','OTHER')),{code:'binding_conflict'});await assert.rejects(resumed.takeResult(a.credential,take),{code:'consumed'});}finally{await second.close();}
    await f.api.begin(a.credential,{...input,operationId:'cancel',state:randomBytes(32).toString('base64url')});await f.api.cancel(a.credential,{version:1,installationId:'install-a',operationId:'cancel'});
    await assert.rejects(f.api.takeResult(a.credential,{...take,operationId:'cancel'}),{code:'canceled'});
    f.setTime(1600001);await assert.rejects(f.api.takeResult(a.credential,take),{code:'expired'});
  }finally{await f.close();}
});

test('operation retries retain original binding and expiry without extending authorization',async()=>{
  const f=await fixture();try{
    const a=await f.enroll(),state=randomBytes(32).toString('base64url'),input={version:1,installationId:'install-a',operationId:'idempotent',issuer,domain,purpose:'direct',sessionKey:'k'.repeat(43),sessionId:'owned',state};
    const started=await f.api.begin(a.credential,input);f.setTime(1100000);
    assert.deepEqual(await f.api.begin(a.credential,input),started);
    for(const change of [{sessionId:'another'},{state:randomBytes(32).toString('base64url')}])await assert.rejects(f.api.begin(a.credential,{...input,...change}),{code:'binding_conflict'});
    f.setTime(started.expiresAt);await assert.rejects(f.api.begin(a.credential,input),{code:'expired'});
  }finally{await f.close();}
});

test('expired callback tombstones retain state through grace and cleanup cannot remove live operations',async()=>{
  const f=await fixture();try{
    const a=await f.enroll(),state=randomBytes(32).toString('base64url'),input={version:1,installationId:'install-a',operationId:'old',issuer,domain,purpose:'direct',sessionKey:'k'.repeat(43),sessionId:'owned',state};
    const old=await f.api.begin(a.credential,input);
    f.setTime(old.expiresAt+29999);
    await assert.rejects(f.api.begin(a.credential,{...input,operationId:'too-soon'}),{code:'binding_conflict'});
    const liveState=randomBytes(32).toString('base64url');await f.api.begin(a.credential,{...input,operationId:'live',state:liveState});
    f.setTime(old.expiresAt+30000);
    const replacementState=randomBytes(32).toString('base64url');await f.api.begin(a.credential,{...input,operationId:'replacement',state:replacementState});
    const oldCallback=`${callbackUrl}?state=${state}&iss=${encodeURIComponent(issuer)}&code=PRIVATE`;
    await assert.rejects(f.api.callback(oldCallback),{code:'binding_conflict'});
    const replacementCallback=`${callbackUrl}?state=${replacementState}&iss=${encodeURIComponent(issuer)}&code=NEW`;assert.equal((await f.api.callback(replacementCallback)).status,'ready');
    const take={version:1,installationId:'install-a',operationId:'replacement',issuer,sessionKey:'k'.repeat(43),sessionId:'owned'};
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
  const f=await fixture();try{const a=await f.enroll();const transport={fetch:(req: Request) =>f.api.handle(req)};const client=createProviderClient({url:'https://identity.example/v1',domain,installationId:'install-a',credential:async()=>a.credential,transport});assert.equal((await client.identity(issuer)).clientId,a.clientId);const result=await client.assert({operationId:'from-sdk',issuer,purpose:'client-authentication'});assert.equal(decodeJwt(result.assertion).aud,issuer);
    const unsafe=createProvider({...f.options,publishedKeys:async()=>[{...await f.options.signer.publicJwk(),kid:'key',d:'PRIVATE_KEY'}]});const response=await unsafe.handle(new Request('https://identity.example/jwks'));assert.equal(response.status,503);assert.ok(!(await response.text()).includes('PRIVATE_KEY'));
  }finally{await f.close();}
});
test('authentication and policy precede metadata; malformed sessions never reach session hook',async()=>{
  const f=await fixture();try{
    let resolves=0,hooks=0;const original=f.options.metadata.resolveCompany;
    const api=createProvider({...f.options,metadata:{...f.options.metadata,resolveCompany:async d=>{resolves++;return original(d);}}});
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
    const a=await f.enroll(),base={version:1,installationId:'install-a',domain,issuer,purpose:'client-authentication'};
    // Install retained tombstones through the same store contract to reach the hard cap quickly.
    await f.store.transaction({kind:'begin',enrollmentId:a.enrollmentId,operationId:'seed',issuer,at:1000000},tx=>{for(let i=0;i<999;i++)tx.put('operation',`${a.enrollmentId}:a${i.toString().padStart(4,'0')}`,{binding:{stateHash:null},expiresAt:1600000,status:'canceled',result:null});});
    const state=randomBytes(32).toString('base64url');await f.api.begin(a.credential,{...base,operationId:'\uffffx',purpose:'direct',sessionKey:'k'.repeat(43),sessionId:'owned',state});
    await f.api.callback(`${callbackUrl}?state=${state}&iss=${encodeURIComponent(issuer)}&code=PRIVATE`);
    await assert.rejects(f.api.begin(a.credential,{...base,operationId:'zz-overflow'}),{code:'rate_limited'});
    await f.api.revokeEnrollment(a.credential,{version:1,installationId:'install-a'});
    const rows=await f.store.transaction({kind:'revoke',enrollmentId:a.enrollmentId},tx=>tx.list('operation',`${a.enrollmentId}:`,1001));assert.equal(rows.length,1000);assert.ok(rows.every(row=>row.value.result===null&&row.value.status==='canceled'));
  }finally{await f.close();}
});
test('real processes atomically race result consumption and revoke against callback',async()=>{
  const f=await fixture();try{
    const a=await f.enroll(),state=randomBytes(32).toString('base64url'),base={version:1,installationId:'install-a',operationId:'race',issuer,domain,purpose:'direct',sessionKey:'k'.repeat(43),sessionId:'owned',state};await f.api.begin(a.credential,base);
    const callback=`${callbackUrl}?state=${state}&iss=${encodeURIComponent(issuer)}&code=PRIVATE_RACE`;await f.api.callback(callback);
    const worker=(action:ProviderRaceAction)=>new Promise<{status?:string;error?:string}>((resolve,reject)=>{
      const child=spawn(process.execPath,[fileURLToPath(new URL('../test-support/provider-worker.mjs',import.meta.url))],{env:{...process.env,DB_PATH:f.path,TASK:JSON.stringify(action)},windowsHide:true});let out='',err='';child.stdout.on('data',d=>out+=d);child.stderr.on('data',d=>err+=d);child.on('error',reject);child.on('close',code=>{try{
        assert.equal(code,0,err);const result:unknown=JSON.parse(out);assert.ok(result&&typeof result==='object');
        if('status' in result){assert.ok(typeof result.status==='string');resolve({status:result.status});}
        else{assert.ok('error' in result&&typeof result.error==='string');resolve({error:result.error});}
      }catch(e){reject(e);}});
    });
    const take:ProviderRaceAction={action:'take',credential:a.credential,body:{version:1,installationId:'install-a',operationId:'race',issuer,sessionKey:'k'.repeat(43),sessionId:'owned'}};
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
      const input={version:1,installationId:'install-a',operationId,domain,issuer,purpose:'direct',sessionKey:'k'.repeat(43),sessionId:'owned',state:states[i]};
      const started=await f.api.begin(a.credential,input);assert.deepEqual(await f.api.begin(a.credential,input),started);
      await f.api.callback(`${callbackUrl}?state=${states[i]}&iss=${encodeURIComponent(issuer)}&code=PRIVATE_UNICODE`);
    }
    for(let i=0;i<8;i++)await f.api.begin(a.credential,{version:1,installationId:'install-a',operationId:'ascii-'+i,domain,issuer,purpose:'client-authentication'});
    await assert.rejects(f.api.begin(a.credential,{version:1,installationId:'install-a',operationId:'overflow',domain,issuer,purpose:'client-authentication'}),{code:'rate_limited'});
    await f.api.revokeEnrollment(a.credential,{version:1,installationId:'install-a'});
    const rows=await f.store.transaction({kind:'revoke',enrollmentId:a.enrollmentId},tx=>tx.list('operation',`${a.enrollmentId}:`,1001));
    assert.equal(rows.length,10);assert.ok(rows.every(row=>row.value.result===null&&row.value.status==='canceled'));
  }finally{await f.close();}
});


test('delegations isolate enrollment clients and reject legacy, private-key and arbitrary-claim requests', async () => {
  const f=await fixture();try {
    const a=await f.enroll();f.setSubject('bob');const b=await f.enroll('install-b');
    const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),jwk=await publicEcJwk(pair.publicKey);
    const input={version:1,installationId:'install-a',operationId:'delegation',jwk};
    const result=await f.api.delegate(a.credential,input),claims=decodeJwt(result.delegation);assert.equal(claims.iat!%1800,0);assert.equal(claims.exp,claims.iat!+3600);
    assert.equal(claims.iss,a.clientId);assert.notEqual(a.clientId,b.clientId);
    assert.deepEqual(Object.keys(claims).sort(),['cnf','exp','iat','iss','jti']);
    assert.deepEqual(await f.api.delegate(a.credential,input),result,'repeat delivery keeps the original delegation and expiry');
    await jwtVerify(result.delegation,await importJWK(await f.options.signer.publicJwk(),'ES256'),{issuer:a.clientId,currentDate:new Date(1000000)});
    const response=await f.api.handle(new Request(a.clientId));assert.equal(response.status,200);assert.equal((await response.json()).client_id,a.clientId);
    for(const extra of [{sub:'another-user'},{issuer:'https://other.example'},{jwk:{...jwk,d:'private'}}]) await assert.rejects(f.api.delegate(a.credential,{...input,...extra}),{code:'binding_conflict'});
    await assert.rejects(f.api.delegate(a.credential,{...input,installationId:'install-b'}),{code:'unauthorized'});
    const {CompactSign,calculateJwkThumbprint}=await import('jose'),{verifySessionJwt}=await import('../dist/protocol/session.js');
    const forged=await new CompactSign(new TextEncoder().encode(JSON.stringify({iss:b.clientId,aud:issuer,sid:'forged_session',sub:'known-user-id',htm:'POST',htu:'https://company.example/api',iat:1000,jti:'request-random-id-1234'}))).setProtectedHeader({alg:'ES256',typ:'poppy-session+jwt',kid:await calculateJwkThumbprint(jwk),pap_dlg:result.delegation}).sign(pair.privateKey);
    const metadata={...f.options.metadata,async resolveClient(id:string){const response=await f.api.handle(new Request(id));return response.json();},async resolveJwks(){return {keys:[{...await f.options.signer.publicJwk(),kid:f.options.signer.kid}]};}};
    await assert.rejects(verifySessionJwt(forged,{companyId:issuer,method:'POST',url:'https://company.example/api',nowMs:1000000,metadata}));
    await f.store.transaction({kind:'metadata',enrollmentId:a.enrollmentId},tx=>{const row=tx.get('enrollment',a.enrollmentId)!;delete row.clientId;tx.put('enrollment',a.enrollmentId,row);});
    await assert.rejects(f.api.delegate(a.credential,{...input,operationId:'legacy'}),{code:'binding_conflict'});
  }finally{await f.close();}
});

test('delegation issuance prunes 1000 expired records and linked state before inserting', async () => {
  const f=await fixture();try {
    const a=await f.enroll();
    await f.store.transaction({kind:'begin',enrollmentId:a.enrollmentId,operationId:'seed',issuer,stateHash:'old-state',at:1000000},tx=>{
      for(let i=0;i<1000;i++)tx.put('operation',a.enrollmentId+':old-'+i,{binding:{purpose:'delegation',stateHash:i===0?'old-state':null},expiresAt:1,status:'signed',result:null});
      tx.put('state','old-state',{enrollmentId:a.enrollmentId,operationId:'old-0'});
    });
    const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
    await f.api.delegate(a.credential,{version:1,installationId:'install-a',operationId:'fresh',jwk:await publicEcJwk(pair.publicKey)});
    const second=f.second();try {
      const rows=await second.transaction({kind:'delegate',enrollmentId:a.enrollmentId,operationId:'fresh',at:1000000},tx=>tx.list('operation',a.enrollmentId+':',1001));
      assert.equal(rows.length,1);assert.equal(rows[0]!.id,a.enrollmentId+':fresh');
      const old=await second.transaction({kind:'callback',stateHash:'old-state'},tx=>tx.get('state','old-state'));assert.equal(old,undefined);
    }finally{await second.close();}
    await f.api.revokeEnrollment(a.credential,{version:1,installationId:'install-a'});
  }finally{await f.close();}
});

test('Operations provider metadata is enrollment-specific and stays unadvertised without readiness',async()=>{
  const f=await fixture();try{
    const enrollment=await f.enroll();
    const identity=await f.api.identity(enrollment.credential,{version:1,installationId:'install-a',issuer,domain});
    const scoped=identity.clientId;
    assert.equal((await (await f.api.handle(new Request(scoped))).json()).extensions,undefined);
    let ready=false;const api=createProvider({...f.options,operations:{ready:async id=>id===enrollment.enrollmentId&&ready}});
    assert.equal((await (await api.handle(new Request(scoped))).json()).extensions,undefined);
    ready=true;assert.deepEqual((await (await api.handle(new Request(scoped))).json()).extensions,{operations:{version:'2'}});
    assert.equal((await (await api.handle(new Request(clientId))).json()).extensions,undefined);
  }finally{await f.close();}
});
