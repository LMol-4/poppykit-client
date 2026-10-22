import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from 'jose';
import { createProvider, createProviderClient, createResultCipher } from '../dist/provider.js';
import { SqliteProviderStore } from '../dist/provider-sqlite.js';

const issuer='https://company.example/issuer', domain='company.example', clientId='https://identity.example/client.json', callbackUrl='https://identity.example/callback';
async function fixture() {
  const dir=mkdtempSync(join(tmpdir(),'provider-')), path=join(dir,'provider.sqlite'), store=new SqliteProviderStore(path);
  let at=1000000, subject='alice', allowSession=true;
  const key=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const publicJwk=await crypto.subtle.exportKey('jwk',key.publicKey);
  const metadata={resolveCompany:async d=>{assert.equal(d,domain);return {document:{organization:{domain,name:'Generic'},web:{browser_session_endpoint:'https://company.example/join'}},authorization:{issuer}};}};
  const options={clientId,callbackUrl,jwksUri:'https://identity.example/jwks',clientName:'Generic provider',store,cipher:createResultCipher(randomBytes(32)),metadata,now:()=>at,
    authenticateEnrollment:async request=>request.headers.get('x-human')==='authenticated'?{subject,allowedCompanies:[domain]}:null,
    verifySession:async b=>allowSession&&b.sessionId==='owned',
    signer:{kid:'key-1',publicJwk:async()=>publicJwk,sign:async bytes=>new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key.privateKey,bytes))}};
  const api=createProvider(options), req=new Request('https://identity.example/v1/enroll',{headers:{'x-human':'authenticated'}});
  async function enroll(installationId='install-a'){return api.enroll(req,{version:1,installationId,idempotencyKey:randomBytes(20).toString('hex')});}
  return {api,options,store,path,dir,enroll,setSubject:v=>subject=v,setTime:v=>at=v,setSession:v=>allowSession=v,close:()=>{store.close();rmSync(dir,{recursive:true,force:true});}};
}
test('authenticated enrollment, visitor/issuer identity and installation isolation',async()=>{
  const f=await fixture();try{
    await assert.rejects(f.api.enroll(new Request(clientId),{version:1,installationId:'a',idempotencyKey:'key'}),{code:'unauthorized'});
    const a=await f.enroll(), b=await f.enroll('install-b');
    const identity=(credential,installationId)=>f.api.identity(credential,{version:1,installationId,domain,issuer});
    assert.deepEqual(await identity(a.credential,'install-a'),await identity(b.credential,'install-b'));
    await assert.rejects(identity(a.credential,'install-b'),{code:'unauthorized'});
    f.setSubject('bob');const c=await f.enroll('install-c');assert.notDeepEqual(await identity(a.credential,'install-a'),await identity(c.credential,'install-c'));
    const response=await f.api.handle(new Request('https://identity.example/v1/enroll',{method:'POST',headers:{'content-type':'application/json','x-human':'authenticated'},body:JSON.stringify({version:2,installationId:'a',idempotencyKey:'other'})}));assert.equal(response.status,409);assert.equal(response.headers.get('cache-control'),'no-store');
  }finally{f.close();}
});
test('constrained signing rejects claims, purposes, companies and unverified browser sessions',async()=>{
  const f=await fixture();try{
    const a=await f.enroll(), binding={version:1,installationId:'install-a',operationId:'sign',domain,issuer,purpose:'session'};
    for(const change of [{subject:'attacker'},{audience:'https://evil.example'},{purpose:'raw'},{issuer:'https://evil.example'},{domain:'evil.example'}])await assert.rejects(f.api.begin(a.credential,{...binding,...change}));
    await f.api.begin(a.credential,binding);
    const result=await f.api.assert(a.credential,{version:1,installationId:'install-a',operationId:'sign',purpose:'session'});
    const payload=decodeJwt(result.assertion);assert.equal(payload.aud,issuer);assert.equal(payload.iss,clientId);assert.equal(payload.exp-payload.iat,60);assert.ok(payload.jti.length>=22);assert.equal(decodeProtectedHeader(result.assertion).typ,'JWT');
    await jwtVerify(result.assertion,await importJWK(await f.options.signer.publicJwk(),'ES256'),{issuer:clientId,audience:issuer,currentDate:new Date(1000000)});
    await assert.rejects(f.api.assert(a.credential,{version:1,installationId:'install-a',operationId:'sign',purpose:'client-authentication'}),{code:'binding_conflict'});
    await assert.rejects(f.api.begin(a.credential,{...binding,purpose:'browser',operationId:'browser',sessionId:'other',returnTo:'https://company.example/'}),{code:'unauthorized'});
    await assert.rejects(f.api.begin(a.credential,{...binding,purpose:'browser',operationId:'browser',sessionId:'owned',returnTo:'https://evil.example/'}),{code:'binding_conflict'});
    await f.api.begin(a.credential,{...binding,purpose:'browser',operationId:'browser',sessionId:'owned',returnTo:'https://company.example/'});
    const browser=await f.api.assert(a.credential,{version:1,installationId:'install-a',operationId:'browser',purpose:'browser'});assert.equal(decodeProtectedHeader(browser.assertion).typ,'poppy-browser+jwt');
    f.setSession(false);await assert.rejects(f.api.assert(a.credential,{version:1,installationId:'install-a',operationId:'browser',purpose:'browser'}),{code:'unauthorized'});
    assert.throws(()=>f.api.takeResult(a.credential,{version:1,installationId:'install-a',operationId:'sign',issuer,sessionId:null}),{code:'binding_conflict'});
  }finally{f.close();}
});
test('callback results encrypted, correlated, atomic, one time; restart, replay, cancel and expiry',async()=>{
  const f=await fixture();try{
    const a=await f.enroll(),b=await f.enroll('install-b'),state=randomBytes(32).toString('base64url');
    const input={version:1,installationId:'install-a',operationId:'direct',issuer,domain,purpose:'direct',sessionId:'session-a',state};
    await f.api.begin(a.credential,input);
    await assert.rejects(f.api.begin(b.credential,{...input,installationId:'install-b'}),{code:'binding_conflict'});
    const callback=`${callbackUrl}?state=${state}&iss=${encodeURIComponent(issuer)}&code=PRIVATE_CODE`;
    assert.throws(()=>f.api.callback(callback.replace(encodeURIComponent(issuer),'https%3A%2F%2Fevil.example')),{code:'binding_conflict'});
    f.api.callback(callback);f.api.callback(callback);
    assert.throws(()=>f.api.callback(callback.replace('PRIVATE_CODE','OTHER')),{code:'binding_conflict'});
    const take={version:1,installationId:'install-a',operationId:'direct',issuer,sessionId:'session-a'};
    assert.throws(()=>f.api.takeResult(a.credential,{...take,sessionId:'other'}),{code:'binding_conflict'});
    assert.throws(()=>f.api.takeResult(b.credential,{...take,installationId:'install-b'}),{code:'binding_conflict'});
    assert.throws(()=>f.api.takeResult(a.credential,{...take,installationId:'install-b'}),{code:'unauthorized'});
    assert.equal(readFileSync(f.path).includes(Buffer.from('PRIVATE_CODE')),false);
    const second=new SqliteProviderStore(f.path);try{const resumed=createProvider({...f.options,store:second});assert.equal(resumed.takeResult(a.credential,take).callbackUrl,callback);assert.throws(()=>f.api.takeResult(a.credential,take),{code:'consumed'});assert.throws(()=>f.api.callback(callback),{code:'consumed'});}finally{second.close();}
    await f.api.begin(a.credential,{...input,operationId:'cancel',state:randomBytes(32).toString('base64url')});f.api.cancel(a.credential,{version:1,installationId:'install-a',operationId:'cancel'});
    assert.throws(()=>f.api.takeResult(a.credential,{...take,operationId:'cancel'}),{code:'canceled'});
    f.setTime(1600001);assert.throws(()=>f.api.takeResult(a.credential,take),{code:'expired'});
  }finally{f.close();}
});
test('revocation races KMS signing; issued assertions remain cryptographically valid',async()=>{
  const f=await fixture();try{
    const a=await f.enroll();await f.api.begin(a.credential,{version:1,installationId:'install-a',operationId:'sign',domain,issuer,purpose:'client-authentication'});
    const input={version:1,installationId:'install-a',operationId:'sign',purpose:'client-authentication'};
    const issued=await f.api.assert(a.credential,input);
    let release,started;const ready=new Promise(r=>started=r),gate=new Promise(r=>release=r),sign=f.options.signer.sign;
    const racing=createProvider({...f.options,signer:{...f.options.signer,sign:async bytes=>{started();await gate;return sign(bytes);}}});
    const pending=racing.assert(a.credential,input);await ready;f.api.revokeEnrollment(a.credential,{version:1,installationId:'install-a'});release();await assert.rejects(pending,{code:'unauthorized'});
    await jwtVerify(issued.assertion,await importJWK(await f.options.signer.publicJwk(),'ES256'),{currentDate:new Date(1000000)});
    await assert.rejects(f.api.assert(a.credential,input),{code:'unauthorized'});
    assert.equal(decodeJwt(issued.assertion).exp,1060); // Revoke is not company token revocation or JWT retraction.
  }finally{f.close();}
});
test('bound HTTP client uses authenticated versioned handlers without raw-byte signing',async()=>{
  const f=await fixture();try{const a=await f.enroll();const transport={fetch:req=>f.api.handle(req)};const client=createProviderClient({url:'https://identity.example/v1',domain,installationId:'install-a',credential:async()=>a.credential,transport});assert.equal((await client.identity(issuer)).clientId,clientId);const result=await client.assert({operationId:'from-sdk',issuer,purpose:'session'});assert.equal(decodeJwt(result.assertion).aud,issuer);}finally{f.close();}
});
