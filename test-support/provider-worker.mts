import assert from 'node:assert/strict';
import { createMetadataResolver } from '../dist/index.js';
import { createProvider, ProviderError } from '../dist/provider.js';
import { SqliteProviderStore } from '../dist/provider-sqlite.js';

export type ProviderRaceAction =
  | { action:'take'; credential:string; body:{version:number;installationId:string;operationId:string;issuer:string;sessionId:string} }
  | { action:'revoke'; credential:string; body:{version:number;installationId:string} }
  | { action:'callback'; callback:string };

const input:unknown=JSON.parse(process.env.TASK??'null');
assert.ok(input&&typeof input==='object'&&'action' in input);
const path=process.env.DB_PATH;assert.ok(path);
const store=new SqliteProviderStore(path);
const unused=async():Promise<never>=>{throw new Error('unexpected worker signing or metadata request');};
const provider=createProvider({
  clientId:'https://identity.example/client.json',callbackUrl:'https://identity.example/callback',jwksUri:'https://identity.example/jwks',clientName:'Generic provider',
  store,cipher:{open:()=> 'private',seal:()=> 'encrypted'},now:()=>1000000,
  metadata:createMetadataResolver({fetch:unused}),authenticateEnrollment:async()=>null,
  signer:{kid:'unused',publicJwk:unused,sign:unused},
});
try{
  let result:{status:string};
  if(input.action==='callback'){
    assert.ok('callback' in input&&typeof input.callback==='string');result=provider.callback(input.callback);
  }else{
    assert.ok('credential' in input&&typeof input.credential==='string'&&'body' in input&&input.body&&typeof input.body==='object'&&!Array.isArray(input.body));
    const body:Record<string,unknown>={...input.body};
    if(input.action==='take')result=provider.takeResult(input.credential,body);
    else{assert.equal(input.action,'revoke');result=provider.revokeEnrollment(input.credential,body);}
  }
  process.stdout.write(JSON.stringify({status:result.status}));
}catch(error){
  if(!(error instanceof ProviderError))throw error;
  process.stdout.write(JSON.stringify({error:error.code}));
}finally{store.close();}
