import assert from 'node:assert/strict';
export function expectValue<T>(value:T|null|undefined):T { assert.ok(value!==null&&value!==undefined,'expected fixture value');return value; }

export async function publicEcJwk(key:CryptoKey){const jwk=await crypto.subtle.exportKey('jwk',key);const {kty,crv,x,y}=jwk;assert.ok(kty&&crv&&x&&y);return {kty,crv,x,y,ext:jwk.ext??true,key_ops:jwk.key_ops??['verify']};}
