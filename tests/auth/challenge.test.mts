import test from 'node:test';
import assert from 'node:assert/strict';
import { authChallenge, schemeChallenge } from '../../dist/auth/challenge.js';

test('header/body auth details merge without losing scope or extension identifiers', () => {
  assert.deepEqual(authChallenge('Bearer error="ignore", DPoP error="insufficient_scope", scope="read write", extension="a"', { error: 'insufficient_scope', scope: 'write custom', extension: 'b', conversation_id: 'conversation' }),
    { error: 'insufficient_scope', requiredScopes: ['read', 'write', 'custom'], extensions: ['a', 'b'], conversationId: 'conversation' });
  assert.deepEqual(authChallenge('DPoP scope="read", extension="needed"', { error: 'secret-diagnostic' }), { requiredScopes: ['read'], extensions: ['needed'] });
});

test('challenge preserves domain-qualified extension names and drops unsafe names',()=>{
  assert.deepEqual(authChallenge('DPoP error="extension_required", extension="example.com/gift-wrap"',{extension:'other.example/thing/v1'}).extensions,['example.com/gift-wrap','other.example/thing/v1']);
  for(const extension of ['https://example.com/thing','example.com/x y','example.com/x\ny','x'.repeat(513)])assert.deepEqual(authChallenge(null,{extension}).extensions,[]);
});


test('Bearer and DPoP challenge details remain independent and current errors are recognized',()=>{
  const header='Basic realm="ignored, realm", Bearer error="invalid_token", resource_metadata="https://api.example/.well-known/oauth-protected-resource/v1?a=b", DPoP error="use_dpop_nonce", scope="read"';
  assert.deepEqual(schemeChallenge(header,'Bearer'),{error:'invalid_token',resource_metadata:'https://api.example/.well-known/oauth-protected-resource/v1?a=b'});
  assert.deepEqual(schemeChallenge(header,'DPoP'),{error:'use_dpop_nonce',scope:'read'});
  assert.deepEqual(authChallenge('Bearer scope="read custom"').requiredScopes,['read','custom']);
  assert.equal(authChallenge('Bearer error="insufficient_scope", scope="read"').error,'insufficient_scope');
  assert.equal(authChallenge(null,{error:'invalid_session'}).error,'invalid_session');
});
