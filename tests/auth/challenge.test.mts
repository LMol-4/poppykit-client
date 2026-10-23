import test from 'node:test';
import assert from 'node:assert/strict';
import { authChallenge } from '../../dist/auth/challenge.js';

test('header/body auth details merge without losing scope or extension identifiers', () => {
  assert.deepEqual(authChallenge('Bearer error="ignore", DPoP error="insufficient_scope", scope="read write", extension="a"', { error: 'insufficient_scope', scope: 'write custom', extension: 'b', conversation_id: 'conversation' }),
    { error: 'insufficient_scope', requiredScopes: ['read', 'write', 'custom'], extensions: ['a', 'b'], conversationId: 'conversation' });
  assert.deepEqual(authChallenge('DPoP scope="read", extension="needed"', { error: 'secret-diagnostic' }), { requiredScopes: ['read'], extensions: ['needed'] });
});

test('challenge preserves domain-qualified extension names and drops unsafe names',()=>{
  assert.deepEqual(authChallenge('DPoP error="extension_required", extension="example.com/gift-wrap"',{extension:'other.example/thing/v1'}).extensions,['example.com/gift-wrap','other.example/thing/v1']);
  for(const extension of ['https://example.com/thing','example.com/x y','example.com/x\ny','x'.repeat(513)])assert.deepEqual(authChallenge(null,{extension}).extensions,[]);
});
