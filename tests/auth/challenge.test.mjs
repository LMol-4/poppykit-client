import test from 'node:test';
import assert from 'node:assert/strict';
import { authChallenge } from '../../dist/auth/challenge.js';

test('header/body auth details merge without losing scope or extension identifiers', () => {
  assert.deepEqual(authChallenge('Bearer error="ignore", DPoP error="insufficient_scope", scope="read write", extension="a"', { error: 'insufficient_scope', scope: 'write custom', extension: 'b', conversation_id: 'conversation' }),
    { error: 'insufficient_scope', requiredScopes: ['read', 'write', 'custom'], extensions: ['a', 'b'], conversationId: 'conversation' });
  assert.deepEqual(authChallenge('DPoP scope="read", extension="needed"', { error: 'secret-diagnostic' }), { requiredScopes: ['read'], extensions: ['needed'] });
});
