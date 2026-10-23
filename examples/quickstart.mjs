import assert from 'node:assert/strict';
import { createMetadataResolver, createNodeTransport } from '@poppykit/client';

const selfCheck = process.argv.includes('--self-check');
const domain = selfCheck ? 'company.example' : process.argv[2];
if (!domain) throw new Error('usage: node examples/quickstart.mjs DOMAIN|--self-check');
const transport = selfCheck ? {
  async fetch(request) {
    assert.equal(request.url, 'https://company.example/.well-known/poppy.json');
    return Response.json({ protocol_version: '0.2', organization: { name: 'Example Company', domain }, web: {} });
  },
} : createNodeTransport();
try {
  const company = await createMetadataResolver(transport).resolveCompany(domain);
  if (selfCheck) assert.equal(company.document.organization.name, 'Example Company');
  console.log(company.document.organization);
} finally {
  transport.close?.();
}
