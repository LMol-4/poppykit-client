// Synthetic Company flow. The trusted terminal asks each time; --self-check always declines.
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createInterface} from 'node:readline/promises';
import {createOperationClient} from '../dist/index.js';
import {SqliteBusinessAttemptStore} from '../dist/sqlite.js';
const dir=await mkdtemp(join(tmpdir(),'poppy-operation-example-')),store=new SqliteBusinessAttemptStore(join(dir,'attempts.db'),'synthetic-user');
const selfCheck=process.argv.includes('--self-check');let sends=0;
try{
  const client=createOperationClient({store,context:async()=>({companyId:'https://example.com',companyName:'Example Company',clientId:'https://agent.example/client',userId:'synthetic',authority:'session:synthetic',operations:true}),
    checkTerms:async(request,operation)=>operation.terms?.order_id===request.arguments?.order_id?[]:['Order differs from your request.'],
    consent:{confirm:async({attemptId,companyId,companyName,summary,terms,differences})=>{
      if(selfCheck)return 'decline';
      if(!process.stdin.isTTY||!process.stderr.isTTY)throw new Error('Trusted terminal required');
      const saved=await client.get(attemptId),display=JSON.stringify({companyId,companyName,summary,terms,differences,request:saved.request,expiresAt:saved.operation.expires_at},null,2).replace(/[\u007f-\u009f\u2028-\u202e\u2066-\u2069]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'));
      const terminal=createInterface({input:process.stdin,output:process.stderr});
      try{const answer=await terminal.question(`${display}\nApprove these exact terms? Type yes: `);return answer==='yes'?'approve':'decline';}finally{terminal.close();}
    }},send:async()=>{sends++;return {kind:'completed',result:{synthetic:true,done:true}};}});
  await client.receiveMcp('exchange-order-one',{channel:'mcp',url:'https://example.com/mcp',name:'exchange',arguments:{order_id:'one'}},{isError:true,structuredContent:{operation:{operation_id:'exchange_one',revision:'revision_one',summary:'Exchange order one for the blue jacket for $70.',terms:{order_id:'one',amount:'70.00'},expires_at:new Date(Date.now()+900000).toISOString()}}});
  const decision=await client.requestConsent('exchange-order-one');
  if(decision.phase==='approved')console.log((await client.retry(decision.id)).phase);else console.log(decision.phase);
  if(selfCheck){assert.equal(decision.phase,'declined');assert.equal(sends,0);}
}finally{store.close();await rm(dir,{recursive:true,force:true});}
