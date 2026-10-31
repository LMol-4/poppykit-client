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
    consent:{confirm:async({companyName,summary,differences})=>{
      if(selfCheck)return 'decline';
      const terminal=createInterface({input:process.stdin,output:process.stdout});
      try{const answer=await terminal.question(`${JSON.stringify(companyName)}\n${JSON.stringify(summary)}\n${JSON.stringify(differences)}\nApprove these exact terms? Type yes: `);return answer==='yes'?'approve':'decline';}finally{terminal.close();}
    }},send:async()=>{sends++;return {kind:'completed',result:{synthetic:true,done:true}};}});
  await client.receiveMcp('exchange-order-one',{channel:'mcp',url:'https://example.com/mcp',name:'exchange',arguments:{order_id:'one'}},{isError:true,structuredContent:{operation:{operation_id:'exchange_one',revision:'revision_one',summary:'Exchange order one for the blue jacket for $70.',terms:{order_id:'one',amount:'70.00'},expires_at:new Date(Date.now()+900000).toISOString()}}});
  const decision=await client.requestConsent('exchange-order-one');
  if(decision.phase==='approved')console.log((await client.retry(decision.id)).phase);else console.log(decision.phase);
  if(selfCheck){assert.equal(decision.phase,'declined');assert.equal(sends,0);}
}finally{store.close();await rm(dir,{recursive:true,force:true});}
