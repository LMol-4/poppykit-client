import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtemp,cp,readFile,writeFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
test('protocol sync compares canonical network tests and ignores generated test JavaScript',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'protocol sync ü '));
 const run=()=>spawnSync(process.execPath,[fileURLToPath(new URL('../scripts/sync-protocol.mjs',import.meta.url)),directory,'--check'],{encoding:'utf8',windowsHide:true});
 try{
  await writeFile(join(directory,'package.json'),'{}');
  for(const path of ['src/protocol','src/network','tests/network'])await cp(new URL('../'+path,import.meta.url),join(directory,path),{recursive:true,filter:source=>!path.startsWith('tests/')||!/\.mjs(?:\.map)?$/.test(source)});
  assert.equal(run().status,0,'clean canonical target matches built source');
  // These files are comparison data only; the sync tool never executes them.
  await writeFile(join(directory,'tests/network/stale-output.mjs'),'stale generated data');await writeFile(join(directory,'tests/network/stale-output.mjs.map'),'stale source-map data');assert.equal(run().status,0,'built target output does not cause canonical drift');
  const source=join(directory,'tests/network/network.test.mts'),original=await readFile(source,'utf8');await writeFile(source,original+'\n// changed canonical source\n');const changed=run();assert.equal(changed.status,1);assert.match(changed.stderr,/tests\/network\/network.test.mts/);
 }finally{await rm(directory,{recursive:true,force:true});}
});
