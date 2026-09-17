// AI-Author: Codex (OpenAI model not exposed by runtime)
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
import {buildSpecification} from './specification.mjs';

const inventory=JSON.parse(fs.readFileSync(process.argv[2]||'tests/fixtures/topology.json','utf8'));
for(const node of inventory.nodes)for(const locale of ['en','zh-CN','zh-TW']){
  const input={node,revision:inventory.revision,locale};
  const generated=buildSpecification(input);
  const relationships=generated.specification.connections.filter(e=>e.id.startsWith('observed-'));
  assert.equal(relationships.length,new Set(node.edges.filter(e=>e.from!==e.to).map(e=>e.from+'\0'+e.to)).size);
  assert(relationships.every(e=>e.from!==e.to));
  assert(generated.warnings.some(w=>w.includes('br-ex')));
  const result=spawnSync(process.execPath,['topology/render.mjs'],{input:JSON.stringify(input),encoding:'utf8',timeout:15000,maxBuffer:3*1024*1024});
  assert.ifError(result.error);assert.equal(result.status,0,result.stderr);
  const artifact=JSON.parse(result.stdout);
  assert.equal(artifact.node,node.name);assert.equal(artifact.revision,inventory.revision);
  assert(artifact.html.includes('<svg'));assert(artifact.html.includes('enp1s0'));
  assert.equal(artifact.renderer,'Archify 2.17');
  assert(generated.specification.meta.legend.entries.cloud.label.includes(locale==='en'?'Uplink':locale==='zh-CN'?'上联':'上聯'));
  if(locale==='zh-TW')assert(artifact.warnings.some(w=>w.includes('英文')));
  console.log(`PASS ${node.name} ${locale}: actual renderer, nine artifact checks, ${Buffer.byteLength(artifact.html)} HTML bytes`);
}
const missing=buildSpecification({node:{name:'missing',primaryPath:['eth0'],edges:[]},locale:'en'});
assert.equal(missing.specification.connections.length,0);assert(missing.warnings.some(w=>w.includes('No dependency')));
assert.throws(()=>buildSpecification({node:{name:'oversize',primaryPath:Array.from({length:13},(_,i)=>'eth'+i)}}),/12-component/);
console.log('PASS no invented edges and bounded topology size');

const malicious='</script><img src=x onerror=alert(1)>';
const probe={node:{name:'escape-probe',ready:true,primaryPath:[malicious],protectedInterfaces:[malicious],edges:[],defaultRoutes:[{destination:'0.0.0.0/0',interface:malicious}]},revision:'test',locale:'en'};
const escaped=spawnSync(process.execPath,['topology/render.mjs'],{input:JSON.stringify(probe),encoding:'utf8',timeout:15000,maxBuffer:3*1024*1024});
assert.ifError(escaped.error);assert.equal(escaped.status,0,escaped.stderr);
const probeHtml=JSON.parse(escaped.stdout).html;
assert(!probeHtml.includes(malicious));assert(probeHtml.includes('&lt;/script&gt;&lt;img'));
assert(!/<(?:script|img|link|iframe)[^>]+(?:src|href)=["']https?:/i.test(probeHtml));
assert(!/@import\s+(?:url\()?['"]?https?:/i.test(probeHtml));
assert(!/url\(['"]?https?:/i.test(probeHtml));
console.log('PASS hostile label escaped, no external HTML/CSS runtime asset references');
