#!/usr/bin/env node
// AI-Author: Codex (OpenAI model not exposed by runtime)
import {readFile, writeFile, mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {buildSpecification} from './specification.mjs';

const root=dirname(fileURLToPath(import.meta.url));
let temporary;
try {
  let raw='';
  for await (const chunk of process.stdin) { raw+=chunk; if(Buffer.byteLength(raw)>128*1024)throw new Error('Topology input exceeds 128 KiB'); }
  const result=buildSpecification(JSON.parse(raw));
  temporary=await mkdtemp(join(tmpdir(),'network-guardrail-topology-'));
  const source=join(temporary,'diagram.json'), output=join(temporary,'diagram.html');
  await writeFile(source,JSON.stringify(result.specification));
  const rendered=spawnSync(process.execPath,['--max-old-space-size=192',join(root,'vendor/archify/renderers/architecture/render-architecture.mjs'),source,output],{encoding:'utf8',timeout:8000,maxBuffer:1024*1024});
  if(rendered.error || rendered.status!==0)throw new Error('Archify renderer rejected the observed topology: '+(rendered.stderr||rendered.error?.message||'render failed').slice(0,3000));
  const checked=spawnSync(process.execPath,['--max-old-space-size=192',join(root,'vendor/archify/scripts/check-render-output.mjs'),output],{encoding:'utf8',timeout:5000,maxBuffer:1024*1024});
  if(checked.error || checked.status!==0)throw new Error('Archify artifact validation failed: '+(checked.stdout||checked.stderr||checked.error?.message||'check failed').slice(0,3000));
  const receipt=JSON.parse(checked.stdout);
  if(!receipt.ok||receipt.checks.length!==9||receipt.composition.summary.errors||receipt.composition.summary.warnings)throw new Error('Archify showcase acceptance did not pass');
  const html=await readFile(output,'utf8');
  if(Buffer.byteLength(html)>2*1024*1024)throw new Error('Topology output exceeds 2 MiB');
  delete result.specification;
  process.stdout.write(JSON.stringify({...result,html}));
} catch(error) {
  process.stderr.write(JSON.stringify({error:String(error.message||error)})+'\n');
  process.exitCode=1;
} finally { if(temporary)await rm(temporary,{recursive:true,force:true}); }
