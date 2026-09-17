// AI-Author: Codex (OpenAI model not exposed by runtime)
import { createHash } from 'node:crypto';

const words = {
  en: {title: 'Protected network path', route: 'Default route', via: 'Next-hop interface', port: 'Member interface', primary: 'Primary uplink', detail: 'OVN and supporting interfaces', observed: 'Observed dependency', notes: 'Evidence boundary', motion: 'Presentation', self: 'Self-membership is omitted from the drawing; raw evidence remains available.', illustrative: 'Trace animation illustrates dependencies, not packet telemetry.', missing: 'No dependency edges were provided. No interface links have been invented.', aliases: 'Protected aliases', ready: 'Discovery ready', pending: 'Incomplete discovery', revision: 'Inventory revision', interface: 'Network interface', uplink: 'Uplink interface'},
  'zh-CN': {title: '主网络保护路径', route: '默认路由', via: '下一跳接口', port: '成员接口', primary: '默认路由与主上联', detail: 'OVN 与辅助接口', observed: '已观测依赖', notes: '证据边界', motion: '演示说明', self: '自成员关系不绘制为环；原始证据仍完整保留。', illustrative: '追踪动画说明接口依赖，不代表实时数据包。', missing: '未提供接口依赖证据；未推断或补造连线。', aliases: '受保护别名', ready: '发现完整', pending: '发现不完整', revision: '清单版本', interface: '网络接口', uplink: '上联接口'},
  'zh-TW': {title: '主網路保護路徑', route: '預設路由', via: '下一跳介面', port: '成員介面', primary: '預設路由與主上聯', detail: 'OVN 與輔助介面', observed: '已觀測相依', notes: '證據邊界', motion: '展示說明', self: '自身成員關係不繪製為環；原始證據仍完整保留。', illustrative: '追蹤動畫說明介面相依，不代表即時封包。', missing: '未提供介面相依證據；未推斷或補造連線。', aliases: '受保護別名', ready: '探索完整', pending: '探索不完整', revision: '清單版本', interface: '網路介面', uplink: '上聯介面'},
};
const clean = (value, max = 160) => typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, max) : '';
const idFor = value => 'iface-' + createHash('sha256').update(value).digest('hex').slice(0, 14);
const detailName = value => value === 'br-int' || /^(ovn-|patch-|genev_sys_|vxlan_sys_)/.test(value);

export function buildSpecification(input) {
  if (!input || typeof input !== 'object' || !input.node || typeof input.node !== 'object') throw new Error('A node evidence object is required');
  const node = input.node;
  const name = clean(node.name);
  if (!name) throw new Error('Node name is required');
  const locale = Object.hasOwn(words, input.locale) ? input.locale : 'zh-CN';
  const t = words[locale];
  const revision = clean(input.revision, 80);
  const warnings = [];
  const rawEdges = Array.isArray(node.edges) ? node.edges : [];
  if (rawEdges.length > 256) throw new Error('Topology edge limit exceeded');
  const edges = [];
  const self = [];
  const seen = new Set();
  for (const value of rawEdges) {
    const from = clean(value?.from), to = clean(value?.to);
    if (!from || !to) continue;
    if (from === to) { self.push(from); continue; }
    const key = from + '\0' + to;
    if (!seen.has(key)) { edges.push({from, to}); seen.add(key); }
  }
  const path = Array.isArray(node.primaryPath) ? node.primaryPath.map(x => clean(x)).filter(Boolean) : [];
  const names = new Set([...path, ...edges.flatMap(e => [e.from, e.to])]);
  const routes = [];
  for (const r of Array.isArray(node.defaultRoutes) ? node.defaultRoutes : []) {
    const iface = clean(r?.interface), destination = clean(r?.destination, 64);
    if (iface && destination && !routes.some(x => x.interface === iface && x.destination === destination)) {
      routes.push({interface: iface, destination}); names.add(iface);
    }
  }
  if (names.size + routes.length > 12) throw new Error('This node exceeds the 12-component presentation limit; inspect raw dependency evidence');
  if (!names.size) throw new Error('No interface topology evidence is available for this node');
  if (!rawEdges.length) warnings.push(t.missing);
  if (self.length) warnings.push(t.self + ' ' + [...new Set(self)].join(', '));
  if (locale === 'zh-TW') warnings.push('圖中內容使用繁體中文；Archify 內建工具列目前回退為英文。');
  const main = [...names].filter(n => !detailName(n));
  const detail = [...names].filter(n => detailName(n));
  const depth = new Map(routes.map(r => [r.interface, 1]));
  for (let pass = 0; pass < main.length; pass++) {
    for (const e of edges) if (main.includes(e.from) && main.includes(e.to) && depth.has(e.from) && !depth.has(e.to)) depth.set(e.to, depth.get(e.from) + 1);
  }
  for (const n of main) if (!depth.has(n)) depth.set(n, 1);
  const components = [], connections = [], primaryIds = [], detailIds = [];
  const layerCounts = new Map();
  const width = 280, height = 90, stepX = 380;
  let maxX = 1100, mainBottom = 190;
  for (const n of main.sort((a,b) => depth.get(a)-depth.get(b) || a.localeCompare(b))) {
    const d = depth.get(n), row = layerCounts.get(d) || 0;
    layerCounts.set(d, row+1);
    const pos = [60 + d*stepX, 100 + row*180];
    components.push({id:idFor(n), type: edges.some(e => e.from===n) ? 'backend':'cloud', label:n, sublabel:t.observed, pos, size:[width,height]});
    primaryIds.push(idFor(n)); maxX=Math.max(maxX,pos[0]+width+60); mainBottom=Math.max(mainBottom,pos[1]+height);
  }
  routes.forEach((r,index) => {
    const id='route-'+index;
    components.push({id,type:'external',label:t.route,sublabel:r.destination,pos:[60,100+index*180],size:[width,height]});
    primaryIds.push(id); mainBottom=Math.max(mainBottom,190+index*180);
    connections.push({id:'route-edge-'+index,from:id,to:idFor(r.interface),label:t.via,variant:'emphasis'});
  });
  const detailRoots = detail.filter(n => edges.some(e => e.from===n && detail.includes(e.to)) && !edges.some(e=>e.to===n && detail.includes(e.from)));
  const assigned = new Set();
  let detailBottom=mainBottom;
  const detailTop=mainBottom+120;
  for (const [rootIndex, root] of detailRoots.entries()) {
    const children=edges.filter(e=>e.from===root && detail.includes(e.to)).map(e=>e.to);
    const y=detailTop+rootIndex*380+100;
    components.push({id:idFor(root),type:'backend',label:root,sublabel:t.observed,pos:[60,y],size:[width,height]});
    assigned.add(root); detailIds.push(idFor(root));
    children.forEach((child,index)=>{
      if(assigned.has(child))return;
      const cy=y+(index-(children.length-1)/2)*200;
      components.push({id:idFor(child),type:'backend',label:child,sublabel:t.observed,pos:[440,cy],size:[width,height]});
      assigned.add(child);detailIds.push(idFor(child));detailBottom=Math.max(detailBottom,cy+height);
    });
    detailBottom=Math.max(detailBottom,y+height);
  }
  const orphans=detail.filter(n=>!assigned.has(n));
  orphans.forEach((n,index)=>{
    const pos=[820,detailTop+100+index*180];
    components.push({id:idFor(n),type:'backend',label:n,sublabel:t.observed,pos,size:[width,height]});
    detailIds.push(idFor(n));detailBottom=Math.max(detailBottom,pos[1]+height);
  });
  for (const [index,e] of edges.entries()) connections.push({id:'observed-edge-'+index,from:idFor(e.from),to:idFor(e.to),label:t.port,variant: main.includes(e.from)&&main.includes(e.to)?'emphasis':'default'});
  const aliases=(Array.isArray(node.protectedInterfaces)?node.protectedInterfaces:[]).map(x=>clean(x)).filter(n=>n&&!names.has(n));
  const boundary=[];
  if(primaryIds.length)boundary.push({kind:'region',label:t.primary,wraps:primaryIds,pad:28});
  if(detailIds.length)boundary.push({kind:'region',label:t.detail,wraps:detailIds,pad:28});
  const views=[];
  if(primaryIds.length)views.push({id:'primary-path',label:t.primary,focus:primaryIds,note:t.illustrative});
  if(detailIds.length)views.push({id:'ovn-detail',label:t.detail,focus:detailIds,note:t.self});
  const notes=[`${t.revision}: ${revision || '—'} · ${node.ready?t.ready:t.pending}`];
  if(self.length)notes.push(t.self);
  if(aliases.length)notes.push(`${t.aliases}: ${aliases.join(', ')}`);
  const specification={schema_version:1,diagram_type:'architecture',meta:{title:`${t.title} · ${name}`,quality_profile:'showcase',animation:'trace',legend:{entries:{external:{label:t.route},backend:{label:t.interface},cloud:{label:t.uplink}}},viewBox:[maxX,Math.max(560,detailBottom+90)],views,...(locale==='zh-TW'?{}:{locale})},components,boundaries:boundary,connections,cards:[{dot:'cyan',title:t.notes,items:notes},{dot:'amber',title:t.motion,items:[t.illustrative,...warnings.filter(w=>w!==t.self&&!w.startsWith(t.self))]}]};
  return {specification,node:name,revision,warnings,renderer:'Archify 2.17'};
}
