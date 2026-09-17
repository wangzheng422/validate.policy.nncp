// AI-Author: Codex (OpenAI model not exposed by runtime)
import * as React from 'react';
import { consoleFetchJSON } from '@openshift-console/dynamic-plugin-sdk';
import type { NodeEvidence } from './types';
import type { Language } from './i18n';

export type Diagram = { html: string; node: string; revision: string; warnings: string[]; renderer: string };
const topologyRequests = new Map<string, Promise<Diagram>>();

export function loadTopology(nodeName: string, language: Language, revision: string, retry = false): Promise<Diagram> {
  const key = `${revision}\u0000${language}\u0000${nodeName}`;
  if (retry) topologyRequests.delete(key);
  const cached = topologyRequests.get(key);
  if (cached) return cached;
  const request = consoleFetchJSON(`/api/proxy/plugin/network-guardrail/api/topology/${encodeURIComponent(nodeName)}?lang=${language}`)
    .then((response: Diagram) => {
      if (!response || typeof response.html !== 'string' || response.node !== nodeName || response.revision !== revision) throw new Error('Invalid topology response');
      return response;
    })
    .catch((reason: unknown) => {
      topologyRequests.delete(key);
      throw reason;
    });
  topologyRequests.set(key, request);
  return request;
}

export function prefetchTopologies(nodes: NodeEvidence[], language: Language, revision: string) {
  // The backend deliberately exposes only two renderer slots. Queue discovery
  // prefetches so opening a tab can share the current request instead of
  // competing with three simultaneous renders and receiving a 429.
  let queue = Promise.resolve();
  nodes.forEach(node => {
    queue = queue.then(() => loadTopology(node.name, language, revision).then(() => undefined).catch(() => undefined));
  });
}

function embeddedDiagram(html: string) {
  const style = `<style id="network-guardrail-embedded-diagram">
html[data-embed="true"] body { height: auto !important; min-height: 0 !important; padding: 0 !important; overflow: hidden !important; }
html[data-embed="true"] .container { height: auto !important; min-height: 0 !important; }
html[data-embed="true"] .diagram-container { flex: none !important; min-height: 0 !important; }
html[data-embed="true"] .diagram-container > svg { flex: none !important; height: auto !important; min-height: 0 !important; width: 100% !important; }
</style>`;
  const reporter = `<script>
(function () {
  function report() {
    var root = document.documentElement, body = document.body, container = document.querySelector('.container');
    var height = Math.max(root ? root.scrollHeight : 0, body ? body.scrollHeight : 0, container ? container.getBoundingClientRect().bottom : 0);
    if (window.parent !== window && isFinite(height)) window.parent.postMessage({ type: 'network-guardrail-topology-height', height: Math.ceil(height) }, '*');
  }
  function schedule() { requestAnimationFrame(function () { requestAnimationFrame(report); }); }
  window.addEventListener('load', schedule);
  if (document.readyState !== 'loading') schedule(); else document.addEventListener('DOMContentLoaded', schedule);
  if (typeof ResizeObserver === 'function') {
    var observer = new ResizeObserver(schedule);
    if (document.documentElement) observer.observe(document.documentElement);
    if (document.body) observer.observe(document.body);
  }
}());
</script>`;
  const embedded = html.replace(/<html\b/i, '<html data-embed="true"');
  return embedded.replace('</head>', `${style}</head>`).replace('</body>', `${reporter}</body>`);
}
const labels = {
  en: { loading: 'Generating Archify topology from current node evidence…', error: 'Topology could not be generated', retry: 'Retry', present: 'Present full screen', exit: 'Exit full screen', openFull: 'Open full architecture', download: 'Download interactive HTML', description: 'The embedded view is a clean diagram. Open the full architecture for Archify controls and exports.', title: 'Interactive network topology', revision: 'Inventory revision' },
  'zh-CN': { loading: '正在根据当前节点证据生成 Archify 拓扑…', error: '拓扑生成失败', retry: '重试', present: '全屏演示', exit: '退出全屏', openFull: '打开完整架构图', download: '下载交互式 HTML', description: '嵌入区域只显示简洁架构图；打开完整架构图可使用 Archify 控件和导出功能。', title: '交互式网络拓扑', revision: '清单版本' },
  'zh-TW': { loading: '正在根據目前節點證據產生 Archify 拓樸…', error: '拓樸產生失敗', retry: '重試', present: '全螢幕展示', exit: '退出全螢幕', openFull: '開啟完整架構圖', download: '下載互動式 HTML', description: '嵌入區域只顯示簡潔架構圖；開啟完整架構圖可使用 Archify 控件和匯出功能。', title: '互動式網路拓樸', revision: '清單版本' },
};

export default function TopologyViewer({ node, language, revision }: { node: NodeEvidence; language: Language; revision: string }) {
  const [diagram, setDiagram] = React.useState<Diagram>();
  const [error, setError] = React.useState('');
  const [attempt, setAttempt] = React.useState(0);
  const [fullscreen, setFullscreen] = React.useState(false);
  const [frameHeight, setFrameHeight] = React.useState(680);
  const container = React.useRef<HTMLDivElement>(null);
  const frame = React.useRef<HTMLIFrameElement>(null);
  const t = labels[language];
  const fullViewerUrl = React.useMemo(() => diagram ? URL.createObjectURL(new Blob([diagram.html], { type: 'text/html;charset=utf-8' })) : '', [diagram]);
  React.useEffect(() => () => { if (fullViewerUrl) URL.revokeObjectURL(fullViewerUrl); }, [fullViewerUrl]);
  React.useEffect(() => {
    let current = true;
    setDiagram(undefined); setError('');
    loadTopology(node.name, language, revision, attempt > 0)
      .then(response => { if (current) setDiagram(response); })
      .catch((reason: unknown) => { if (current) setError(reason instanceof Error ? reason.message : String(reason)); });
    return () => { current = false; };
  }, [node.name, language, revision, attempt]);
  React.useEffect(() => {
    const onMessage = (event: MessageEvent) => {
      if (event.source !== frame.current?.contentWindow || event.data?.type !== 'network-guardrail-topology-height') return;
      const height = Number(event.data.height);
      if (Number.isFinite(height)) setFrameHeight(Math.max(440, Math.min(2400, Math.ceil(height))));
    };
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, []);
  React.useEffect(() => {
    const update = () => setFullscreen(document.fullscreenElement === container.current);
    document.addEventListener('fullscreenchange', update);
    return () => document.removeEventListener('fullscreenchange', update);
  }, []);
  const present = async () => {
    try {
      if (document.fullscreenElement === container.current) await document.exitFullscreen();
      else await container.current?.requestFullscreen();
    } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); }
  };
  const download = () => {
    if (!diagram) return;
    const objectURL = URL.createObjectURL(new Blob([diagram.html], { type: 'text/html;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = objectURL; link.download = `network-guardrail-${node.name}-${language}.html`;
    document.body.appendChild(link); link.click(); link.remove();
    window.setTimeout(() => URL.revokeObjectURL(objectURL), 30000);
  };
  return <div ref={container} data-testid="topology-viewer" style={{ display: 'flex', flexDirection: 'column', gap: 10, padding: fullscreen ? 18 : 0, height: fullscreen ? '100vh' : 'auto', boxSizing: 'border-box', background: fullscreen ? '#f4f6f9' : undefined, color: fullscreen ? '#17202d' : undefined }}>
    <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8 }}>
      <strong>{t.title}</strong>
      {diagram && <span style={{ fontSize: 12 }}>{diagram.renderer} · {t.revision}: {diagram.revision}</span>}
      <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
        <button className="ng-button" type="button" onClick={present} disabled={!diagram}>{fullscreen ? t.exit : t.present}</button>
        {diagram && fullViewerUrl && <a className="ng-button" data-testid="topology-full-link" href={fullViewerUrl} target="_blank" rel="noopener noreferrer">{t.openFull}</a>}
        <button className="ng-button" type="button" onClick={download} disabled={!diagram}>{t.download}</button>
      </div>
    </div>
    <p style={{ margin: 0, fontSize: 13 }}>{t.description}</p>
    {diagram?.warnings?.map((warning, index) => <p key={index} role="note" style={{ margin: 0, fontSize: 12 }}>{warning}</p>)}
    {error && <div role="alert">{t.error}: {error} <button className="ng-button" type="button" onClick={() => setAttempt(x => x + 1)}>{t.retry}</button></div>}
    {!diagram && !error && <div role="status">{t.loading}</div>}
    {diagram && <iframe ref={frame} title={`${t.title}: ${node.name}`} srcDoc={embeddedDiagram(diagram.html)} sandbox="allow-scripts allow-downloads" allow="fullscreen; clipboard-write" allowFullScreen scrolling="no" referrerPolicy="no-referrer" style={{ width: '100%', height: fullscreen ? 'calc(100vh - 90px)' : `${frameHeight}px`, overflow: 'hidden', border: '1px solid #ccd3df', borderRadius: 10, background: '#fff' }} />}
  </div>;
}
