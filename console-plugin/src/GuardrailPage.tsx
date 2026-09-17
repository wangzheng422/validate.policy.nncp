// AI-Author: Codex (OpenAI model not exposed by runtime)
import * as React from 'react';
import { consoleFetchJSON } from '@openshift-console/dynamic-plugin-sdk';
import { languages, Language, translations, Texts } from './i18n';
import { Overview, Inventory, Policies, Events, Preflight, Control, ControlMode, Examples } from './types';
import TopologyViewer, { prefetchTopologies } from './TopologyViewer';
import './style.css';

const API = '/api/proxy/plugin/network-guardrail/api';
type Tab = 'overview' | 'path' | 'policies' | 'history' | 'preflight';
const tabs: Tab[] = ['overview', 'path', 'policies', 'history', 'preflight'];
const json = (value: unknown) => JSON.stringify(value, null, 2);
const display = (value: unknown, fallback: string) => value === undefined || value === null || value === '' ? fallback : String(value);
function useEvidence<T>(endpoint: string, revision: number) {
  const [state, setState] = React.useState<{ data?: T; error?: string; loading: boolean }>({ loading: true });
  React.useEffect(() => {
    let current = true;
    setState({ loading: true });
    consoleFetchJSON(`${API}/${endpoint}`).then((data: T) => { if (current) setState({ data, loading: false }); })
      .catch((error: Error) => { if (current) setState({ error: error.message, loading: false }); });
    return () => { current = false; };
  }, [endpoint, revision]);
  return state;
}
function Warnings({ items, t }: { items?: string[]; t: Texts }) {
  return items?.length ? <aside className="ng-warning" role="status"><strong>{t.warnings}</strong><ul>{items.map((item, i) => <li key={i}>{item}</li>)}</ul></aside> : null;
}
function LoadState({ state, t }: { state: {loading: boolean; error?: string}; t: Texts }) {
  return state.loading ? <p role="status">{t.loading}</p> : state.error ? <div className="ng-error" role="alert"><strong>{t.failed}</strong><p>{state.error}</p></div> : null;
}
function download(name: string, yaml: string) {
  const url = URL.createObjectURL(new Blob([yaml], { type: 'application/yaml;charset=utf-8' }));
  const link = document.createElement('a'); link.href = url; link.download = `${name.replace(/[^a-zA-Z0-9_.-]/g, '_')}.yaml`;
  document.body.appendChild(link); link.click(); link.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function Yaml({ name, value, t }: {name: string; value: string; t: Texts}) {
  return <details className="ng-details"><summary>{t.reviewYaml}</summary><div className="ng-yaml-actions"><button className="ng-button" onClick={() => download(name, value)}>{t.download}</button></div><pre aria-label={t.content}>{value}</pre></details>;
}
function Paths({ data, t, language }: {data: Inventory; t: Texts; language: Language}) {
  const [selected, setSelected] = React.useState('');
  const node = data.nodes.find(item => item.name === selected) || data.nodes[0];
  return <><div className="ng-meta"><span>{t.revision}: <code>{display(data.revision, t.noData)}</code></span><span>{t.discovery}: {display(data.discoveredAt, t.noData)}</span></div>
    <Warnings items={data.warnings} t={t}/><p className="ng-muted">{t.sourceHint}</p>
    {!node ? <p>{t.noNodes}</p> : <><label className="ng-label">{t.node}<select value={node.name} onChange={e => setSelected(e.target.value)}>{data.nodes.map(item => <option key={item.name}>{item.name}</option>)}</select></label>
      <section className="ng-card"><div className="ng-section-title"><h2>{node.name}</h2><span className={`ng-badge ${node.ready ? 'ng-good' : 'ng-neutral'}`}>{node.ready ? t.ready : t.notReady}</span></div>
        <p>{t.roles}: {(node.roles || []).join(', ') || t.noData}</p><TopologyViewer node={node} language={language} revision={data.revision}/>
        <p><strong>{t.protected}: </strong>{node.protectedInterfaces?.map(item => <code className="ng-chip" key={item}>{item}</code>)}</p>
        <Warnings items={node.warnings} t={t}/>
        <details className="ng-details"><summary>{t.connections}</summary>{node.edges?.length ? <ul>{node.edges.map((edge, i) => <li key={i}><code>{edge.from}</code> → <code>{edge.to}</code></li>)}</ul> : <p>{t.noConnections}</p>}</details>
        <details className="ng-details"><summary>{t.routes}</summary><pre>{json(node.defaultRoutes)}</pre></details>
        <details className="ng-details"><summary>{t.evidence}</summary><p>{t.technical}</p><pre>{json(node.evidence)}</pre></details>
      </section></>}
  </>;
}
function PolicyView({data, t}: {data: Policies; t: Texts}) {
  return <><Warnings items={data.warnings} t={t}/><p>{t.activeRevision}: <code>{display(data.activeRevision, t.noData)}</code></p>
    {!data.items.length && <p>{t.noPolicies}</p>}
    {data.items.map(policy => <section className="ng-card" key={`${policy.kind}/${policy.name}`}><div className="ng-section-title"><div><p className="ng-eyebrow">{policy.kind}</p><h2>{policy.name}</h2></div><span className={`ng-badge ${policy.active ? 'ng-info' : 'ng-neutral'}`}>{policy.active ? t.active : t.inactive}</span></div>
      <div className="ng-rule-grid">{(policy.rules || []).map(rule => <article className="ng-rule" key={rule.id}><p className="ng-eyebrow">{rule.category}</p><h3>{rule.id}</h3><p>{rule.message}</p><details><summary>{t.expression}</summary><pre>{rule.expression}</pre></details></article>)}</div>
      <Yaml name={policy.name} value={policy.yaml} t={t}/>
    </section>)}
    {data.candidate && <section className="ng-card"><div className="ng-section-title"><h2>{t.candidate}</h2><span className={`ng-badge ${data.candidate.ready ? 'ng-info' : 'ng-neutral'}`}>{data.candidate.ready ? t.candidateReady : t.candidateIncomplete}</span></div><p>{t.candidateHint}</p><p>{t.revision}: <code>{display(data.candidate.revision, t.noData)}</code></p><Yaml name="network-guardrail-candidate" value={data.candidate.yaml} t={t}/></section>}
  </>;
}
type EvidenceState<T> = {data?: T; error?: string; loading: boolean};
async function requestFailure(error: unknown) {
  const value = error as {code?: number; response?: Response; json?: {error?: string; partial?: boolean}; message?: string};
  let body = value?.json;
  if (!body && value?.response) { try { body = await value.response.clone().json(); } catch { /* Retain the transport message. */ } }
  return {code: Number(value?.code || value?.response?.status || 0), message: body?.error || value?.message || String(error), partial: body?.partial};
}
function ControlPanel({state, t, onRefresh}: {state: EvidenceState<Control>; t: Texts; onRefresh: () => void}) {
  const [mode, setMode] = React.useState<ControlMode>('Deny');
  const [acceptedFor, setAcceptedFor] = React.useState<string>();
  const [busy, setBusy] = React.useState(false);
  const [notice, setNotice] = React.useState<{success: boolean; code?: number; message: string; partial?: boolean}>();
  const data = state.data;
  const reviewKey = data ? `${data.candidate.revision}|${data.candidate.ready}|${data.bindingResourceVersion}|${data.state}|${mode}` : '';
  const accepted = Boolean(reviewKey && acceptedFor === reviewKey);
  const permitted = data && (mode === 'Disabled' ? data.capabilities.canDisable : data.capabilities.canEnable);
  const ready = data && (mode === 'Disabled' || (data.candidate.ready && Boolean(data.candidate.yaml.trim()) && data.state !== 'Unknown'));
  const change = async (next: ControlMode) => {
    if (!data || busy || !accepted || state.loading) return;
    if (next === 'Disabled' ? !data.capabilities.canDisable : !data.capabilities.canEnable || !data.candidate.ready || !data.candidate.yaml.trim()) return;
    setBusy(true); setNotice(undefined);
    try {
      const response = await consoleFetchJSON.post(`${API}/control`, {mode: next, revision: data.candidate.revision, bindingResourceVersion: data.bindingResourceVersion, confirm: true});
      setNotice({success: true, message: response.message || ''});
    } catch (error) {
      const failure = await requestFailure(error); setNotice({success: false, ...failure});
    } finally { setBusy(false); setAcceptedFor(undefined); onRefresh(); }
  };
  return <section className="ng-card ng-control" aria-labelledby="ng-control-title">
    <h2 id="ng-control-title">{t.controlTitle}</h2><p>{t.controlScope}</p><LoadState state={state} t={t}/>
    {notice && <aside role={notice.success ? 'status' : 'alert'} className={notice.success ? 'ng-note' : 'ng-error'}><strong>{notice.success ? t.controlSuccess : notice.code === 409 ? t.controlConflict : notice.code === 403 ? t.controlForbidden : t.controlFailure}</strong><p>{notice.message}</p>{notice.partial && <p>{t.controlPartial}</p>}</aside>}
    {data && <><p><strong>{t.currentMode}: </strong><span className="ng-badge ng-info">{t[data.state]}</span></p><Warnings items={data.warnings} t={t}/>
      <div className="ng-control-review"><p>{t.reviewedRevision}: <code>{data.candidate.revision || t.noData}</code></p><p>{t.activeRevision}: <code>{data.approvedRevision || t.noData}</code></p>
        <details className="ng-details"><summary>{t.reviewYaml}</summary><pre aria-label={t.content}>{data.candidate.yaml || t.noData}</pre></details>
      </div>
      <label className="ng-label" htmlFor="ng-control-mode">{t.targetMode}</label><select id="ng-control-mode" value={mode} disabled={busy} onChange={e => setMode(e.target.value as ControlMode)}>{(['Deny','Audit','Disabled'] as const).map(value => <option value={value} key={value}>{t[value]}</option>)}</select>
      <p className="ng-control-effect">{mode === 'Deny' ? t.effectDeny : mode === 'Audit' ? t.effectAudit : t.effectDisabled}</p>
      {!permitted && <p className="ng-warning">{t.noControlPermission}</p>}{!ready && <p className="ng-warning">{t.enableUnavailable}</p>}
      <label className="ng-confirm"><input type="checkbox" checked={accepted} disabled={busy} onChange={e => setAcceptedFor(e.target.checked ? reviewKey : undefined)}/><span>{t.acceptChange}</span></label>
      <div className="ng-control-actions"><button className="ng-button ng-primary" disabled={busy || !accepted || !permitted || !ready} onClick={() => change(mode)}>{busy ? t.changingMode : t.applyMode}</button><button className="ng-button ng-stop" disabled={busy || !accepted || !data.capabilities.canDisable || data.state === 'Disabled'} onClick={() => change('Disabled')}>{t.stopInterception}</button></div><p className="ng-muted">{t.effectDisabled}</p>
      <details className="ng-details"><summary>{t.permissionDetails}</summary><ul>{data.capabilities.checks.map((check,i) => <li key={i}><code>{check.verb} {check.resource}</code>: {check.allowed ? t.yes : t.no}{check.reason ? ` — ${check.reason}` : ''}</li>)}</ul></details>
    </>}
  </section>;
}
function History({data, t, focusEvent}: {data: Events; t: Texts; focusEvent?: string}) {
  const [filter, setFilter] = React.useState('');
  const items = data.items.filter(event => json(event).toLowerCase().includes(filter.toLowerCase()));
  React.useEffect(() => { if (focusEvent) document.getElementById(`ng-event-${focusEvent}`)?.scrollIntoView({block: 'center'}); }, [focusEvent, data.items]);
  return <><Warnings items={data.warnings} t={t}/><p className="ng-muted">{t.historyRecordHint}</p><label className="ng-label">{t.filter}<input type="search" value={filter} onChange={e => setFilter(e.target.value)}/></label>
    <div className="ng-table-wrap"><table><caption className="ng-sr-only">{t.history}</caption><thead><tr>{[t.time, t.actor, t.action, t.eventSource, t.object, t.rule, t.reason, t.auditID, t.details].map(name => <th scope="col" key={name}>{name}</th>)}</tr></thead><tbody>
      {!items.length && <tr><td colSpan={9}>{t.noEvents}</td></tr>}
      {items.map((event, i) => { const e = event.spec; return <tr id={`ng-event-${event.metadata?.name}`} className={event.metadata?.name === focusEvent ? 'ng-highlight' : undefined} key={event.metadata?.name || i}><td>{e.timestamp}</td><td>{e.username}</td><td><span className={`ng-badge ${e.action === 'DENY' ? 'ng-danger' : 'ng-info'}`}>{e.action}</span></td><td>{e.source === 'preflight' ? t.sourcePreflight : e.source === 'audit-log' ? t.sourceAudit : t.sourceUnknown}<small>{t.dryRun}: {e.dryRun ? t.yes : t.no}</small></td><td><code>{e.name}</code></td><td>{e.rule}</td><td>{e.reason}</td><td><code>{display(e.auditID,t.noData)}</code></td><td><details><summary>{t.details}</summary><dl>
        {[[t.eventName,event.metadata?.name],[t.verb,e.verb],[t.category,e.category],[t.policy,e.policy],[t.binding,e.binding],[t.sourceIPs,(e.sourceIPs || []).join(', ')],[t.userAgent,e.userAgent],[t.responseCode,e.responseCode]].map(([label,value]) => <React.Fragment key={label}><dt>{label}</dt><dd>{display(value,t.noData)}</dd></React.Fragment>)}
      </dl></details></td></tr>; })}
    </tbody></table></div></>;
}
function PreflightView({t, examples, onComplete, onHistory}: {t: Texts; examples: EvidenceState<Examples>; onComplete: () => void; onHistory: (eventName?: string) => void}) {
  const [yaml, setYaml] = React.useState(''); const [busy, setBusy] = React.useState(false); const [result, setResult] = React.useState<Preflight>();
  const run = async (event: React.FormEvent) => { event.preventDefault(); if (!yaml.trim() || busy) return; setBusy(true); setResult(undefined);
    try { const response = await consoleFetchJSON.post(`${API}/preflight`, { yaml }); setResult(response); }
    catch (error) { const failure = await requestFailure(error); setResult({allowed: null, outcome: 'ERROR', message: failure.message, statusCode: failure.code, warnings: [], dryRun: true}); }
    finally { setBusy(false); onComplete(); }
  };
  return <><section className="ng-card"><h2>{t.examples}</h2><p>{t.examplesHint}</p><LoadState state={examples} t={t}/><Warnings items={examples.data?.warnings} t={t}/>
    {examples.data && <div className="ng-rule-grid">{examples.data.items.length ? examples.data.items.map(example => <article className="ng-rule" key={example.id}><h3>{example.id === 'protected-primary-removal' ? t.primaryRemovalTitle : example.id === 'dns-only' ? t.dnsOnlyTitle : example.title}</h3><p>{example.id === 'protected-primary-removal' ? t.primaryRemovalDescription : example.id === 'dns-only' ? t.dnsOnlyDescription : example.description}</p><p>{t.expected}: <strong>{t[example.expectedOutcome]}</strong></p><button className="ng-button" disabled={busy} onClick={() => {setYaml(example.yaml);setResult(undefined);document.getElementById('ng-yaml')?.focus();}}>{t.loadExample}</button></article>) : <p>{t.examplesUnavailable}</p>}</div>}
    </section><p>{t.yamlHint}</p><aside className="ng-note">{t.noApply}</aside><form onSubmit={run}><label className="ng-label" htmlFor="ng-yaml">{t.yaml}</label><textarea id="ng-yaml" value={yaml} onChange={e => { setYaml(e.target.value); setResult(undefined); }} rows={18} spellCheck={false} required disabled={busy}/><button className="ng-button ng-primary" type="submit" disabled={busy || !yaml.trim()}>{busy ? t.running : t.run}</button></form>
    {result && <section aria-live="polite" className={`ng-result ${result.outcome === 'ALLOWED' ? 'ng-good' : result.outcome === 'DENIED' ? 'ng-danger' : 'ng-neutral'}`}><h2>{t[result.outcome]}</h2><p>{result.outcome === 'ALLOWED' ? t.allowedHint : result.outcome === 'DENIED' ? t.deniedHint : t.errorHint}</p><pre>{result.message}</pre><p>{t.responseCode}: {result.statusCode || t.noData}</p><p>{t.auditID}: <code>{result.auditID || t.noData}</code></p><p>{result.eventRecorded ? t.eventSaved : t.eventNotSaved}</p>{result.eventName && <p>{t.eventName}: <code>{result.eventName}</code></p>}{result.eventWarning && <p className="ng-warning">{result.eventWarning}</p>}<Warnings items={result.warnings} t={t}/><button className="ng-button" onClick={() => onHistory(result.eventName)}>{t.openHistory}</button></section>}
  </>;
}
export default function GuardrailPage() {
  const [language, setLanguage] = React.useState<Language>(() => { try { const saved = localStorage.getItem('network-guardrail-language'); return saved && saved in languages ? saved as Language : 'en'; } catch { return 'en'; } });
  const [tab, setTab] = React.useState<Tab>('overview'); const [revision, setRevision] = React.useState(0); const [focusEvent, setFocusEvent] = React.useState<string>(); const t = translations[language];
  const overview = useEvidence<Overview>('overview', revision); const inventory = useEvidence<Inventory>('inventory', revision); const policies = useEvidence<Policies>('policies', revision); const events = useEvidence<Events>('events', revision); const control = useEvidence<Control>('control', revision); const examples = useEvidence<Examples>('examples', revision);
  React.useEffect(() => {
    if (inventory.data?.ready && inventory.data.nodes.length) prefetchTopologies(inventory.data.nodes, language, inventory.data.revision);
  }, [inventory.data, language]);
  const refresh = () => setRevision(n => n + 1);
  const changeLanguage = (value: Language) => {setLanguage(value); try {localStorage.setItem('network-guardrail-language',value);} catch { /* Storage is optional. */ }};
  return <main className="ng-app" lang={language}><header className="ng-header"><div><p className="ng-eyebrow">OPENSHIFT · NETWORK GUARDRAIL</p><h1>{t.title}</h1><p>{t.subtitle}</p></div><div className="ng-toolbar"><label>{t.language}<select value={language} onChange={e => changeLanguage(e.target.value as Language)}>{Object.entries(languages).map(([value,label]) => <option value={value} key={value}>{label}</option>)}</select></label><button className="ng-button" onClick={refresh}>{t.refresh}</button></div></header>
    <nav className="ng-tabs" aria-label={t.title}>{tabs.map(value => <button key={value} className={tab === value ? 'ng-tab ng-selected' : 'ng-tab'} aria-current={tab === value ? 'page' : undefined} onClick={() => setTab(value)}>{t[value]}</button>)}</nav>
    <div className="ng-content">
      {tab === 'overview' && <><LoadState state={overview} t={t}/>{overview.data && <><section className="ng-card ng-enforcement"><div><p className="ng-eyebrow">{t.enforcement}</p><h2>{t[overview.data.enforcement.state]}</h2><p>{overview.data.enforcement.message}</p><p className="ng-muted">{t.enforcementHint}</p></div><span className={`ng-status-dot ng-state-${overview.data.enforcement.state}`} aria-hidden="true"/></section></>}<ControlPanel state={control} t={t} onRefresh={refresh}/>{overview.data && <><div className="ng-stats">{(['nodes','readyNodes','events','rules'] as const).map(key => <article className="ng-card" key={key}><p>{t[key]}</p><strong>{overview.data?.counts[key]}</strong></article>)}</div><p className="ng-muted">{t.collected}: {overview.data.collectedAt} · {t.refreshHint}</p><Warnings items={overview.data.warnings} t={t}/><div className="ng-actions"><button className="ng-card ng-action" onClick={() => setTab('path')}><h2>{t.inspect} →</h2><p>{t.inspectHint}</p></button><button className="ng-card ng-action" onClick={() => setTab('preflight')}><h2>{t.next} →</h2><p>{t.nextHint}</p></button></div></>}</>}
      {tab === 'path' && <><LoadState state={inventory} t={t}/>{inventory.data && <Paths data={inventory.data} t={t} language={language}/>}</>}
      {tab === 'policies' && <><LoadState state={policies} t={t}/>{policies.data && <PolicyView data={policies.data} t={t}/>}</>}
      {tab === 'history' && <><LoadState state={events} t={t}/>{events.data && <History data={events.data} t={t} focusEvent={focusEvent}/>}</>}
      {tab === 'preflight' && <PreflightView t={t} examples={examples} onComplete={refresh} onHistory={eventName => {setFocusEvent(eventName);setTab('history');refresh();}}/>}
    </div>
  </main>;
}
