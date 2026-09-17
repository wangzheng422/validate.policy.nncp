// AI-Author: Codex (OpenAI model not exposed by runtime)
export type Overview = { collectedAt: string; enforcement: {state: 'Disabled' | 'Audit' | 'Deny' | 'Unknown'; message: string}; counts: {nodes: number; readyNodes: number; events: number; rules: number}; warnings: string[] };
export type NodeEvidence = {name: string; roles: string[]; ready: boolean; protectedInterfaces: string[]; primaryPath: string[]; defaultRoutes: unknown[]; edges: {from: string; to: string}[]; evidence: unknown[]; warnings: string[]};
export type Inventory = {nodes: NodeEvidence[]; revision: string; discoveredAt: string; ready: boolean; warnings: string[]};
export type Policy = {name: string; kind: string; active: boolean; rules: {id: string; category: string; message: string; expression: string}[]; yaml: string};
export type Policies = {items: Policy[]; candidate: {revision: string; ready: boolean; yaml: string}; activeRevision: string; warnings: string[]};
export type AuditEvent = {metadata: {name: string}; spec: {source?: 'preflight' | 'audit-log'; timestamp: string; username: string; sourceIPs: string[]; userAgent: string; verb: string; name: string; action: 'DENY' | 'AUDIT'; reason: string; rule: string; category: string; policy: string; binding: string; auditID: string; dryRun: boolean; responseCode: number; expressionIndex: number}};
export type Events = {items: AuditEvent[]; warnings: string[]};
export type Preflight = {eventRecorded?: boolean; eventName?: string; eventWarning?: string; allowed: boolean | null; outcome: 'ALLOWED' | 'DENIED' | 'ERROR'; message: string; statusCode: number; warnings: string[]; dryRun: true; auditID?: string};

export type ControlMode = 'Deny' | 'Audit' | 'Disabled';
export type Control = {
  state: ControlMode | 'Unknown'; bindingResourceVersion: string;
  candidate: {revision: string; ready: boolean; yaml: string}; approvedRevision: string;
  capabilities: {canEnable: boolean; canDisable: boolean; canRecordEvents: boolean; checks: {resource: string; verb: string; allowed: boolean; reason: string}[]};
  warnings: string[]; message?: string;
};
export type Examples = {items: {id: string; title: string; description: string; yaml: string; expectedOutcome: 'ALLOWED' | 'DENIED'}[]; warnings?: string[]};
