#!/usr/bin/env python3
# AI-Author: Codex (OpenAI model not exposed by runtime)
"""Run real local Kubernetes admission tests without any external kubeconfig.

Requires official envtest binaries, Python/PyYAML, and openssl. Starts only
loopback API/etcd processes; no nodes or NMState operator are installed.
"""
import argparse
import copy
import datetime
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from guardrail.audit import events_from_audit  # noqa: E402
from guardrail.kube import APIError  # noqa: E402
from guardrail.preflight import preflight  # noqa: E402

NNCP = '/apis/nmstate.io/v1/nodenetworkconfigurationpolicies'
VAP = '/apis/admissionregistration.k8s.io/v1beta1/validatingadmissionpolicies'
BIND = '/apis/admissionregistration.k8s.io/v1beta1/validatingadmissionpolicybindings'
PARAM = '/apis/guardrail.openshift.io/v1alpha1/networkguardrailparameters'
HOST = 'kubernetes.io/hostname'


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Lab:
    def __init__(self, binaries):
        self.binaries = binaries
        self.directory = Path(tempfile.mkdtemp(prefix='network-guardrail-admission-'))
        self.processes, self.logs, self.rows = [], [], []
        self.token = secrets.token_urlsafe(48)
        self.audit = self.directory / 'audit.jsonl'

    def start_process(self, args, name):
        output = (self.directory / (name + '.log')).open('w')
        self.logs.append(output)
        self.processes.append(subprocess.Popen(args, stdout=output, stderr=subprocess.STDOUT))

    def start(self):
        p = self.directory
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(p / 'key.pem'), '-out', str(p / 'cert.pem'),
                        '-days', '1', '-subj', '/CN=localhost', '-addext',
                        'subjectAltName=IP:127.0.0.1,DNS:localhost'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.chmod(p / 'key.pem', 0o600)
        (p / 'tokens.csv').write_text(self.token + ',test-admin,test-admin,"system:masters"\n')
        os.chmod(p / 'tokens.csv', 0o600)
        # Metadata captures policy annotations without recording NNCP request bodies.
        (p / 'audit-policy.yaml').write_text('apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n'
                                           '- level: Metadata\n  resources:\n'
                                           '  - group: nmstate.io\n    resources: [nodenetworkconfigurationpolicies]\n'
                                           '- level: None\n')
        etcd_port, peer_port, api_port = port(), port(), port()
        self.url = 'https://127.0.0.1:' + str(api_port)
        self.context = ssl.create_default_context(cafile=str(p / 'cert.pem'))
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                 urllib.request.HTTPSHandler(context=self.context))
        self.start_process([str(self.binaries / 'etcd'), '--name=test', '--data-dir=' + str(p / 'etcd'),
                            '--listen-client-urls=http://127.0.0.1:' + str(etcd_port),
                            '--advertise-client-urls=http://127.0.0.1:' + str(etcd_port),
                            '--listen-peer-urls=http://127.0.0.1:' + str(peer_port),
                            '--initial-advertise-peer-urls=http://127.0.0.1:' + str(peer_port),
                            '--initial-cluster=test=http://127.0.0.1:' + str(peer_port)], 'etcd')
        self.start_process([str(self.binaries / 'kube-apiserver'), '--bind-address=127.0.0.1',
                            '--advertise-address=127.0.0.1', '--secure-port=' + str(api_port),
                            '--etcd-servers=http://127.0.0.1:' + str(etcd_port),
                            '--etcd-prefix=/isolated-guardrail-test', '--authorization-mode=RBAC',
                            '--anonymous-auth=false', '--token-auth-file=' + str(p / 'tokens.csv'),
                            '--tls-cert-file=' + str(p / 'cert.pem'), '--tls-private-key-file=' + str(p / 'key.pem'),
                            '--service-account-issuer=https://guardrail.test.invalid',
                            '--service-account-signing-key-file=' + str(p / 'key.pem'),
                            '--service-account-key-file=' + str(p / 'key.pem'),
                            '--service-cluster-ip-range=10.200.0.0/24',
                            '--feature-gates=ValidatingAdmissionPolicy=true',
                            '--enable-admission-plugins=ValidatingAdmissionPolicy',
                            '--runtime-config=admissionregistration.k8s.io/v1beta1=true',
                            '--audit-policy-file=' + str(p / 'audit-policy.yaml'),
                            '--audit-log-path=' + str(self.audit), '--audit-log-mode=blocking'], 'apiserver')
        self.wait(lambda: self.request('GET', '/readyz')[0] == 200, 'API readiness', 45)

    def request(self, method, path, obj=None):
        data = None if obj is None else json.dumps(obj).encode()
        req = urllib.request.Request(self.url + path, data=data, method=method,
                                     headers={'Authorization': 'Bearer ' + self.token,
                                              'Content-Type': 'application/json', 'User-Agent': 'guardrail-local-test'})
        try:
            with self.opener.open(req, timeout=10) as response:
                raw = response.read().decode()
                return response.status, json.loads(raw) if raw.startswith('{') else raw
        except urllib.error.HTTPError as error:
            raw = error.read().decode()
            return error.code, json.loads(raw) if raw.startswith('{') else raw
        except (urllib.error.URLError, TimeoutError):
            return 0, 'connection unavailable'

    def ok(self, method, path, obj=None):
        code, body = self.request(method, path, obj)
        if not 200 <= code < 300:
            with (self.directory / 'setup-errors.jsonl').open('a') as evidence:
                evidence.write(json.dumps({'aiAuthor': 'Codex (OpenAI model not exposed by runtime)',
                                           'method': method, 'path': path, 'httpStatus': code,
                                           'response': body}) + '\n')
        assert 200 <= code < 300, (method, path, code, body)
        return body

    def wait(self, fn, label, timeout=20):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if fn():
                return
            if any(proc.poll() is not None for proc in self.processes):
                raise AssertionError('local process exited; inspect ' + str(self.directory))
            time.sleep(.2)
        raise AssertionError('timed out: ' + label + '; inspect ' + str(self.directory))

    def fixture(self, path):
        obj = yaml.safe_load(path.read_text())
        self.ok('POST', '/apis/apiextensions.k8s.io/v1/customresourcedefinitions', obj)
        crd_path = '/apis/apiextensions.k8s.io/v1/customresourcedefinitions/' + obj['metadata']['name']
        self.wait(lambda: any(c['type'] == 'Established' and c['status'] == 'True'
                              for c in self.ok('GET', crd_path).get('status', {}).get('conditions', [])),
                  'CRD established')

    def parameters(self, ready=True):
        nodes = []
        for name, role in [('worker-0', 'worker'), ('worker-1', 'worker'), ('master-0', 'master'), ('master-1', 'master')]:
            nodes.append({'name': name, 'labels': {HOST: name, 'node-role.kubernetes.io/' + role: ''},
                          'roles': [role], 'protectedInterfaces': ['br-ex', 'enp4s3', 'primary-profile', 'primary-alt'], 'ready': True})
        return {'apiVersion': 'guardrail.openshift.io/v1alpha1', 'kind': 'NetworkGuardrailParameters',
                'metadata': {'name': 'reviewed'}, 'spec': {'revision': 'test-local-1', 'ready': ready,
                'protectedInterfaces': ['br-ex', 'enp4s3', 'primary-profile', 'primary-alt', 'ovn-k8s-mp0', 'br-int'], 'nodes': nodes}}

    def binding(self, actions):
        return {'apiVersion': 'admissionregistration.k8s.io/v1beta1', 'kind': 'ValidatingAdmissionPolicyBinding',
                'metadata': {'name': 'network-guardrail-test'}, 'spec': {'policyName': 'network-guardrail',
                'paramRef': {'name': 'reviewed', 'parameterNotFoundAction': 'Deny'}, 'validationActions': actions}}

    def replace(self, path, obj):
        obj = copy.deepcopy(obj)
        obj['metadata']['resourceVersion'] = self.ok('GET', path)['metadata']['resourceVersion']
        self.ok('PUT', path, obj)

    def case(self, name, obj, rule=None, method='POST', path=NNCP, missing=True):
        obj = copy.deepcopy(obj)
        obj['metadata']['name'] = name
        code, body = self.request(method, path + '?dryRun=All', obj)
        message = body.get('message', '') if isinstance(body, dict) else str(body)
        confirmed_missing = False
        if missing:
            lookup, result = self.request('GET', NNCP + '/' + name)
            confirmed_missing = lookup == 404 and result.get('reason') == 'NotFound'
        with (self.directory / 'cases.jsonl').open('a') as evidence:
            evidence.write(json.dumps({'aiAuthor': 'Codex (OpenAI model not exposed by runtime)',
                                       'case': name, 'method': method, 'httpStatus': code,
                                       'expectedRule': rule, 'response': body,
                                       'confirmedNotFound': confirmed_missing}) + '\n')
        if missing:
            assert confirmed_missing, (name, 'unexpected persistence', lookup)
        if rule is None:
            assert 200 <= code < 300, (name, code, body)
        else:
            assert code in (403, 422) and 'network-guardrail' in message and rule in message, (name, rule, code, body)
        self.rows.append((name, method, code, rule or 'allowed', message))
        print(f'PASS {name}: {method} {code} {rule or "allowed"}', flush=True)

    def audit_events(self):
        result = []
        if self.audit.exists():
            for line in self.audit.read_text().splitlines():
                try:
                    result.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return result

    def close(self):
        for proc in reversed(self.processes):
            if proc.poll() is None:
                proc.terminate()
        for proc in reversed(self.processes):
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        for stream in self.logs:
            stream.close()
        for name in ['tokens.csv', 'key.pem']:
            (self.directory / name).unlink(missing_ok=True)


def nncp(desired=None):
    return {'apiVersion': 'nmstate.io/v1', 'kind': 'NodeNetworkConfigurationPolicy',
            'metadata': {'name': 'placeholder'}, 'spec': {'nodeSelector': {HOST: 'worker-0'},
            'maxUnavailable': 1, 'desiredState': desired if desired is not None else
            {'interfaces': [{'name': 'enp8s0', 'type': 'ethernet', 'state': 'up'}]}}}


def run(lab):
    lab.start()
    lab.fixture(ROOT / 'tests/fixtures/nncp-crd.yaml')
    lab.fixture(ROOT / 'charts/network-guardrail/crds/networkguardrailparameters.yaml')
    lab.ok('POST', PARAM, lab.parameters())
    lab.ok('POST', VAP, yaml.safe_load((ROOT / 'policies/nncp-policy.yaml').read_text()))
    bad = nncp({'interfaces': [{'name': 'br-ex', 'state': 'absent'}]})
    lab.case('no-binding', bad)
    lab.ok('POST', BIND, lab.binding(['Audit']))
    lab.wait(lambda: lab.request('POST', NNCP + '?dryRun=All', dict(bad, metadata={'name': 'audit-canary'}))[0] == 201
             and any(events_from_audit(e) for e in lab.audit_events()), 'Audit annotation')
    lab.case('audit-allows', bad)
    lab.replace(BIND + '/network-guardrail-test', lab.binding(['Deny', 'Audit']))
    lab.wait(lambda: 'GR-003' in str(lab.request('POST', NNCP + '?dryRun=All', dict(bad, metadata={'name': 'deny-canary'})))
             and lab.request('POST', NNCP + '?dryRun=All', dict(bad, metadata={'name': 'deny-canary'}))[0] in (403, 422),
             'Deny enforcement')
    lab.case('protected-br-ex', bad, 'GR-003')
    lab.case('protected-primary', nncp({'interfaces': [{'name': 'enp4s3', 'state': 'down'}]}), 'GR-003')
    for name, destination in [('default-ipv4', '0.0.0.0/0'), ('default-ipv6', '::/0'),
                              ('default-ipv4-zero-padded-prefix', '0.0.0.0/00'),
                              ('default-ipv6-zero-padded-prefix', '0:0:0:0:0:0:0:0/00')]:
        lab.case(name, nncp({'routes': {'config': [{'destination': destination, 'next-hop-interface': 'enp8s0'}]}}), 'GR-007')
    lab.case('primary-route', nncp({'routes': {'config': [{'destination': '192.0.2.0/24', 'next-hop-interface': 'enp4s3'}]}}), 'GR-007')
    lab.case('new-bond-primary', nncp({'interfaces': [{'name': 'bond-secondary', 'type': 'bond',
             'link-aggregation': {'mode': 'active-backup', 'port': ['enp4s3', 'enp8s0']}}]}), 'GR-006')
    lab.case('new-bridge-primary', nncp({'interfaces': [{'name': 'br-new', 'type': 'linux-bridge',
             'bridge': {'port': [{'name': 'enp4s3'}]}}]}), 'GR-006')
    lab.case('new-vlan-primary', nncp({'interfaces': [{'name': 'vlan-100', 'type': 'vlan',
             'vlan': {'base-iface': 'enp4s3', 'id': 100}}]}), 'GR-006')
    lab.case('controller-primary', nncp({'interfaces': [{'name': 'enp8s0', 'controller': 'br-ex'}]}), 'GR-006')
    lab.case('new-vrf-primary', nncp({'interfaces': [{'name': 'vrf-new', 'type': 'vrf',
             'vrf': {'port': ['enp4s3'], 'route-table-id': 100}}]}), 'GR-006')
    for alias in ['primary-profile', 'primary-alt']:
        lab.case('protected-' + alias, nncp({'interfaces': [{'name': alias, 'state': 'down'}]}), 'GR-003')
    lab.case('bridge-primary-alias', nncp({'interfaces': [{'name': 'br-new', 'type': 'linux-bridge',
             'bridge': {'port': [{'name': 'primary-profile'}]}}]}), 'GR-006')
    lab.case('mac-identifier', nncp({'interfaces': [{'name': 'alias-primary', 'type': 'ethernet',
             'identifier': 'mac-address', 'mac-address': '02:00:00:00:00:01', 'state': 'down'}]}), 'GR-009')
    lab.case('pci-identifier', nncp({'interfaces': [{'name': 'alias-primary', 'type': 'ethernet',
             'identifier': 'pci-address', 'pci-address': '0000:01:00.0', 'state': 'down'}]}), 'GR-009')
    lab.case('profile-name', nncp({'interfaces': [{'name': 'enp8s0', 'profile-name': 'secondary-profile', 'state': 'up'}]}), 'GR-009')
    lab.case('interface-wildcard', nncp({'interfaces': [{'name': 'enp*', 'state': 'down'}]}), 'GR-009')
    lab.case('sriov-indirect-name', nncp({'interfaces': [{'name': 'sriov:enp4s3:0', 'state': 'down'}]}), 'GR-009')
    captured = nncp({'interfaces': [{'name': '{{ capture.primary.interfaces.0.name }}', 'state': 'down'}]})
    captured['spec']['capture'] = {'primary': 'interfaces.name == "enp4s3"'}
    lab.case('capture-interface', captured, 'GR-009')
    captured_route = nncp({'routes': {'config': [{'destination': '{{ capture.default.routes.running.0.destination }}',
                         'next-hop-interface': '{{ capture.default.routes.running.0.next-hop-interface }}', 'state': 'absent'}]}})
    captured_route['spec']['capture'] = {'default': 'routes.running.destination == "0.0.0.0/0"'}
    lab.case('capture-route', captured_route, 'GR-007')
    automatic = {'enabled': True, 'dhcp': True, 'auto-routes': False, 'auto-gateway': False, 'auto-dns': False}
    lab.case('dhcp-defaults', nncp({'interfaces': [{'name': 'enp8s0', 'type': 'ethernet',
             'ipv4': {'enabled': True, 'dhcp': True}}]}), 'GR-010')
    for option in ['auto-routes', 'auto-gateway', 'auto-dns']:
        dynamic = copy.deepcopy(automatic)
        del dynamic[option]
        lab.case('dhcp-missing-' + option, nncp({'interfaces': [{'name': 'enp8s0', 'type': 'ethernet', 'ipv4': dynamic}]}), 'GR-010')
    lab.case('autoconf-defaults', nncp({'interfaces': [{'name': 'enp8s0', 'type': 'ethernet',
             'ipv6': {'enabled': True, 'dhcp': True, 'autoconf': True}}]}), 'GR-010')
    lab.case('safe-dhcp-no-auto', nncp({'interfaces': [{'name': 'enp8s0', 'type': 'ethernet', 'ipv4': automatic}]}))
    lab.case('safe-autoconf-no-auto', nncp({'interfaces': [{'name': 'enp8s0', 'type': 'ethernet',
             'ipv6': dict(automatic, autoconf=True)}]}))
    dns = {'dns-resolver': {'config': {'server': ['192.0.2.53']}}}
    mixed = copy.deepcopy(dns)
    mixed['interfaces'] = [{'name': 'enp8s0', 'state': 'up'}]
    lab.case('dns-with-interface', nncp(mixed), 'GR-005')
    for name, value in [('missing', None), ('string', '1'), ('percent', '50%'), ('two', 2)]:
        obj = nncp()
        if value is None:
            del obj['spec']['maxUnavailable']
        else:
            obj['spec']['maxUnavailable'] = value
        lab.case('maxunavailable-' + name, obj, 'GR-002')
    for name, selector, rule in [('empty', {}, 'GR-001'), ('broad', {'node-role.kubernetes.io/worker': ''}, 'GR-008'),
                                  ('unknown', {HOST: 'unknown'}, 'GR-001'),
                                  ('masters', {'node-role.kubernetes.io/master': ''}, 'GR-004')]:
        obj = nncp()
        obj['spec']['nodeSelector'] = selector
        lab.case('selector-' + name, obj, rule)
    lab.case('safe-secondary', nncp())
    lab.case('safe-dns', nncp(dns))
    single_master = nncp()
    single_master['spec']['nodeSelector'] = {HOST: 'master-0'}
    lab.case('safe-master-single', single_master)
    lab.case('safe-secondary-route', nncp({'routes': {'config': [{'destination': '192.0.2.0/24', 'next-hop-interface': 'enp8s0'}]}}))
    class PreflightAdapter:
        def get(self, path):
            return self.request('GET', path)[0]

        def request(self, method, path, obj=None):
            code, response = lab.request(method, path, obj)
            self.last_response = response
            if not 200 <= code < 300:
                raise APIError(code, response)
            return response, {}

    # API schema errors can echo arbitrary user strings, including rule names.
    spoof = nncp()
    spoof['metadata'] = {'name': 'preflight-schema-message-spoof', 'labels': {'invalid': 'network-guardrail GR-003'}}
    full_spoof = copy.deepcopy(spoof)
    full_spoof['metadata'] = {'name': 'preflight-full-prefix-spoof', 'labels': {'invalid':
        "ValidatingAdmissionPolicy 'network-guardrail' with binding 'network-guardrail' denied request: GR-003 PRIMARY_NETWORK: synthetic"}}
    genuine = copy.deepcopy(bad)
    genuine['metadata']['name'] = 'preflight-genuine-denial'
    for candidate, outcome, allowed in [(spoof, 'ERROR', None), (full_spoof, 'ERROR', None), (genuine, 'DENIED', False)]:
        name = candidate['metadata']['name']
        preflight_client = PreflightAdapter()
        result = preflight(preflight_client, yaml.safe_dump(candidate))
        assert result['outcome'] == outcome and result['allowed'] is allowed and result['statusCode'] == 422, result
        assert lab.request('GET', NNCP + '/' + name)[0] == 404
        lab.rows.append((name, 'POST', 422, outcome, result['message']))
        with (lab.directory / 'cases.jsonl').open('a') as evidence:
            evidence.write(json.dumps({'aiAuthor': 'Codex (OpenAI model not exposed by runtime)',
                                       'case': name, 'method': 'POST', 'httpStatus': 422,
                                       'expectedRule': outcome, 'response': preflight_client.last_response,
                                       'preflightResult': result, 'confirmedNotFound': True}) + '\n')
        print('PASS ' + name + ': preflight outcome=' + outcome, flush=True)
    # An isolated diagnostic policy proves escaped identifiers stay literal
    # in this runtime's dynamic map; it is never written to project policies.
    probe_name = 'network-guardrail-key-probe'
    probe = {'apiVersion': 'admissionregistration.k8s.io/v1beta1', 'kind': 'ValidatingAdmissionPolicy',
             'metadata': {'name': probe_name}, 'spec': {'failurePolicy': 'Fail',
             'matchConstraints': {'resourceRules': [{'apiGroups': ['nmstate.io'], 'apiVersions': ['v1'],
                 'operations': ['CREATE'], 'resources': ['nodenetworkconfigurationpolicies']}]},
             'matchConditions': [{'name': 'diagnostic-only', 'expression': "object.metadata.name.startsWith('probe-hyphen')"}],
             'validations': [{'expression': "dyn(object.spec.desiredState)['dns-resolver']['config']['server'][0] == '192.0.2.53' && "
                 "!has(dyn(object.spec.desiredState).dns__dash__resolver) && "
                 "dyn(object.spec.desiredState)['routes']['config'][0]['next-hop-interface'] == 'enp8s0' && "
                 "!has(dyn(object.spec.desiredState)['routes']['config'][0].next__dash__hop__dash__interface)",
                 'message': 'GR-PROBE hyphenated map keys and escaped identifiers differ'}]}}
    lab.ok('POST', VAP, probe)
    lab.ok('POST', BIND, {'apiVersion': probe['apiVersion'], 'kind': 'ValidatingAdmissionPolicyBinding',
                         'metadata': {'name': probe_name}, 'spec': {'policyName': probe_name, 'validationActions': ['Deny']}})
    probe_obj = nncp(copy.deepcopy(dns))
    probe_obj['spec']['desiredState']['routes'] = {'config': [{'destination': '192.0.2.0/24', 'next-hop-interface': 'enp8s0'}]}
    probe_bad = copy.deepcopy(probe_obj)
    probe_bad['metadata']['name'] = 'probe-hyphen-canary'
    probe_bad['spec']['desiredState']['dns-resolver']['config']['server'] = ['203.0.113.53']
    lab.wait(lambda: 'GR-PROBE' in str(lab.request('POST', NNCP + '?dryRun=All', probe_bad)), 'hyphen probe policy')
    lab.case('probe-hyphen-negative', probe_bad, 'GR-PROBE')
    lab.case('probe-hyphen-positive', probe_obj)
    lab.ok('DELETE', BIND + '/' + probe_name)
    lab.ok('DELETE', VAP + '/' + probe_name)
    seed = nncp()
    seed['metadata']['name'] = 'update-existing'
    saved = lab.ok('POST', NNCP, seed)
    changed = copy.deepcopy(saved)
    changed['spec']['desiredState'] = bad['spec']['desiredState']
    lab.case('update-existing', changed, 'GR-003', method='PUT', path=NNCP + '/update-existing', missing=False)
    assert lab.ok('GET', NNCP + '/update-existing')['spec'] == saved['spec'], 'denied update changed stored resource'
    lab.case('update-existing', saved, method='PUT', path=NNCP + '/update-existing', missing=False)
    lab.ok('DELETE', NNCP + '/update-existing')
    assert lab.request('GET', NNCP + '/update-existing')[0] == 404
    lab.replace(PARAM + '/reviewed', lab.parameters(False))
    lab.wait(lambda: 'GR-000' in str(lab.request('POST', NNCP + '?dryRun=All', nncp())), 'unready params')
    lab.case('params-unready', nncp(), 'GR-000')
    lab.ok('DELETE', PARAM + '/reviewed')
    lab.wait(lambda: 'no params found' in str(lab.request('POST', NNCP + '?dryRun=All', nncp())).lower(), 'missing params')
    lab.case('params-missing', nncp(), 'no params found')
    converted = [item for event in lab.audit_events() for item in events_from_audit(event)]
    assert any(e['spec']['action'] == 'AUDIT' and e['spec']['name'] == 'audit-allows' and e['spec']['dryRun'] for e in converted)
    assert any(e['spec']['action'] == 'DENY' and e['spec']['name'] == 'protected-br-ex' and e['spec']['rule'] == 'GR-003' for e in converted)
    assert all('requestObject' not in e['spec'] for e in converted)
    print('PASS collector: real API audit annotation -> AUDIT/DENY events', flush=True)
    return converted


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binaries', type=Path, default=Path('/tmp/network-guardrail-envtest/controller-tools/envtest'))
    parser.add_argument('--report', type=Path, default=ROOT / 'docs/admission-validation.md')
    args = parser.parse_args()
    for name in ['etcd', 'kube-apiserver']:
        if not (args.binaries / name).is_file():
            parser.error('missing envtest binary: ' + str(args.binaries / name))
    lab = Lab(args.binaries)
    try:
        converted = run(lab)
        version = subprocess.check_output([str(args.binaries / 'kube-apiserver'), '--version'], text=True).strip()
        lines = ['<!-- AI-Author: Codex (OpenAI model not exposed by runtime) -->', '# Local admission validation', '',
                 '- Timestamp: ' + datetime.datetime.now(datetime.timezone.utc).isoformat(), '- API server: ' + version,
                 '- Execution: loopback-only API server and etcd; VAP v1beta1 explicitly enabled.',
                 '- No worker nodes, NMState operator, external cluster, or external kubeconfig used.',
                 '- NNCP fixture preserves the actual opaque desiredState schema; parameters are synthetic.',
                 '- All case submissions use server-side dry run. CREATE cases were confirmed NotFound afterward.',
                 '- UPDATE seed was unchanged after denial and was deleted after testing.',
                 '- Real Metadata audit annotations were parsed through guardrail.audit.events_from_audit.',
                 '- Converted audit records observed: ' + str(len(converted)),
                 '- Processes stopped and generated authentication/signing secrets removed.',
                 '- Local evidence directory (not portable): `' + str(lab.directory) + '`', '',
                 'Evidence files: `cases.jsonl` contains complete synthetic-case API responses; `audit.jsonl` contains the real Metadata audit events. Generated authentication secrets are removed.', '',
                 'Reproduce: `python3 scripts/test-admission.py --binaries /path/to/envtest`.', '',
                 '| Case | Operation | HTTP | Expected result |', '| --- | --- | --- | --- |']
        lines += [f'| {name} | {method} | {code} | {rule} |' for name, method, code, rule, _ in lab.rows]
        lines += ['', 'This establishes upstream Kubernetes 1.29 admission behavior. It does not establish availability, support, or enablement on a particular OpenShift 4.16 cluster.', '']
        args.report.write_text('\n'.join(lines))
        print('PASS report: ' + str(args.report))
    finally:
        lab.close()
        print('Local evidence retained: ' + str(lab.directory), flush=True)


if __name__ == '__main__':
    main()
