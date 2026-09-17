# AI-Author: Codex (OpenAI model not exposed by runtime)
"""Offline behavioral regression tests; fakes never contact a Kubernetes API."""
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

import yaml
from guardrail import api, audit, discovery
from guardrail.kube import APIError, Kube, NNCP
from guardrail.preflight import parse_candidate, preflight


CANDIDATE = """apiVersion: nmstate.io/v1
kind: NodeNetworkConfigurationPolicy
metadata:
  name: secondary-net
spec:
  desiredState:
    interfaces:
      - name: eth9
        state: up
        type: ethernet
"""


def node(name='worker-0'):
    return {'metadata': {'name': name, 'labels': {'node-role.kubernetes.io/worker': '', 'zone': 'east'}},
            'status': {'addresses': [{'type': 'InternalIP', 'address': '192.0.2.10'}]}}


def state(interfaces=None, routes=None, name='worker-0'):
    if interfaces is None:
        interfaces = [{'name': 'eth0', 'type': 'ethernet', 'ipv4': {'address': [{'ip': '192.0.2.10', 'prefix-length': 24}]}}]
    if routes is None:
        routes = [{'destination': '0.0.0.0/0', 'next-hop-interface': interfaces[0]['name']}]
    return {'metadata': {'name': name, 'resourceVersion': '1'},
            'status': {'currentState': {'interfaces': interfaces, 'routes': {'running': routes}}}}


class DiscoveryTests(unittest.TestCase):
    def test_default_routes_ipv4_ipv6_and_absent(self):
        s = state([{'name': 'eth0'}, {'name': 'eth1'}], [
            {'destination': '0.0.0.0/0', 'next-hop-interface': 'eth0'},
            {'destination': '::/0', 'next-hop-interface': 'eth1'},
            {'destination': '0.0.0.0/0', 'next-hop-interface': 'removed', 'state': 'absent'},
            {'destination': '10.0.0.0/8', 'next-hop-interface': 'other'},
        ])
        result = discovery.discover_node(node(), s)
        self.assertTrue(result['ready'])
        self.assertEqual({'eth0', 'eth1'}, set(result['primaryPath']))
        self.assertEqual(2, len(result['defaultRoutes']))
        self.assertTrue(discovery.BUILTINS <= set(result['protectedInterfaces']))

    def test_bond_vlan_dependencies(self):
        interfaces = [
            {'name': 'bond0.100', 'vlan': {'base-iface': 'bond0', 'id': 100}},
            {'name': 'bond0', 'link-aggregation': {'port': ['eth0', 'eth1']}},
            {'name': 'eth0'}, {'name': 'eth1'}, {'name': 'eth9'},
        ]
        result = discovery.discover_node(node(), state(interfaces))
        self.assertTrue(result['ready'])
        self.assertEqual({'bond0.100', 'bond0', 'eth0', 'eth1'}, set(result['primaryPath']))
        self.assertNotIn('eth9', result['protectedInterfaces'])

    def test_ovs_nested_bond_port_is_not_missing_interface(self):
        # Upstream NMState represents this bond as a logical OVS bridge port,
        # not as an extra currentState.interfaces entry.
        interfaces = [
            {'name': 'br-ex', 'type': 'ovs-bridge', 'bridge': {'port': [
                {'name': 'ovs-bond', 'link-aggregation': {'mode': 'balance-slb',
                    'port': [{'name': 'eth0'}, {'name': 'eth1'}]}}]}},
            {'name': 'eth0'}, {'name': 'eth1'},
        ]
        result = discovery.discover_node(node(), state(interfaces))
        self.assertTrue({'br-ex', 'eth0', 'eth1'} <= set(result['protectedInterfaces']))
        self.assertTrue(result['ready'], result['warnings'])

    def test_reverse_controller_traversal_protects_sibling(self):
        interfaces = [{'name': 'eth0', 'controller': 'br-primary'},
                      {'name': 'br-primary', 'bridge': {'port': [{'name': 'eth0'}, {'name': 'eth1'}]}},
                      {'name': 'eth1'}]
        result = discovery.discover_node(node(), state(interfaces))
        self.assertTrue(result['ready'])
        self.assertEqual({'eth0', 'br-primary', 'eth1'}, set(result['primaryPath']))

    def test_missing_nns_default_and_dependency_remain_unready(self):
        cases = [None, state(routes=[]),
                 state([{'name': 'bond0', 'link-aggregation': {'port': ['missing']}}]),
                 state(routes=[{'destination': '::/0'}])]
        for candidate in cases:
            with self.subTest(candidate=candidate):
                result = discovery.discover_node(node(), candidate)
                self.assertFalse(result['ready'])
                self.assertTrue(result['warnings'])
                self.assertTrue(discovery.BUILTINS <= set(result['protectedInterfaces']))
        result = discovery.discover_node(node(), cases[2])
        self.assertIn('missing', result['protectedInterfaces'])

    def test_observed_aliases_are_protected_without_changing_canonical_path(self):
        interfaces = [
            {'name': 'eth0', 'profile-name': 'primary-uplink', 'alt-names': [{'name': 'enp1s0'}, 'uplink']},
            {'name': 'eth9', 'profile-name': 'secondary-network', 'alt-names': ['secondary']},
        ]
        snapshot = state(interfaces)
        inventory, parameters = discovery.discover([node()], [snapshot])
        result = inventory['nodes'][0]
        self.assertTrue(result['ready'])
        self.assertEqual(['eth0'], result['primaryPath'])
        self.assertTrue({'eth0', 'primary-uplink', 'enp1s0', 'uplink'} <= set(result['protectedInterfaces']))
        self.assertTrue({'primary-uplink', 'enp1s0', 'uplink'} <= set(parameters['spec']['protectedInterfaces']))
        self.assertFalse({'eth9', 'secondary-network', 'secondary'} & set(result['protectedInterfaces']))
        # Ordering is not a policy change, but a different observed identity is.
        snapshot['status']['currentState']['interfaces'][0]['alt-names'].reverse()
        reordered = discovery.discover([node()], [snapshot])[1]
        self.assertEqual(parameters['spec']['revision'], reordered['spec']['revision'])
        snapshot['status']['currentState']['interfaces'][0]['alt-names'] = ['enp2s0', 'uplink']
        renamed = discovery.discover([node()], [snapshot])[1]
        self.assertNotEqual(parameters['spec']['revision'], renamed['spec']['revision'])
        self.assertIn('enp2s0', renamed['spec']['protectedInterfaces'])
        self.assertNotIn('enp1s0', renamed['spec']['protectedInterfaces'])

    def test_vrf_membership_protects_controller_and_all_dependent_ports(self):
        interfaces = [
            {'name': 'eth0'},
            {'name': 'vrf-primary', 'type': 'vrf', 'vrf': {'route-table-id': 100, 'port': ['eth0', 'bond0']}},
            {'name': 'bond0', 'link-aggregation': {'port': ['eth1', 'eth2']}},
            {'name': 'eth1'}, {'name': 'eth2'}, {'name': 'eth9'},
        ]
        # Seed is a physical member; traversal must ascend to its VRF and then
        # protect the other VRF port's complete lower-interface dependency chain.
        result = discovery.discover_node(node(), state(interfaces))
        self.assertTrue(result['ready'], result['warnings'])
        self.assertEqual({'eth0', 'vrf-primary', 'bond0', 'eth1', 'eth2'}, set(result['primaryPath']))
        self.assertNotIn('eth9', result['protectedInterfaces'])
        self.assertIn({'from': 'vrf-primary', 'to': 'bond0'}, result['edges'])

    def test_no_nodes_is_not_ready(self):
        inventory, parameters = discovery.discover([], [])
        self.assertFalse(inventory['ready'])
        self.assertFalse(parameters['spec']['ready'])

    def test_revision_stable_across_order_and_observation_metadata(self):
        nodes = [node('worker-1'), node()]
        states = [state(name='worker-1'), state()]
        first_inventory, first = discovery.discover(nodes, states)
        states.reverse()
        for s in states:
            s['metadata']['resourceVersion'] = '99'
        second_inventory, second = discovery.discover(list(reversed(nodes)), states)
        self.assertEqual(first['spec']['revision'], second['spec']['revision'])
        self.assertEqual(first['spec'], second['spec'])
        self.assertEqual(first_inventory['revision'], second_inventory['revision'])
        nodes[0]['metadata']['labels']['zone'] = 'west'
        changed = discovery.discover(nodes, states)[1]
        self.assertNotEqual(first['spec']['revision'], changed['spec']['revision'])
        changed = discovery.discover(nodes, [states[0]])[1]
        self.assertFalse(changed['spec']['ready'])


class FakeKube:
    def __init__(self, current=None, get_error=None, write_error=None):
        self.current, self.get_error, self.write_error = current, get_error, write_error
        self.calls = []

    def get(self, path):
        self.calls.append(('GET', path, None))
        if self.get_error:
            raise self.get_error
        if self.current is None:
            raise APIError(404, {'message': 'Not found'})
        return self.current

    def request(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if self.write_error:
            raise self.write_error
        return {}, {'Audit-Id': 'audit-test', 'Warning': '299 test warning'}


class PreflightTests(unittest.TestCase):
    def test_valid_candidate_and_managed_metadata_removed(self):
        obj = yaml.safe_load(CANDIDATE)
        obj['metadata'].update(resourceVersion='spoof', uid='spoof', managedFields=[], labels={'team': 'test'})
        parsed = parse_candidate(yaml.safe_dump(obj))
        self.assertEqual({'name': 'secondary-net', 'labels': {'team': 'test'}}, parsed['metadata'])

    def test_rejects_ambiguous_or_wrong_documents(self):
        wrong_kind = CANDIDATE.replace('NodeNetworkConfigurationPolicy', 'ConfigMap')
        duplicate = CANDIDATE.replace('  name: secondary-net', '  name: first\n  name: second')
        alias = CANDIDATE.replace('spec:\n', 'unused: &ref {}\nspec: *ref\n#')
        inputs = [wrong_kind, duplicate, alias, CANDIDATE + '\n---\n' + CANDIDATE,
                  '[]', CANDIDATE.replace('nmstate.io/v1', 'nmstate.io/v1beta1'),
                  CANDIDATE.replace('  name: secondary-net', '  name: UPPER'),
                  CANDIDATE.replace('  name: secondary-net', '  generateName: generated-'),
                  CANDIDATE.replace('  name: secondary-net', '  name: secondary-net\n  namespace: default'),
                  CANDIDATE + '\nstatus: {}\n', 'x' * (128 * 1024 + 1)]
        for text in inputs:
            with self.subTest(text=text[:80]):
                with self.assertRaises((ValueError, yaml.YAMLError)):
                    parse_candidate(text)

    def test_create_posts_only_server_dry_run(self):
        kube = FakeKube()
        result = preflight(kube, CANDIDATE)
        self.assertEqual('CREATE', result['operation'])
        self.assertTrue(result['allowed'])
        self.assertEqual('audit-test', result['auditID'])
        method, path, body = kube.calls[-1]
        self.assertEqual('POST', method)
        self.assertEqual(NNCP, urlsplit(path).path)
        self.assertEqual({'dryRun': ['All'], 'fieldValidation': ['Strict']}, parse_qs(urlsplit(path).query))
        self.assertNotIn('resourceVersion', body['metadata'])

    def test_update_puts_dry_run_with_live_resource_version(self):
        kube = FakeKube(current={'metadata': {'resourceVersion': '82'}})
        result = preflight(kube, CANDIDATE)
        self.assertEqual('UPDATE', result['operation'])
        method, path, body = kube.calls[-1]
        self.assertEqual('PUT', method)
        self.assertEqual(NNCP + '/secondary-net', urlsplit(path).path)
        self.assertEqual(['All'], parse_qs(urlsplit(path).query)['dryRun'])
        self.assertEqual('82', body['metadata']['resourceVersion'])

    def test_read_rbac_failure_never_submits(self):
        kube = FakeKube(get_error=APIError(403, {'message': 'User cannot get NNCP'}))
        with self.assertRaises(APIError):
            preflight(kube, CANDIDATE)
        self.assertEqual(['GET'], [x[0] for x in kube.calls])

    def test_only_explicit_guardrail_error_is_denied(self):
        for code, message, outcome, allowed in [
            (403, 'User cannot create NNCP', 'ERROR', None),
            (422, 'network-guardrail invalid syntax', 'ERROR', None),
            (500, 'network-guardrail GR-001 server failure', 'ERROR', None),
            (422, 'Invalid value: network-guardrail GR-003', 'ERROR', None),
            (403, "ValidatingAdmissionPolicy 'network-guardrail' with binding 'network-guardrail' denied request: GR-001 PROTECTED_INTERFACE: cannot modify", 'DENIED', False),
        ]:
            with self.subTest(code=code, message=message):
                body = {'message': message}
                if outcome == 'DENIED':
                    body['details'] = {'causes': [{'message': message}]}
                result = preflight(FakeKube(write_error=APIError(code, body)), CANDIDATE)
                self.assertEqual(outcome, result['outcome'])
                self.assertIs(allowed, result['allowed'])
        spoof = "ValidatingAdmissionPolicy 'network-guardrail' with binding 'x' denied request: GR-003"
        body = {'message': spoof, 'details': {'causes': [{'field': 'metadata.labels', 'message': spoof}]}}
        self.assertEqual('ERROR', preflight(FakeKube(write_error=APIError(422, body)), CANDIDATE)['outcome'])

    def test_kube_rejects_persistent_nncp_writes_before_network(self):
        kube = Kube.__new__(Kube)
        for method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            for suffix in ['', '/name', '?dryRun=None', '?dryRun=All&dryRun=None']:
                with self.subTest(method=method, suffix=suffix):
                    with self.assertRaisesRegex(ValueError, 'Persistent NNCP writes'):
                        kube.request(method, NNCP + suffix, {})

    def test_kube_dry_run_keeps_caller_token_on_http_request(self):
        kube = Kube.__new__(Kube)
        kube.base, kube.context, kube.token = 'https://example.invalid', None, 'test-caller-token'
        response = Mock()
        response.read.return_value = b'{}'
        response.headers = {'Audit-Id': 'request-audit'}
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        with patch('guardrail.kube.urllib.request.urlopen', return_value=response) as urlopen:
            kube.request('POST', NNCP + '?dryRun=All', {'kind': 'NodeNetworkConfigurationPolicy'})
        request = urlopen.call_args.args[0]
        self.assertEqual('Bearer test-caller-token', request.get_header('Authorization'))
        self.assertEqual('POST', request.method)
        self.assertIn('dryRun=All', request.full_url)


class APITests(unittest.TestCase):
    def handler(self, path='/api/preflight', token='user-token'):
        handler = api.Handler.__new__(api.Handler)
        handler.path, handler.command = path, 'POST'
        body = json.dumps({'yaml': CANDIDATE}).encode()
        handler.headers = {'Content-Length': str(len(body)), 'Content-Type': 'application/json'}
        if token is not None:
            handler.headers['Authorization'] = 'Bearer ' + token
        handler.rfile = io.BytesIO(body)
        handler.connection = Mock()
        handler.send = Mock()
        return handler

    def test_api_forwards_caller_token_to_real_preflight_logic(self):
        for path in ['/preflight', '/api/preflight']:
            for current, method in [(None, 'POST'), ({'metadata': {'resourceVersion': '17'}}, 'PUT')]:
                with self.subTest(path=path, method=method):
                    handler = self.handler(path)
                    kube = FakeKube(current=current)
                    with patch('guardrail.api.Kube', return_value=kube) as factory:
                        handler.handle_request()
                    factory.assert_called_once_with(token='user-token')
                    status, body = handler.send.call_args.args
                    self.assertEqual(200, status)
                    self.assertEqual('ALLOWED', body['outcome'])
                    self.assertEqual(method, kube.calls[-1][0])
                    self.assertIn('dryRun=All', kube.calls[-1][1])

    def test_inventory_reads_use_caller_token(self):
        handler = self.handler('/api/inventory')
        handler.command = 'GET'
        kube = FakeKube(current={'status': {'nodes': [], 'ready': False}})
        with patch('guardrail.api.Kube', return_value=kube) as factory:
            handler.handle_request()
        factory.assert_called_once_with(token='user-token')
        self.assertEqual((200, {'nodes': [], 'ready': False}), handler.send.call_args.args)
        self.assertEqual('GET', kube.calls[0][0])

    def test_api_requires_user_token_and_never_falls_back_to_service_account(self):
        handler = self.handler(token=None)
        with patch('guardrail.api.Kube') as factory:
            handler.handle_request()
        factory.assert_not_called()
        self.assertEqual(401, handler.send.call_args.args[0])

    def test_read_rbac_failure_returns_error_not_guardrail_denial(self):
        handler = self.handler()
        kube = FakeKube(get_error=APIError(403, {'message': 'User cannot get NNCP'}))
        with patch('guardrail.api.Kube', return_value=kube):
            handler.handle_request()
        status, body = handler.send.call_args.args
        self.assertEqual(403, status)
        self.assertEqual({'error': 'User cannot get NNCP'}, body)
        self.assertEqual(['GET'], [c[0] for c in kube.calls])

    def test_invalid_yaml_returns_400_without_kubernetes_write(self):
        handler = self.handler()
        body = json.dumps({'yaml': CANDIDATE.replace('NodeNetworkConfigurationPolicy', 'Secret')}).encode()
        handler.rfile = io.BytesIO(body)
        handler.headers['Content-Length'] = str(len(body))
        kube = FakeKube()
        with patch('guardrail.api.Kube', return_value=kube):
            handler.handle_request()
        self.assertEqual(400, handler.send.call_args.args[0])
        self.assertEqual([], kube.calls)


def audit_record():
    return {'stage': 'ResponseComplete', 'auditID': 'event-id', 'verb': 'create',
            'objectRef': {'apiGroup': 'nmstate.io', 'resource': 'nodenetworkconfigurationpolicies', 'name': 'bad-net'},
            'user': {'username': 'alice', 'extra': {'private': 'not-recorded'}},
            'sourceIPs': ['192.0.2.1'], 'userAgent': 'oc/test', 'stageTimestamp': '2026-09-16T00:00:00Z',
            'requestURI': NNCP + '?dryRun=All', 'requestObject': {'private': 'BODY_SECRET'},
            'responseObject': {'private': 'BODY_SECRET'}, 'responseStatus': {'code': 403},
            'annotations': {audit.ANNOTATION: json.dumps([{'policy': 'network-guardrail',
                'binding': 'network-guardrail', 'expressionIndex': 1,
                'validationActions': ['Deny', 'Audit'], 'message': 'GR-001 PROTECTED_INTERFACE: eth0'}])}}


class AuditTests(unittest.TestCase):
    def test_filter_requires_real_failure_annotation_and_relevant_stage_resource(self):
        for field, value in [('stage', 'RequestReceived'), ('verb', 'get'), ('auditID', ''), ('annotations', {}),
                             ('objectRef', {'apiGroup': 'apps', 'resource': 'deployments'})]:
            with self.subTest(field=field):
                record = audit_record()
                record[field] = value
                self.assertEqual([], audit.events_from_audit(record))
        record = audit_record()
        record['annotations'][audit.ANNOTATION] = json.dumps([{'policy': 'other-policy'}])
        self.assertEqual([], audit.events_from_audit(record))
        for raw in ['broken', '{}', 'null']:
            record['annotations'][audit.ANNOTATION] = raw
            self.assertEqual([], audit.events_from_audit(record))

    def test_minimal_event_drops_bodies_and_extra_identity(self):
        result = audit.events_from_audit(audit_record())[0]
        spec = result['spec']
        self.assertEqual('DENY', spec['action'])
        self.assertEqual('GR-001', spec['rule'])
        self.assertEqual('PROTECTED_INTERFACE', spec['category'])
        self.assertTrue(spec['dryRun'])
        self.assertEqual('alice', spec['username'])
        self.assertNotIn('BODY_SECRET', json.dumps(result))
        self.assertNotIn('not-recorded', json.dumps(result))
        self.assertNotIn('requestObject', spec)
        self.assertNotIn('responseObject', spec)
        self.assertEqual('network-guardrail', result['metadata']['labels']['app.kubernetes.io/managed-by'])

    def test_audit_action_never_claims_denial_from_status_alone(self):
        for actions, code, expected in [(['Audit'], 201, 'AUDIT'), (['Audit'], 403, 'AUDIT'),
                                        (['Deny', 'Audit'], 201, 'AUDIT'), (['Deny', 'Audit'], 422, 'DENY')]:
            with self.subTest(actions=actions, code=code):
                record = audit_record()
                failure = json.loads(record['annotations'][audit.ANNOTATION])[0]
                failure['validationActions'] = actions
                record['annotations'][audit.ANNOTATION] = json.dumps([failure])
                record['responseStatus']['code'] = code
                self.assertEqual(expected, audit.events_from_audit(record)[0]['spec']['action'])

    def test_deterministic_identity_deduplicates_and_conflict_is_harmless(self):
        record = audit_record()
        original = audit.events_from_audit(record)[0]
        record['stageTimestamp'] = '2026-09-16T01:00:00Z'
        self.assertEqual(original['metadata']['name'], audit.events_from_audit(record)[0]['metadata']['name'])
        record['auditID'] = 'other-event'
        self.assertNotEqual(original['metadata']['name'], audit.events_from_audit(record)[0]['metadata']['name'])
        kube = FakeKube(write_error=APIError(409, {'message': 'AlreadyExists'}))
        audit.persist(kube, record)
        self.assertEqual('POST', kube.calls[0][0])
        kube.write_error = APIError(500, {'message': 'temporary failure'})
        with self.assertRaises(APIError):
            audit.persist(kube, record)

    def test_retention_only_deletes_owned_oldest_with_uid_precondition(self):
        items = []
        for index in range(4):
            items.append({'metadata': {'name': f'event-{index}', 'uid': f'uid-{index}',
                           'labels': {'app.kubernetes.io/managed-by': 'network-guardrail'}},
                          'spec': {'timestamp': f'2026-09-16T0{index}:00:00Z'}})
        items.append({'metadata': {'name': 'foreign', 'uid': 'foreign'}, 'spec': {'timestamp': ''}})
        kube = FakeKube()
        kube.list = Mock(return_value=items)
        audit.retain(kube, 2)
        self.assertEqual(['event-1', 'event-0'], [c[1].rsplit('/', 1)[1] for c in kube.calls])
        self.assertEqual(['DELETE', 'DELETE'], [c[0] for c in kube.calls])
        self.assertEqual({'uid': 'uid-1'}, kube.calls[0][2]['preconditions'])
        self.assertEqual({'uid': 'uid-0'}, kube.calls[1][2]['preconditions'])


class TailTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.log = Path(self.directory.name) / 'audit.log'
        self.checkpoint = Path(self.directory.name) / 'checkpoint.json'
        self.log.write_bytes(b'')
        self.tail = audit.Tail(self.log, self.checkpoint)
        self.addCleanup(self.close_tail)

    def close_tail(self):
        if self.tail.stream:
            self.tail.stream.close()

    def test_partial_line_is_not_returned_or_checkpointed(self):
        self.log.write_bytes(b'{"value":')
        self.assertIsNone(self.tail.next())
        self.assertFalse(self.checkpoint.exists())
        with self.log.open('ab') as stream:
            stream.write(b'1}\n')
        self.assertEqual(b'{"value":1}\n', self.tail.next())
        self.tail.ack()
        self.assertEqual(self.log.stat().st_size, json.loads(self.checkpoint.read_text())['offset'])

    def test_retry_replays_unacknowledged_line(self):
        self.log.write_bytes(b'first\nsecond\n')
        self.assertEqual(b'first\n', self.tail.next())
        self.tail.retry()
        self.assertEqual(b'first\n', self.tail.next())
        self.tail.ack()
        self.assertEqual(b'second\n', self.tail.next())
        self.tail.retry()
        self.assertEqual(b'second\n', self.tail.next())

    def test_rotation_drains_old_file_then_reads_new_file(self):
        self.log.write_bytes(b'first\nsecond\n')
        self.assertEqual(b'first\n', self.tail.next())
        self.tail.ack()
        self.log.rename(self.log.with_suffix('.1'))
        self.log.write_bytes(b'third\n')
        self.assertEqual(b'second\n', self.tail.next())
        self.tail.ack()
        self.assertEqual(b'third\n', self.tail.next())
        self.tail.ack()
        self.assertIsNone(self.tail.next())

    def test_truncation_restarts_at_zero(self):
        self.log.write_bytes(b'a-long-original-line\n')
        self.assertEqual(b'a-long-original-line\n', self.tail.next())
        self.tail.ack()
        self.log.write_bytes(b'new\n')
        self.assertEqual(b'new\n', self.tail.next())

    def test_restart_uses_only_acknowledged_checkpoint(self):
        self.log.write_bytes(b'first\nsecond\n')
        self.tail.next()
        self.tail.ack()
        self.tail.next()
        self.close_tail()
        self.tail = audit.Tail(self.log, self.checkpoint)
        self.assertEqual(b'second\n', self.tail.next())

    def test_invalid_checkpoint_does_not_skip_records(self):
        self.checkpoint.write_text('invalid json')
        self.log.write_bytes(b'first\n')
        self.assertEqual(b'first\n', self.tail.next())


if __name__ == '__main__':
    unittest.main()
