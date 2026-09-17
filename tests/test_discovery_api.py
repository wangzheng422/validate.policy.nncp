# AI-Author: Codex (OpenAI model not exposed by runtime)
import unittest
from unittest.mock import Mock
from guardrail.kube import APIError, Kube
from guardrail.api import policies
from guardrail.controller import policy
from unittest.mock import patch


class DiscoveryAPITests(unittest.TestCase):
    def test_nns_beta_with_nncp_stable_is_discovered_per_resource(self):
        client = Kube.__new__(Kube)
        documents = {
            '/apis/nmstate.io': {'preferredVersion': {'groupVersion': 'nmstate.io/v1'}, 'versions': [
                {'groupVersion': 'nmstate.io/v1'}, {'groupVersion': 'nmstate.io/v1beta1'}]},
            '/apis/nmstate.io/v1': {'resources': [{'name': 'nodenetworkconfigurationpolicies'}]},
            '/apis/nmstate.io/v1beta1': {'resources': [{'name': 'nodenetworkstates'}]}}
        client.get = Mock(side_effect=lambda path: documents[path])
        self.assertEqual('/apis/nmstate.io/v1beta1/nodenetworkstates', client.collection('nmstate.io', 'nodenetworkstates'))
        self.assertEqual('/apis/nmstate.io/v1/nodenetworkconfigurationpolicies', client.collection('nmstate.io', 'nodenetworkconfigurationpolicies'))

    def test_missing_resource_is_not_reported_as_empty_inventory(self):
        client = Kube.__new__(Kube)
        client.get = Mock(return_value={'versions': []})
        with self.assertRaises(APIError):
            client.collection('nmstate.io', 'nodenetworkstates')

    def test_installed_policy_without_binding_is_not_active(self):
        with patch('guardrail.api.optional', side_effect=[policy(), None, None, None]):
            self.assertFalse(policies(Mock())['items'][0]['active'])
        with patch('guardrail.api.optional', side_effect=[policy(), {'spec': {}}, None, None]):
            self.assertTrue(policies(Mock())['items'][0]['active'])


if __name__ == '__main__':
    unittest.main()
