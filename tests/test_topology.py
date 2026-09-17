# AI-Author: Codex (OpenAI model not exposed by runtime)
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from guardrail.kube import APIError, GROUP
from guardrail.topology import render_topology


class TopologyTests(unittest.TestCase):
    def setUp(self):
        self.kube = Mock()
        self.kube.get.return_value = {'status': {'revision': 'r1', 'nodes': [{'name': 'node-1', 'edges': []}]}}

    def test_uses_caller_read_and_fixed_process_with_stdin_only(self):
        result = {'html': '<html>test</html>', 'node': 'node-1', 'revision': 'r1'}
        with patch('guardrail.topology.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=json.dumps(result))) as run:
            self.assertEqual(render_topology(self.kube, 'node-1', 'zh-CN'), result)
        self.kube.get.assert_called_once_with(GROUP + '/primarynetworkinventories/cluster')
        args, kwargs = run.call_args
        self.assertEqual(args[0][0], 'node')
        self.assertNotIn('shell', kwargs)
        self.assertEqual(json.loads(kwargs['input'])['locale'], 'zh-CN')
        self.assertEqual(kwargs['timeout'], 15)

    def test_permission_failure_never_starts_renderer(self):
        self.kube.get.side_effect = APIError(403, {'message': 'Forbidden'})
        with patch('guardrail.topology.subprocess.run') as run, self.assertRaises(APIError) as caught:
            render_topology(self.kube, 'node-1')
        self.assertEqual(caught.exception.code, 403)
        run.assert_not_called()

    def test_unknown_node_and_bad_language_never_start_renderer(self):
        for node, lang, code in [('missing', 'en', 404), ('node-1', '../../x', 400)]:
            with patch('guardrail.topology.subprocess.run') as run, self.assertRaises(APIError) as caught:
                render_topology(self.kube, node, lang)
            self.assertEqual(caught.exception.code, code)
            run.assert_not_called()

    def test_timeout_releases_capacity_and_returns_actionable_error(self):
        import subprocess
        with patch('guardrail.topology.subprocess.run', side_effect=subprocess.TimeoutExpired('node', 15)):
            for _ in range(3):
                with self.assertRaises(APIError) as caught:
                    render_topology(self.kube, 'node-1')
                self.assertEqual(caught.exception.code, 504)

    def test_wrong_node_output_is_rejected(self):
        with patch('guardrail.topology.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout='{"html":"x","node":"other"}')):
            with self.assertRaises(APIError) as caught:
                render_topology(self.kube, 'node-1')
            self.assertEqual(caught.exception.code, 502)


if __name__ == '__main__':
    unittest.main()
