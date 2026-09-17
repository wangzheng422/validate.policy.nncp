# AI-Author: Codex (OpenAI model not exposed by runtime)
"""Caller authorization, control conflicts, examples, and preflight provenance."""

from copy import deepcopy
import io
import json
import unittest
from unittest.mock import Mock, patch
import yaml

from guardrail import api, control, demo
from guardrail.controller import policy
from guardrail.discovery import discover
from guardrail.kube import APIError, GROUP, NNCP, admission_path, events_path, namespace

BINDINGS = admission_path("validatingadmissionpolicybindings")
BINDING = BINDINGS + "/network-guardrail"
POLICY = admission_path("validatingadmissionpolicies") + "/network-guardrail"
CM = "/api/v1/namespaces/" + namespace() + "/configmaps/network-guardrail-candidate"


class Cluster:
    """In-memory API with optimistic resource versions and caller SSAR checks."""
    def __init__(self):
        node = {"metadata": {"name": "worker-0", "labels": {
            "kubernetes.io/hostname": "worker-0", "node-role.kubernetes.io/worker": ""}},
            "status": {"addresses": [{"type": "InternalIP", "address": "192.0.2.10"}]}}
        state = {"metadata": {"name": "worker-0", "resourceVersion": "1"}, "status": {"currentState": {
            "interfaces": [{"name": "enp4s3", "ipv4": {"address": [{"ip": "192.0.2.10"}]}}],
            "routes": {"running": [{"destination": "0.0.0.0/0", "next-hop-interface": "enp4s3"}]},
            "dns-resolver": {"running": {"server": ["192.0.2.53", "2001:db8::53"]}}}}}
        inventory, parameters = discover([node], [state])
        self.candidate = parameters
        self.objects = {control.INVENTORY: {"status": inventory}, POLICY: policy(),
                        CM: {"data": {"parameters.yaml": yaml.safe_dump(parameters)}},
                        "/apis/nmstate.io/v1beta1/nodenetworkstates/worker-0": state}
        self.calls, self.denied, self.failures = [], set(), {}
        self.sequence = 10
        self.on_get = None

    def get(self, path):
        self.calls.append(("GET", path, None))
        if self.on_get:
            self.on_get(path)
        if ("GET", path) in self.failures:
            raise self.failures[("GET", path)]
        if path not in self.objects:
            raise APIError(404, {"message": "Not found", "reason": "NotFound"})
        return deepcopy(self.objects[path])

    def request(self, method, path, body=None):
        self.calls.append((method, path, deepcopy(body)))
        if (method, path) in self.failures:
            raise self.failures[(method, path)]
        if path == control.SSAR:
            attrs = body["spec"]["resourceAttributes"]
            return {"status": {"allowed": (attrs["resource"], attrs["verb"]) not in self.denied}}, {}
        if path == "/apis/authentication.k8s.io/v1/selfsubjectreviews":
            return {"status": {"userInfo": {"username": "test-caller"}}}, {}
        target = path if method != "POST" else path + "/" + body["metadata"]["name"]
        current = self.objects.get(target)
        if method == "DELETE":
            expected = body["preconditions"]
            if current is None or any(current["metadata"].get(k) != v for k, v in expected.items()):
                raise APIError(409, {"message": "Delete precondition conflict"})
            del self.objects[target]
            return {}, {}
        if method == "POST" and current is not None:
            raise APIError(409, {"message": "Already exists"})
        if method == "PUT" and (current is None or body["metadata"].get("resourceVersion") != current["metadata"].get("resourceVersion")):
            raise APIError(409, {"message": "Update conflict"})
        self.sequence += 1
        saved = deepcopy(body)
        saved["metadata"]["resourceVersion"] = str(self.sequence)
        saved["metadata"].setdefault("uid", "uid-" + str(self.sequence))
        self.objects[target] = saved
        return deepcopy(saved), {}

    def list(self, path):
        self.calls.append(("LIST", path, None))
        if ("LIST", path) in self.failures:
            raise self.failures[("LIST", path)]
        return [deepcopy(v) for k, v in self.objects.items() if k.startswith(path + "/")]

    def collection(self, group, resource):
        assert (group, resource) == ("nmstate.io", "nodenetworkstates")
        return "/apis/nmstate.io/v1beta1/nodenetworkstates"

    def approve(self):
        self.objects[control.PARAMETERS + "/cluster"] = deepcopy(self.candidate)
        self.objects[control.PARAMETERS + "/cluster"]["metadata"].update(resourceVersion="5", uid="params-uid")

    def binding(self, mode="Deny"):
        self.objects[BINDING] = {"apiVersion": policy()["apiVersion"], "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {"name": "network-guardrail", "resourceVersion": "7", "uid": "binding-uid",
                         "labels": {"app.kubernetes.io/managed-by": "Helm"},
                         "annotations": {"meta.helm.sh/release-name": "existing-release"}},
            "spec": {"policyName": "network-guardrail", "paramRef": {"name": "cluster", "parameterNotFoundAction": "Deny"},
                     "validationActions": ["Deny", "Audit"] if mode == "Deny" else ["Audit", "Warn"]}}

    def changes(self):
        return [c for c in self.calls if c[0] in ("POST", "PUT", "DELETE") and c[1] != control.SSAR
                and not c[1].endswith("/selfsubjectreviews")]


def request(kube, mode="Deny", version=""):
    return {"mode": mode, "revision": kube.candidate["spec"]["revision"], "bindingResourceVersion": version, "confirm": True}


class ControlTests(unittest.TestCase):
    def test_get_control_uses_ssar_without_changing_resources(self):
        kube = Cluster()
        result = control.get_control(kube)
        self.assertEqual("Disabled", result["state"])
        self.assertEqual("", result["bindingResourceVersion"])
        self.assertTrue(result["candidate"]["ready"])
        self.assertTrue(result["capabilities"]["canEnable"])
        self.assertEqual([], kube.changes())
        attrs = [b["spec"]["resourceAttributes"] for m, p, b in kube.calls if p == control.SSAR]
        event = next(a for a in attrs if a["resource"] == "networkguardrailevents")
        self.assertEqual(namespace(), event["namespace"])
        self.assertNotIn("name", event)

    def test_enabling_writes_only_fixed_parameters_then_global_binding(self):
        kube = Cluster()
        result = control.set_control(kube, request(kube))
        self.assertEqual("Deny", result["state"])
        self.assertTrue(result["parametersUpdated"])
        self.assertTrue(result["bindingUpdated"])
        self.assertEqual([control.PARAMETERS, BINDINGS], [c[1] for c in kube.changes()])
        binding = kube.objects[BINDING]
        self.assertEqual(["Deny", "Audit"], binding["spec"]["validationActions"])
        self.assertNotIn("matchResources", binding["spec"])
        self.assertEqual("Deny", binding["spec"]["paramRef"]["parameterNotFoundAction"])
        self.assertEqual("console-user", binding["metadata"]["annotations"]["guardrail.openshift.io/managed-by"])
        self.assertNotIn("meta.helm.sh/release-name", binding["metadata"]["annotations"])

    def test_mode_change_preserves_helm_metadata_without_reapproving_parameters(self):
        kube = Cluster()
        kube.approve()
        kube.binding()
        before = deepcopy(kube.objects[BINDING]["metadata"])
        result = control.set_control(kube, request(kube, "Audit", "7"))
        self.assertFalse(result["parametersUpdated"])
        self.assertEqual("Audit", result["state"])
        self.assertEqual(["Audit", "Warn"], kube.objects[BINDING]["spec"]["validationActions"])
        for key in ("labels", "annotations", "uid"):
            self.assertEqual(before[key], kube.objects[BINDING]["metadata"][key])
        self.assertEqual([BINDING], [c[1] for c in kube.changes()])

    def test_disabled_allows_missing_candidate_and_uses_uid_rv_preconditions(self):
        kube = Cluster()
        kube.approve()
        kube.binding()
        params = deepcopy(kube.objects[control.PARAMETERS + "/cluster"])
        del kube.objects[CM]
        del kube.objects[control.INVENTORY]
        del kube.objects[POLICY]
        result = control.set_control(kube, request(kube, "Disabled", "7"))
        self.assertEqual("Disabled", result["state"])
        self.assertEqual(params, kube.objects[control.PARAMETERS + "/cluster"])
        self.assertEqual([("DELETE", BINDING)], [(c[0], c[1]) for c in kube.changes()])
        self.assertEqual({"uid": "binding-uid", "resourceVersion": "7"}, kube.changes()[0][2]["preconditions"])

    def test_disable_does_not_depend_on_discovery_read_permissions(self):
        kube = Cluster()
        kube.binding()
        kube.failures[("GET", control.INVENTORY)] = APIError(403, {"message": "Cannot read inventory"})
        result = control.set_control(kube, request(kube, "Disabled", "7"))
        self.assertEqual("Disabled", result["state"])
        self.assertTrue(result["bindingUpdated"])
        self.assertFalse(result["capabilities"]["canEnable"])
        self.assertTrue(result["warnings"])
        self.assertNotIn(BINDING, kube.objects)

    def test_stale_binding_candidate_unready_foreign_and_confirm_rejected(self):
        for case in ("binding", "revision", "unready", "foreign", "confirm", "extra", "target"):
            with self.subTest(case=case):
                kube = Cluster()
                req = request(kube)
                if case == "binding":
                    kube.binding()
                elif case == "revision":
                    req["revision"] = "old"
                elif case == "unready":
                    kube.objects[control.INVENTORY]["status"]["ready"] = False
                elif case == "foreign":
                    kube.binding()
                    kube.objects[BINDING]["spec"]["policyName"] = "foreign"
                    req.update(mode="Disabled", bindingResourceVersion="7")
                elif case == "confirm":
                    req["confirm"] = 1
                elif case == "extra":
                    req["parameters"] = {"arbitrary": True}
                else:
                    candidate = deepcopy(kube.candidate)
                    candidate["metadata"]["name"] = "other"
                    kube.objects[CM]["data"]["parameters.yaml"] = yaml.safe_dump(candidate)
                with self.assertRaises(control.ControlError):
                    control.set_control(kube, req)
                self.assertEqual([], kube.changes())

    def test_active_binding_requires_disable_before_snapshot_change(self):
        kube = Cluster()
        kube.approve()
        kube.binding()
        kube.objects[control.PARAMETERS + "/cluster"]["spec"]["revision"] = "old"
        self.assertFalse(control.get_control(kube)["capabilities"]["canEnable"])
        with self.assertRaisesRegex(control.ControlError, "Disable"):
            control.set_control(kube, request(kube, "Audit", "7"))
        self.assertEqual([], kube.changes())

    def test_denied_permissions_are_checked_before_parameter_write(self):
        for denied in (("validatingadmissionpolicybindings", "create"), ("networkguardrailparameters", "create")):
            with self.subTest(denied=denied):
                kube = Cluster()
                kube.denied.add(denied)
                self.assertFalse(control.get_control(kube)["capabilities"]["canEnable"])
                with self.assertRaises(control.ControlError) as error:
                    control.set_control(kube, request(kube))
                self.assertEqual(403, error.exception.code)
                self.assertEqual([], kube.changes())

    def test_changed_binding_between_permission_checks_and_write_conflicts(self):
        kube = Cluster()
        reads = []
        def race(path):
            if path == BINDING:
                reads.append(path)
                if len(reads) == 3:
                    kube.binding()
        kube.on_get = race
        with self.assertRaises(control.ControlError) as error:
            control.set_control(kube, request(kube))
        self.assertEqual(409, error.exception.code)
        self.assertEqual([], kube.changes())

    def test_binding_failure_reports_applied_parameters_without_rollback(self):
        kube = Cluster()
        kube.failures[("POST", BINDINGS)] = APIError(409, {"message": "Created concurrently"})
        with self.assertRaises(control.ControlError) as error:
            control.set_control(kube, request(kube))
        self.assertTrue(error.exception.body["partial"])
        self.assertTrue(error.exception.body["parametersUpdated"])
        self.assertFalse(error.exception.body["bindingUpdated"])
        self.assertIn(control.PARAMETERS + "/cluster", kube.objects)
        self.assertNotIn(BINDING, kube.objects)
        self.assertFalse(any(c[0] == "DELETE" for c in kube.changes()))

    def test_uncertain_parameter_response_does_not_attempt_binding(self):
        kube = Cluster()
        kube.failures[("POST", control.PARAMETERS)] = TimeoutError()
        with self.assertRaises(control.ControlError) as error:
            control.set_control(kube, request(kube))
        self.assertIsNone(error.exception.body["parametersUpdated"])
        self.assertFalse(error.exception.body["bindingUpdated"])
        self.assertEqual([control.PARAMETERS], [c[1] for c in kube.changes()])

    def test_tampered_policy_and_bad_status_cannot_enable(self):
        for case in ("empty", "fail-open", "scope", "variables", "warnings", "stale"):
            with self.subTest(case=case):
                kube = Cluster()
                vap = kube.objects[POLICY]
                if case == "empty":
                    vap["spec"]["validations"] = []
                elif case == "fail-open":
                    vap["spec"]["failurePolicy"] = "Ignore"
                elif case == "scope":
                    vap["spec"]["matchConstraints"]["objectSelector"] = {"matchLabels": {"only": "test"}}
                elif case == "variables":
                    vap["spec"]["variables"][0]["expression"] = "dyn({})"
                elif case == "warnings":
                    vap["status"] = {"typeChecking": {"expressionWarnings": [{"warning": "bad field"}]}}
                else:
                    vap["metadata"]["generation"] = 2
                    vap["status"] = {"observedGeneration": 1}
                self.assertFalse(control.get_control(kube)["capabilities"]["canEnable"])
                with self.assertRaises(control.ControlError):
                    control.set_control(kube, request(kube))
                self.assertEqual([], kube.changes())

    def test_kubernetes_policy_defaults_do_not_prevent_enable(self):
        kube = Cluster()
        match = kube.objects[POLICY]["spec"]["matchConstraints"]
        match.update(matchPolicy="Equivalent", namespaceSelector={"matchLabels": {}}, objectSelector={})
        for validation in kube.objects[POLICY]["spec"]["validations"]:
            validation["reason"] = "Invalid"
        self.assertTrue(control.get_control(kube)["capabilities"]["canEnable"])

    def test_noncanonical_binding_is_not_reported_as_global_enforcement(self):
        for case in ("parameter-name", "parameter-selector", "parameter-namespace", "allow-missing",
                     "object-selector", "resource-rules", "exclude-rules"):
            with self.subTest(case=case):
                kube = Cluster()
                kube.approve()
                kube.binding()
                spec = kube.objects[BINDING]["spec"]
                if case == "parameter-name":
                    spec["paramRef"]["name"] = "unrelated"
                elif case == "parameter-selector":
                    spec["paramRef"]["selector"] = {}
                elif case == "parameter-namespace":
                    spec["paramRef"]["namespace"] = "unrelated"
                elif case == "allow-missing":
                    spec["paramRef"]["parameterNotFoundAction"] = "Allow"
                elif case == "object-selector":
                    spec["matchResources"] = {"objectSelector": {"matchLabels": {"demo": "only"}}}
                else:
                    key = "resourceRules" if case == "resource-rules" else "excludeResourceRules"
                    spec["matchResources"] = {key: [{"apiGroups": ["other"]}]}
                self.assertEqual("Unknown", control.get_control(kube)["state"])
                self.assertEqual("Unknown", api.enforcement(kube)["state"])

    def test_empty_defaulted_binding_match_fields_remain_global(self):
        kube = Cluster()
        kube.approve()
        kube.binding()
        kube.objects[BINDING]["spec"]["matchResources"] = {
            "matchPolicy": "Equivalent", "namespaceSelector": {"matchLabels": {}, "matchExpressions": []},
            "objectSelector": {}, "resourceRules": [], "excludeResourceRules": []}
        self.assertEqual("Deny", control.get_control(kube)["state"])
        self.assertEqual("Deny", api.enforcement(kube)["state"])


class DemoTests(unittest.TestCase):
    def text(self):
        return "apiVersion: nmstate.io/v1\nkind: NodeNetworkConfigurationPolicy\nmetadata:\n  name: test-denial\nspec: {}\n"

    def denial(self):
        return {"outcome": "DENIED", "allowed": False, "dryRun": True, "operation": "CREATE", "statusCode": 422,
                "auditID": "real-api-audit-id", "message": "Node is forbidden: ValidatingAdmissionPolicy 'network-guardrail' with binding 'network-guardrail' denied request: GR-003 PRIMARY_NETWORK: protected interface"}

    def test_examples_reuse_real_hostname_interface_and_observed_dns(self):
        result = demo.examples(Cluster())
        self.assertEqual(["protected-primary-removal", "dns-only"], [x["id"] for x in result["items"]])
        bad, good = [yaml.safe_load(x["yaml"]) for x in result["items"]]
        self.assertEqual({"kubernetes.io/hostname": "worker-0"}, bad["spec"]["nodeSelector"])
        self.assertEqual("enp4s3", bad["spec"]["desiredState"]["interfaces"][0]["name"])
        self.assertEqual(["192.0.2.53", "2001:db8::53"], good["spec"]["desiredState"]["dns-resolver"]["config"]["server"])
        self.assertNotIn("interfaces", good["spec"]["desiredState"])
        self.assertTrue(all("DRY RUN ONLY" in x["yaml"] for x in result["items"]))

    def test_unready_inventory_never_generates_fabricated_examples(self):
        kube = Cluster()
        kube.objects[control.INVENTORY]["status"]["ready"] = False
        self.assertEqual([], demo.examples(kube)["items"])
        kube = Cluster()
        del kube.objects["/apis/nmstate.io/v1beta1/nodenetworkstates/worker-0"]
        result = demo.examples(kube)
        self.assertEqual(["protected-primary-removal"], [x["id"] for x in result["items"]])
        self.assertTrue(any("DNS-only" in w for w in result["warnings"]))

    def test_denied_history_has_real_provenance_identity_and_no_yaml_body(self):
        kube = Cluster()
        with patch("guardrail.demo.preflight", return_value=self.denial()):
            result = demo.preflight_with_history(kube, self.text())
        self.assertTrue(result["eventRecorded"])
        event = kube.objects[events_path() + "/" + result["eventName"]]
        self.assertEqual("preflight", event["spec"]["source"])
        self.assertEqual("real-api-audit-id", event["spec"]["auditID"])
        self.assertEqual("test-caller", event["spec"]["username"])
        self.assertTrue(event["spec"]["usernameVerified"])
        self.assertTrue(event["spec"]["dryRun"])
        self.assertEqual("GR-003", event["spec"]["rule"])
        self.assertEqual("", result["eventWarning"])
        self.assertNotIn("requestObject", event["spec"])
        self.assertNotIn("yaml", event["spec"])

    def test_allowed_or_error_outcomes_do_not_create_denial_events(self):
        for outcome, allowed in (("ALLOWED", True), ("ERROR", None)):
            kube = Cluster()
            with patch("guardrail.demo.preflight", return_value={"outcome": outcome, "allowed": allowed}):
                result = demo.preflight_with_history(kube, self.text())
            self.assertFalse(result["eventRecorded"])
            self.assertEqual([], kube.calls)

    def test_missing_audit_identity_is_not_fabricated(self):
        kube = Cluster()
        kube.failures[("POST", "/apis/authentication.k8s.io/v1/selfsubjectreviews")] = APIError(404, {})
        denial = self.denial()
        denial["auditID"] = ""
        with patch("guardrail.demo.preflight", return_value=denial):
            result = demo.preflight_with_history(kube, self.text())
        event = kube.objects[events_path() + "/" + result["eventName"]]
        self.assertEqual("", event["spec"]["auditID"])
        self.assertEqual("unknown", event["spec"]["username"])
        self.assertFalse(event["spec"]["usernameVerified"])
        self.assertIn("unknown", result["eventWarning"])

    def test_history_create_and_cleanup_permission_failures_keep_real_denial(self):
        for phase in ("create", "list"):
            kube = Cluster()
            kube.failures[("POST" if phase == "create" else "LIST", events_path())] = APIError(403, {})
            with patch("guardrail.demo.preflight", return_value=self.denial()):
                result = demo.preflight_with_history(kube, self.text())
            self.assertEqual("DENIED", result["outcome"])
            self.assertFalse(result["allowed"])
            self.assertEqual(phase != "create", result["eventRecorded"])
            self.assertIn("403", result["eventWarning"])

    def test_retention_deletes_only_old_preflight_records_with_preconditions(self):
        kube = Cluster()
        for name, source, managed in (("preflight-old", "preflight", True), ("preflight-newer", "preflight", True),
                                      ("audit-old", "audit-log", True), ("preflight-foreign", "preflight", False)):
            kube.objects[events_path() + "/" + name] = {"metadata": {"name": name, "uid": name, "resourceVersion": "4",
                "labels": {"app.kubernetes.io/managed-by": "network-guardrail" if managed else "another"}},
                "spec": {"source": source, "timestamp": "2000-01-01" if name.endswith("old") else "2001-01-01"}}
        with patch("guardrail.demo.preflight", return_value=self.denial()), patch("guardrail.demo.EVENT_LIMIT", 2):
            result = demo.preflight_with_history(kube, self.text())
        self.assertTrue(result["eventRecorded"])
        deletes = [c for c in kube.changes() if c[0] == "DELETE"]
        self.assertEqual([events_path() + "/preflight-old"], [c[1] for c in deletes])
        self.assertEqual({"uid": "preflight-old", "resourceVersion": "4"}, deletes[0][2]["preconditions"])
        self.assertIn(events_path() + "/audit-old", kube.objects)
        self.assertIn(events_path() + "/preflight-foreign", kube.objects)


class HandlerTests(unittest.TestCase):
    def handler(self, method, path, body=None):
        handler = api.Handler.__new__(api.Handler)
        handler.path, handler.command = path, method
        data = json.dumps(body).encode() if body is not None else b""
        handler.headers = {"Authorization": "Bearer caller-only", "Content-Type": "application/json", "Content-Length": str(len(data))}
        handler.rfile = io.BytesIO(data)
        handler.connection, handler.send = Mock(), Mock()
        return handler

    def test_control_error_details_and_caller_identity_survive_http_boundary(self):
        kube = Cluster()
        kube.failures[("POST", BINDINGS)] = APIError(409, {"message": "Concurrent create"})
        handler = self.handler("POST", "/api/control", request(kube))
        with patch("guardrail.api.Kube", return_value=kube) as factory:
            handler.handle_request()
        factory.assert_called_once_with(token="caller-only")
        status, body = handler.send.call_args.args
        self.assertEqual(409, status)
        self.assertTrue(body["parametersUpdated"])
        self.assertTrue(body["partial"])
        self.assertIn("error", body)

    def test_topology_decodes_node_once_and_keeps_authorized_kube(self):
        handler = self.handler("GET", "/api/topology/node%252Fone?lang=zh-TW")
        kube = Cluster()
        with patch("guardrail.api.Kube", return_value=kube), patch("guardrail.api.render_topology", return_value={"html": "ok"}) as render:
            handler.handle_request()
        render.assert_called_once_with(kube, "node%2Fone", "zh-TW")
        self.assertEqual(200, handler.send.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
