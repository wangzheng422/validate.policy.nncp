# AI-Author: Codex (OpenAI model not exposed by runtime)
"""Caller-authorized changes to the fixed global guardrail binding only."""

from copy import deepcopy
import yaml

from .controller import policy as canonical_policy
from .discovery import BUILTINS
from .kube import APIError, GROUP, admission_path, events_path, namespace
from .preflight import StrictLoader

NAME = "network-guardrail"
PARAMETERS = GROUP + "/networkguardrailparameters"
INVENTORY = GROUP + "/primarynetworkinventories/cluster"
SSAR = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"


class ControlError(APIError):
    """Preserve explicit conflict and partial-change details for the UI."""


def fail(code, message, **details):
    raise ControlError(code, {"message": message, **details})


def optional(kube, path):
    try:
        return kube.get(path)
    except APIError as exc:
        if exc.code == 404:
            return None
        raise


def access(kube, resource, verb, group, name=None, namespaced=False):
    attributes = {"group": group, "resource": resource, "verb": verb}
    if name and verb != "create":
        attributes["name"] = name
    if namespaced:
        attributes["namespace"] = namespace()
    review = {"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
              "spec": {"resourceAttributes": attributes}}
    try:
        response, _ = kube.request("POST", SSAR, review)
        status = response.get("status", {})
        allowed = status.get("allowed") is True and not status.get("denied", False)
        reason = str(status.get("reason") or status.get("evaluationError") or "")[:512]
    except APIError as exc:
        allowed, reason = False, "Permission check failed (HTTP " + str(exc.code) + ")."
    return {"resource": resource, "verb": verb, "allowed": allowed, "reason": reason}


def binding_state(binding):
    if binding is None:
        return "Disabled"
    spec = binding.get("spec", {})
    if (spec.get("policyName") != NAME or spec.get("paramRef") != {
            "name": "cluster", "parameterNotFoundAction": "Deny"}):
        return "Unknown"
    match = _without_empty(deepcopy(spec.get("matchResources", {})))
    if not isinstance(match, dict) or match.pop("matchPolicy", "Equivalent") != "Equivalent" or match:
        return "Unknown"
    actions = spec.get("validationActions", [])
    if "Deny" in actions:
        return "Deny"
    if "Audit" in actions:
        return "Audit"
    return "Unknown"


def _candidate(cm, inventory):
    text = (cm or {}).get("data", {}).get("parameters.yaml", "")
    status = (inventory or {}).get("status", {})
    result = {"revision": "", "ready": False, "yaml": text}
    warnings, obj = [], None
    try:
        obj = yaml.load(text, Loader=StrictLoader) if text else None
        if not isinstance(obj, dict):
            raise ValueError("Candidate parameters have not been published.")
        if (obj.get("apiVersion") != "guardrail.openshift.io/v1alpha1"
                or obj.get("kind") != "NetworkGuardrailParameters"
                or obj.get("metadata", {}).get("name") != "cluster"
                or obj.get("metadata", {}).get("namespace")):
            raise ValueError("Candidate must be the cluster-scoped NetworkGuardrailParameters/cluster.")
        spec = obj.get("spec", {})
        revision = spec.get("revision", "")
        result["revision"] = revision if isinstance(revision, str) else ""
        nodes = status.get("nodes", [])
        if not nodes or status.get("ready") is not True or not all(n.get("ready") is True for n in nodes):
            raise ValueError("Current discovery inventory is not ready.")
        expected = {"revision": status.get("revision"), "ready": True,
                    "protectedInterfaces": sorted(BUILTINS | {i for n in nodes for i in n["protectedInterfaces"]}),
                    "nodes": [{k: n[k] for k in ("name", "labels", "roles", "protectedInterfaces", "ready")}
                              for n in nodes]}
        if not result["revision"] or spec != expected:
            raise ValueError("Candidate parameters do not match the current ready inventory; refresh discovery.")
        result["ready"] = True
    except (ValueError, TypeError, KeyError, AttributeError, yaml.YAMLError):
        warnings.append("Candidate parameters are absent, invalid, or inconsistent with current ready inventory.")
    return result, obj, warnings


def _snapshot(kube):
    binding = optional(kube, admission_path("validatingadmissionpolicybindings") + "/" + NAME)
    active = optional(kube, PARAMETERS + "/cluster")
    policy = optional(kube, admission_path("validatingadmissionpolicies") + "/" + NAME)
    cm = optional(kube, "/api/v1/namespaces/" + namespace() + "/configmaps/network-guardrail-candidate")
    inventory = optional(kube, INVENTORY)
    candidate, obj, warnings = _candidate(cm, inventory)
    return binding, active, policy, candidate, obj, warnings


def _without_empty(value):
    if isinstance(value, dict):
        normalized = {key: _without_empty(item) for key, item in value.items()}
        return {key: item for key, item in normalized.items() if item not in ({}, [], None)}
    if isinstance(value, list):
        return [_without_empty(item) for item in value]
    return value


def _critical_policy(spec):
    result = {key: deepcopy(spec.get(key)) for key in (
        "paramKind", "variables", "validations", "matchConditions", "auditAnnotations")}
    result["failurePolicy"] = spec.get("failurePolicy", "Fail")
    match = deepcopy(spec.get("matchConstraints", {}))
    match.setdefault("matchPolicy", "Equivalent")
    result["matchConstraints"] = match
    for validation in result.get("validations") or []:
        validation.setdefault("reason", "Invalid")
    return _without_empty(result)


def _policy_valid(policy):
    if policy is None or policy.get("metadata", {}).get("name") != NAME:
        return False
    if _critical_policy(policy.get("spec", {})) != _critical_policy(canonical_policy()["spec"]):
        return False
    status = policy.get("status", {})
    if status.get("typeChecking", {}).get("expressionWarnings"):
        return False
    generation = policy.get("metadata", {}).get("generation")
    observed = status.get("observedGeneration")
    if isinstance(generation, int) and isinstance(observed, int) and observed < generation:
        return False
    return not any(condition.get("type") in ("Accepted", "Ready", "TypeChecked") and condition.get("status") == "False"
                   for condition in status.get("conditions", []))


def _foreign(binding):
    return binding is not None and binding.get("spec", {}).get("policyName") != NAME


def get_control(kube):
    binding, active, policy, candidate, obj, warnings = _snapshot(kube)
    checks = [access(kube, "networkguardrailparameters", "update" if active else "create",
                     "guardrail.openshift.io", "cluster"),
              access(kube, "validatingadmissionpolicybindings", "update" if binding else "create",
                     "admissionregistration.k8s.io", NAME),
              access(kube, "validatingadmissionpolicybindings", "delete", "admissionregistration.k8s.io", NAME),
              access(kube, "networkguardrailevents", "create", "guardrail.openshift.io", namespaced=True)]
    active_matches = active is not None and obj is not None and active.get("spec") == obj.get("spec")
    foreign = _foreign(binding)
    if foreign:
        warnings.append("The fixed binding references another policy; this UI will not modify or delete it.")
    if binding and not active_matches:
        warnings.append("Disable the existing binding before approving a changed parameter snapshot.")
    if not _policy_valid(policy):
        warnings.append("The canonical guardrail policy is absent, changed, or has unresolved type-check/status results.")
    if binding and binding_state(binding) == "Unknown" and not foreign:
        warnings.append("The existing binding has noncanonical scope or parameters; global enforcement cannot be inferred.")
    can_enable = (checks[1]["allowed"] and (active_matches or checks[0]["allowed"])
                  and candidate["ready"] and _policy_valid(policy) and not foreign
                  and (not binding or active_matches))
    return {"state": binding_state(binding),
            "bindingResourceVersion": (binding or {}).get("metadata", {}).get("resourceVersion", ""),
            "candidate": candidate, "approvedRevision": (active or {}).get("spec", {}).get("revision", ""),
            "capabilities": {"canEnable": bool(can_enable),
                             "canDisable": not foreign and (binding is None or checks[2]["allowed"]),
                             "canRecordEvents": checks[3]["allowed"], "checks": checks},
            "message": "Configured global binding state; verify admission using server-side dry run.",
            "warnings": warnings}


def _check_version(binding, expected):
    actual = (binding or {}).get("metadata", {}).get("resourceVersion", "")
    if actual != expected:
        fail(409, "The guardrail binding changed. Refresh and confirm the current state.", refreshRequired=True)
    if _foreign(binding):
        fail(409, "The fixed binding references another policy and will not be modified.", refreshRequired=True)


def _require(check):
    if not check["allowed"]:
        fail(403, "Caller is not authorized to " + check["verb"] + " " + check["resource"] + ".")


def _metadata(existing, name):
    return deepcopy(existing["metadata"]) if existing else {"name": name}


def set_control(kube, request):
    if (not isinstance(request, dict)
            or set(request) != {"mode", "revision", "bindingResourceVersion", "confirm"}
            or request.get("mode") not in ("Deny", "Audit", "Disabled")
            or not isinstance(request.get("revision"), str)
            or not isinstance(request.get("bindingResourceVersion"), str)
            or request.get("confirm") is not True):
        fail(400, "Provide mode, revision, bindingResourceVersion, and explicit confirm: true only.")
    mode, expected = request["mode"], request["bindingResourceVersion"]
    collection = admission_path("validatingadmissionpolicybindings")
    target = collection + "/" + NAME
    binding = optional(kube, target)
    _check_version(binding, expected)
    parameters_updated = binding_updated = False
    approved_revision = ""
    if mode == "Disabled":
        if binding is not None:
            _require(access(kube, "validatingadmissionpolicybindings", "delete", "admissionregistration.k8s.io", NAME))
            metadata = binding["metadata"]
            try:
                kube.request("DELETE", target, {"apiVersion": "v1", "kind": "DeleteOptions",
                             "preconditions": {"uid": metadata["uid"], "resourceVersion": metadata["resourceVersion"]}})
            except APIError as exc:
                fail(exc.code, "Binding deletion failed: " + str(exc.body.get("message", "Kubernetes API error")),
                     parametersUpdated=False, bindingUpdated=False if exc.code < 500 else None, refreshRequired=True)
            except Exception:
                fail(502, "Binding deletion outcome is unknown; refresh before retrying.",
                     parametersUpdated=False, bindingUpdated=None, refreshRequired=True)
            binding_updated = True
    else:
        binding, active, policy, candidate, obj, _ = _snapshot(kube)
        _check_version(binding, expected)
        if not candidate["ready"] or request["revision"] != candidate["revision"]:
            fail(409, "The reviewed candidate revision is stale or discovery is not ready.", refreshRequired=True)
        if not _policy_valid(policy):
            fail(409, "The canonical guardrail VAP is absent, changed, or has unresolved type-check/status results.", refreshRequired=True)
        same_parameters = active is not None and active.get("spec") == obj["spec"]
        if binding is not None and not same_parameters:
            fail(409, "Disable the binding before approving a changed parameter snapshot.", refreshRequired=True)
        _require(access(kube, "validatingadmissionpolicybindings", "update" if binding else "create",
                        "admissionregistration.k8s.io", NAME))
        if not same_parameters:
            _require(access(kube, "networkguardrailparameters", "update" if active else "create",
                            "guardrail.openshift.io", "cluster"))
        # Recheck the shared binding immediately before the first resource write.
        _check_version(optional(kube, target), expected)
        approved_revision = candidate["revision"]
        if not same_parameters:
            parameters = {"apiVersion": "guardrail.openshift.io/v1alpha1", "kind": "NetworkGuardrailParameters",
                          "metadata": _metadata(active, "cluster"), "spec": deepcopy(obj["spec"])}
            if active is None:
                parameters["metadata"]["annotations"] = {"guardrail.openshift.io/managed-by": "console-user"}
            try:
                kube.request("PUT" if active else "POST", PARAMETERS + ("/cluster" if active else ""), parameters)
            except APIError as exc:
                fail(exc.code, "Parameter approval failed: " + str(exc.body.get("message", "Kubernetes API error")),
                     parametersUpdated=False if exc.code < 500 else None, bindingUpdated=False, refreshRequired=True)
            except Exception:
                fail(502, "Parameter approval outcome is unknown; binding was not changed. Refresh before retrying.",
                     parametersUpdated=None, bindingUpdated=False, refreshRequired=True)
            parameters_updated = True
        desired = {"apiVersion": policy["apiVersion"], "kind": "ValidatingAdmissionPolicyBinding",
                   "metadata": _metadata(binding, NAME), "spec": {"policyName": NAME,
                   "paramRef": {"name": "cluster", "parameterNotFoundAction": "Deny"},
                   "validationActions": ["Deny", "Audit"] if mode == "Deny" else ["Audit", "Warn"]}}
        if binding is None:
            desired["metadata"]["annotations"] = {"guardrail.openshift.io/managed-by": "console-user"}
        try:
            kube.request("PUT" if binding else "POST", target if binding else collection, desired)
            binding_updated = True
        except APIError as exc:
            fail(exc.code, "Binding change failed: " + str(exc.body.get("message", "Kubernetes API error")),
                 partial=parameters_updated, parametersUpdated=parameters_updated, bindingUpdated=False,
                 approvedRevision=approved_revision if parameters_updated else "", refreshRequired=True)
        except Exception:
            fail(502, "Binding request outcome could not be confirmed; refresh before retrying.",
                 partial=parameters_updated, parametersUpdated=parameters_updated, bindingUpdated=None,
                 approvedRevision=approved_revision if parameters_updated else "", refreshRequired=True)
    try:
        response = get_control(kube)
    except Exception:
        if mode == "Disabled":
            # Stopping must not depend on permission to inspect discovery data.
            try:
                current = optional(kube, target)
            except Exception:
                fail(502, "The stop request completed but current binding state could not be read. Refresh before retrying.",
                     partial=True, parametersUpdated=False, bindingUpdated=binding_updated, refreshRequired=True)
            response = {"state": binding_state(current),
                        "bindingResourceVersion": (current or {}).get("metadata", {}).get("resourceVersion", ""),
                        "candidate": {"revision": "", "ready": False, "yaml": ""}, "approvedRevision": "",
                        "capabilities": {"canEnable": False, "canDisable": not _foreign(current),
                                         "canRecordEvents": False, "checks": []},
                        "warnings": ["Current binding state was read, but discovery and approval details are unavailable. Refresh before enabling."]}
        else:
            fail(502, "The write completed but refreshed state could not be read. Refresh before retrying.",
                 partial=True, parametersUpdated=parameters_updated, bindingUpdated=binding_updated,
                 refreshRequired=True)
    response.update(parametersUpdated=parameters_updated, bindingUpdated=binding_updated,
                    message="Global mode request completed. Admission caches may take time to observe it; verify with dry run.")
    return response
