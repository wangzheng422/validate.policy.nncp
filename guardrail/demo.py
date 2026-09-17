# AI-Author: Codex (OpenAI model not exposed by runtime)
"""Live-inventory dry-run examples and explicitly sourced preflight history."""

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import re
from urllib.parse import quote
import uuid
import yaml

from .control import INVENTORY, optional
from .discovery import BUILTINS
from .kube import APIError, events_path
from .preflight import parse_candidate, preflight

EVENT_LIMIT = 500


def examples(kube):
    inventory = (optional(kube, INVENTORY) or {}).get("status", {})
    warnings = ["Expected outcomes assume global Deny with the matching reviewed inventory; the actual API response is authoritative.",
                "Examples are for server-side dry run only. Do not apply the primary-interface removal example."]
    nodes = [n for n in inventory.get("nodes", []) if n.get("ready") is True
             and n.get("labels", {}).get("kubernetes.io/hostname") and n.get("primaryPath")]
    if inventory.get("ready") is not True or not nodes:
        return {"items": [], "warnings": ["A ready live inventory and an explicit hostname target are required for examples."]}
    nodes.sort(key=lambda n: (bool({"master", "control-plane"} & set(n.get("roles", []))), n["name"]))
    node = nodes[0]
    parents = {edge["from"] for edge in node.get("edges", [])}
    leaves = [name for name in node["primaryPath"] if name not in BUILTINS and name not in parents]
    interface = sorted(leaves or node["primaryPath"])[0]
    base = {"apiVersion": "nmstate.io/v1", "kind": "NodeNetworkConfigurationPolicy",
            "metadata": {"name": "guardrail-example-protected-primary"},
            "spec": {"nodeSelector": {"kubernetes.io/hostname": node["labels"]["kubernetes.io/hostname"]},
                     "maxUnavailable": 1, "desiredState": {"interfaces": [{"name": interface, "state": "absent"}]}}}
    header = ("# AI-Author: Codex (OpenAI model not exposed by runtime)\n"
              "# DRY RUN ONLY: submit through Network Guardrail Preflight; do not apply.\n")
    items = [{"id": "protected-primary-removal", "title": "Reject removal of a protected primary interface",
              "description": "Intentionally dangerous removal of " + interface + " on observed node " + node["name"] + ".",
              "yaml": header + "# Intentionally dangerous example.\n" + yaml.safe_dump(base, sort_keys=False),
              "expectedOutcome": "DENIED"}]
    try:
        collection = kube.collection("nmstate.io", "nodenetworkstates")
        state = kube.get(collection + "/" + quote(node["name"], safe=""))
        resolver = state.get("status", {}).get("currentState", {}).get("dns-resolver", {})
        servers = resolver.get("config", {}).get("server") or resolver.get("running", {}).get("server", [])
        if not isinstance(servers, list) or not servers or not all(isinstance(s, str) and s for s in servers):
            raise ValueError("No observed DNS server list")
        dns = deepcopy(base)
        dns["metadata"]["name"] = "guardrail-example-dns-only"
        dns["spec"]["desiredState"] = {"dns-resolver": {"config": {"server": servers}}}
        items.append({"id": "dns-only", "title": "Allow an isolated DNS-only request",
                      "description": "Reuses DNS servers observed on " + node["name"] + " without interface changes.",
                      "yaml": header + yaml.safe_dump(dns, sort_keys=False), "expectedOutcome": "ALLOWED"})
    except (APIError, ValueError, TypeError, AttributeError):
        warnings.append("The DNS-only example is unavailable because the caller could not read an observed DNS server list.")
    return {"items": items, "warnings": warnings}


def _identity(kube):
    try:
        review, _ = kube.request("POST", "/apis/authentication.k8s.io/v1/selfsubjectreviews",
                                 {"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"})
        username = review.get("status", {}).get("userInfo", {}).get("username")
        if isinstance(username, str) and username:
            return username[:256], True
    except Exception:
        pass
    return "unknown", False


def _retain_preflight(kube):
    items = [obj for obj in kube.list(events_path())
             if obj.get("spec", {}).get("source") == "preflight"
             and obj.get("metadata", {}).get("name", "").startswith("preflight-")
             and obj.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/managed-by") == "network-guardrail"]
    items.sort(key=lambda obj: obj.get("spec", {}).get("timestamp", ""), reverse=True)
    for obj in items[EVENT_LIMIT:]:
        metadata = obj["metadata"]
        if not metadata.get("uid") or not metadata.get("resourceVersion"):
            raise ValueError("History metadata lacks deletion preconditions")
        kube.request("DELETE", events_path() + "/" + quote(metadata["name"], safe=""),
                     {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {
                         "uid": metadata["uid"], "resourceVersion": metadata["resourceVersion"]}})


def preflight_with_history(kube, text):
    result = preflight(kube, text)
    result.update(eventRecorded=False, eventWarning="", eventName="")
    if result.get("outcome") != "DENIED" or result.get("allowed") is not False:
        return result
    candidate = parse_candidate(text)
    username, verified = _identity(kube)
    warnings = [] if verified else ["Caller identity could not be verified; history records username as unknown."]
    message = str(result.get("message", ""))
    marker = re.search(r"denied request: (GR-\d+)\s+([A-Z_]+):", message)
    binding = re.search(r"with binding '([^']+)' denied request:", message)
    audit_id = result.get("auditID", "")
    identity = audit_id or str(uuid.uuid4())
    event_name = "preflight-" + hashlib.sha256(identity.encode()).hexdigest()[:40]
    event = {"apiVersion": "guardrail.openshift.io/v1alpha1", "kind": "NetworkGuardrailEvent",
             "metadata": {"name": event_name, "labels": {"app.kubernetes.io/managed-by": "network-guardrail",
                                                          "guardrail.openshift.io/source": "preflight"}},
             "spec": {"source": "preflight", "dryRun": True, "auditID": audit_id,
                      "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                      "username": username, "usernameVerified": verified,
                      "verb": result.get("operation", "CREATE").lower(), "name": candidate["metadata"]["name"],
                      "action": "DENY", "policy": "network-guardrail",
                      "binding": binding[1] if binding else "", "rule": marker[1] if marker else "",
                      "category": marker[2] if marker else "", "reason": message[:4096],
                      "responseCode": result.get("statusCode"), "outcome": result["outcome"]}}
    try:
        kube.request("POST", events_path(), event)
        result["eventRecorded"] = True
        result["eventName"] = event_name
    except APIError as exc:
        warnings.append("The denial is real, but history creation was not confirmed (HTTP " + str(exc.code) + ").")
    except Exception:
        warnings.append("The denial is real, but history creation could not be confirmed.")
    if result["eventRecorded"]:
        try:
            _retain_preflight(kube)
        except APIError as exc:
            warnings.append("History was saved, but its 500-event retention could not be completed with caller permissions (HTTP " + str(exc.code) + ").")
        except Exception:
            warnings.append("History was saved, but its 500-event retention could not be confirmed.")
    result["eventWarning"] = " ".join(warnings)
    return result
