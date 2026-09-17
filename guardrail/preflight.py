# AI-Author: Codex (OpenAI model not exposed by runtime)
"""Real admission preflight, always dryRun=All, using the caller's token."""

import re
from urllib.parse import quote
import yaml

from .kube import APIError, NNCP


class StrictLoader(yaml.SafeLoader):
    """Reject duplicate YAML keys and alias graphs before building the request."""
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ValueError("YAML aliases are not accepted")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        keys = set()
        for key, _ in node.value:
            name = self.construct_object(key, deep=deep)
            if not isinstance(name, str) or name in keys:
                raise ValueError("YAML mapping keys must be unique strings")
            keys.add(name)
        return super().construct_mapping(node, deep=deep)


def parse_candidate(text):
    if not isinstance(text, str) or len(text.encode()) > 128 * 1024:
        raise ValueError("Provide one NNCP YAML document, at most 128 KiB")
    obj = yaml.load(text, Loader=StrictLoader)
    if not isinstance(obj, dict) or obj.get("apiVersion") != "nmstate.io/v1" or obj.get("kind") != "NodeNetworkConfigurationPolicy":
        raise ValueError("Only nmstate.io/v1 NodeNetworkConfigurationPolicy is accepted")
    meta = obj.get("metadata", {})
    name = meta.get("name", "") if isinstance(meta, dict) else ""
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", name):
        raise ValueError("A valid explicit metadata.name is required")
    if meta.get("namespace") or meta.get("generateName"):
        raise ValueError("NNCP is cluster scoped; namespace and generateName are not accepted")
    if not isinstance(obj.get("spec"), dict):
        raise ValueError("NNCP spec must be an object")
    if set(obj) - {"apiVersion", "kind", "metadata", "spec"}:
        raise ValueError("Only apiVersion, kind, metadata and spec are accepted")
    # Status/managed fields cannot influence dry-run submission.
    obj["metadata"] = {k: v for k, v in meta.items() if k in ("name", "labels", "annotations")}
    return obj


def preflight(kube, text):
    obj = parse_candidate(text)
    name = obj["metadata"]["name"]
    target = NNCP + "/" + quote(name, safe="")
    operation = "CREATE"
    try:
        current = kube.get(target)
    except APIError as exc:
        if exc.code != 404:
            raise
        current = None
    try:
        if current is None:
            _, headers = kube.request("POST", NNCP + "?dryRun=All&fieldValidation=Strict", obj)
        else:
            operation = "UPDATE"
            obj["metadata"]["resourceVersion"] = current["metadata"]["resourceVersion"]
            # This is an explicit replacement preflight, not a claim about SSA merge semantics.
            _, headers = kube.request("PUT", target + "?dryRun=All&fieldValidation=Strict", obj)
        return {"allowed": True, "outcome": "ALLOWED", "message": "API server accepted this dry-run; no NNCP was persisted. This does not prove operational network safety.",
                "dryRun": True, "operation": operation, "statusCode": 200,
                "auditID": headers.get("Audit-Id", headers.get("Audit-ID", "")),
                "warnings": [headers["Warning"]] if headers.get("Warning") else []}
    except APIError as exc:
        # A forbidden RBAC request, syntax error, timeout, or missing API is NOT
        # evidence that a guardrail rejected a dangerous configuration.
        message = exc.body.get("message", "Kubernetes API error")
        prefix = r"ValidatingAdmissionPolicy 'network-guardrail' with binding '[^']+' denied request: GR-\d+\b"
        causes = exc.body.get("details", {}).get("causes", [])
        denied = exc.code in (400, 403, 422) and any(
            isinstance(cause, dict) and not cause.get("field") and
            re.match(prefix, cause.get("message", "")) for cause in causes)
        return {"allowed": False if denied else None, "outcome": "DENIED" if denied else "ERROR",
                "message": message, "dryRun": True, "operation": operation, "statusCode": exc.code,
                "auditID": exc.headers.get("Audit-Id", ""), "warnings": []}
