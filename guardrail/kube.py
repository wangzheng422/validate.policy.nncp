# AI-Author: Codex (OpenAI model not exposed by runtime)
"""Small TLS-verified Kubernetes REST client. No shell, exec, or kubeconfig logging."""

import json
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.parse
import urllib.request

GROUP = "/apis/guardrail.openshift.io/v1alpha1"
NNCP = "/apis/nmstate.io/v1/nodenetworkconfigurationpolicies"
SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")


class APIError(Exception):
    def __init__(self, code, body, headers=None):
        self.code, self.body, self.headers = code, body, headers or {}
        super().__init__(body.get("message", "Kubernetes API request failed"))


class Kube:
    def __init__(self, token=None):
        self.token = token
        host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
        if ":" in host and not host.startswith("["):
            host = "[" + host + "]"
        self.base = "https://" + host + ":" + os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        self.context = ssl.create_default_context(cafile=str(SA_DIR / "ca.crt"))

    def request(self, method, path, body=None, content_type="application/json"):
        # Defense in depth: this application has no persistent NNCP write path.
        if path.startswith(NNCP) and method not in ("GET", "HEAD"):
            if urllib.parse.parse_qs(urllib.parse.urlsplit(path).query).get("dryRun") != ["All"]:
                raise ValueError("Persistent NNCP writes are forbidden")
        token = self.token if self.token is not None else (SA_DIR / "token").read_text().strip()
        req = urllib.request.Request(self.base + path,
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers={"Authorization": "Bearer " + token, "Content-Type": content_type,
                                              "Accept": "application/json", "User-Agent": "network-guardrail/0.2.0"},
                                     method=method)
        try:
            with urllib.request.urlopen(req, context=self.context, timeout=20) as response:
                payload = response.read()
                return json.loads(payload) if payload else {}, dict(response.headers)
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read())
            except (ValueError, UnicodeDecodeError):
                payload = {"message": "Kubernetes API returned a non-JSON error"}
            raise APIError(exc.code, payload, dict(exc.headers)) from None

    def get(self, path):
        return self.request("GET", path)[0]

    def list(self, path):
        items, cursor = [], ""
        while True:
            query = "?limit=500" + ("&continue=" + urllib.parse.quote(cursor, safe="") if cursor else "")
            page = self.get(path + query)
            items.extend(page.get("items", []))
            cursor = page.get("metadata", {}).get("continue", "")
            if not cursor:
                return items

    def collection(self, group, resource):
        """Resolve each resource's served version; NMState NNS may remain beta."""
        discovery = self.get("/apis/" + group)
        preferred = discovery.get("preferredVersion", {}).get("groupVersion")
        versions = sorted(discovery.get("versions", []), key=lambda v: v["groupVersion"] != preferred)
        for version in versions:
            path = "/apis/" + version["groupVersion"]
            try:
                resources = self.get(path).get("resources", [])
            except APIError as exc:
                if exc.code == 404:
                    continue
                raise
            if any(r.get("name") == resource for r in resources):
                return path + "/" + resource
        raise APIError(404, {"message": "Required resource is not served: " + group + "/" + resource})

    def upsert(self, collection, obj):
        name = urllib.parse.quote(obj["metadata"]["name"], safe="")
        try:
            current = self.get(collection + "/" + name)
        except APIError as exc:
            if exc.code != 404:
                raise
            return self.request("POST", collection, obj)[0]
        obj["metadata"]["resourceVersion"] = current["metadata"]["resourceVersion"]
        return self.request("PUT", collection + "/" + name, obj)[0]


def namespace():
    return os.environ.get("NAMESPACE", "network-guardrail")


def events_path():
    return GROUP + "/namespaces/" + namespace() + "/networkguardrailevents"


def admission_path(resource):
    version = os.environ.get("POLICY_API_VERSION", "admissionregistration.k8s.io/v1beta1")
    return "/apis/" + version + "/" + resource
