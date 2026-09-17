# AI-Author: Codex (OpenAI model not exposed by runtime)
"""HTTPS Console proxy backend. Every resource read uses the logged-in caller."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import ssl
from urllib.parse import parse_qs, unquote, urlsplit
import yaml

from .controller import policy
from .control import ControlError, binding_state, get_control, set_control
from .demo import examples, preflight_with_history
from .kube import APIError, GROUP, Kube, admission_path, events_path, namespace
from .topology import render_topology


def optional(kube, path):
    try:
        return kube.get(path)
    except APIError as exc:
        if exc.code == 404:
            return None
        raise


def inventory(kube):
    obj = optional(kube, GROUP + "/primarynetworkinventories/cluster")
    return (obj or {}).get("status", {"nodes": [], "ready": False, "warnings": ["Discovery has not published inventory."]})


def enforcement(kube):
    binding = optional(kube, admission_path("validatingadmissionpolicybindings") + "/network-guardrail")
    if not binding:
        return {"state": "Disabled", "message": "No binding installed; requests are not blocked by this policy."}
    actions = binding.get("spec", {}).get("validationActions", [])
    state = binding_state(binding)
    message = ("The binding has noncanonical scope or parameters; global enforcement cannot be inferred."
               if state == "Unknown" else "Configured global binding actions: " + ", ".join(actions) + ". Verify with server dry-run.")
    return {"state": state, "message": message}


def event_list(kube):
    items = kube.list(events_path())
    for item in items:
        item.setdefault("spec", {}).setdefault("source", "audit-log")
    items.sort(key=lambda x: x.get("spec", {}).get("timestamp", ""), reverse=True)
    return {"items": items[:500], "warnings": ["History distinguishes real API preflight denials from optional audit-log collection. Preflight records are dry-run results; they do not prove that a change was applied. Direct CLI requests appear only when audit collection is enabled and functioning. Accepted requests and full submitted bodies are not stored."]}


def policies(kube):
    live = optional(kube, admission_path("validatingadmissionpolicies") + "/network-guardrail")
    binding = optional(kube, admission_path("validatingadmissionpolicybindings") + "/network-guardrail")
    cm = optional(kube, "/api/v1/namespaces/" + namespace() + "/configmaps/network-guardrail-candidate")
    active = optional(kube, GROUP + "/networkguardrailparameters/cluster")
    param_text = (cm or {}).get("data", {}).get("parameters.yaml", "")
    candidate = yaml.safe_load(param_text) if param_text else {}
    candidate_spec = (candidate or {}).get("spec", {})
    current = live or policy()
    rules = []
    for v in current["spec"]["validations"]:
        prefix = v.get("message", "").split(":", 1)[0].split(" ", 1)
        rules.append({"id": prefix[0], "category": prefix[1] if len(prefix) > 1 else "",
                      "message": v.get("message", ""), "expression": v["expression"]})
    active_rev = (active or {}).get("spec", {}).get("revision", "")
    warnings = []
    if candidate_spec.get("revision") != active_rev:
        warnings.append("Discovered candidate differs from approved parameters; review and apply a fresh snapshot.")
    return {"items": [{"name": "network-guardrail", "kind": "ValidatingAdmissionPolicy", "active": live is not None and binding is not None,
                        "rules": rules, "yaml": yaml.safe_dump(current, sort_keys=False)}],
            "candidate": {"revision": candidate_spec.get("revision", ""), "ready": candidate_spec.get("ready", False), "yaml": param_text},
            "activeRevision": active_rev, "warnings": warnings}


def overview(kube):
    data = inventory(kube)
    state = enforcement(kube)
    pol = policies(kube)
    events = event_list(kube)
    return {"collectedAt": data.get("discoveredAt", ""), "enforcement": state,
            "counts": {"nodes": len(data["nodes"]), "readyNodes": sum(n["ready"] for n in data["nodes"]),
                       "events": len(events["items"]), "rules": len(pol["items"][0]["rules"])},
            "warnings": data.get("warnings", []) + pol["warnings"] + events["warnings"]}


class Handler(BaseHTTPRequestHandler):
    server_version = "NetworkGuardrail/0.2"

    def log_message(self, format, *args):
        # Never log credentials, user-supplied YAML, or query parameters.
        return

    def send(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def dispatch(self):
        path = urlsplit(self.path).path
        if path == "/healthz" and self.command == "GET":
            return self.send(200, {"status": "ok"})
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or not auth[7:].strip():
            return self.send(401, {"error": "Console user bearer token required"})
        kube = Kube(token=auth[7:].strip())
        routes = {"/overview": overview, "/inventory": inventory, "/policies": policies, "/events": event_list,
                  "/control": get_control, "/examples": examples}
        if path.startswith("/api/"):
            path = path[4:]
        if self.command == "GET" and path in routes:
            return self.send(200, routes[path](kube))
        if self.command == "GET" and path.startswith("/topology/"):
            query = parse_qs(urlsplit(self.path).query)
            languages = query.get("lang", ["en"])
            if len(languages) != 1:
                raise ValueError("Only one topology language is accepted")
            return self.send(200, render_topology(kube, unquote(path[len("/topology/"):], errors="strict"), languages[0]))
        if self.command == "POST" and path in ("/preflight", "/control"):
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 256 * 1024:
                return self.send(413, {"error": "Request size must be between 1 byte and 256 KiB"})
            if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
                return self.send(415, {"error": "application/json required"})
            body = json.loads(self.rfile.read(length))
            if path == "/control":
                return self.send(200, set_control(kube, body))
            if not isinstance(body, dict) or set(body) != {"yaml"}:
                raise ValueError("Expected a JSON object containing only yaml")
            return self.send(200, preflight_with_history(kube, body["yaml"]))
        self.send(404, {"error": "Endpoint not found"})

    def handle_request(self):
        self.connection.settimeout(30)
        try:
            self.dispatch()
        except ControlError as exc:
            self.send(exc.code, {"error": exc.body.get("message", "Guardrail control failed"),
                                 **{key: value for key, value in exc.body.items() if key != "message"}})
        except APIError as exc:
            self.send(exc.code, {"error": exc.body.get("message", "Kubernetes API error")})
        except (ValueError, TypeError, yaml.YAMLError, RecursionError):
            self.send(400, {"error": "Invalid request or YAML. Supply one well-formed NNCP without aliases or duplicate keys."})
        except Exception as exc:
            print("API failure: " + type(exc).__name__, flush=True)
            self.send(502, {"error": "Backend request failed; check API connectivity and backend logs."})

    do_GET = handle_request
    do_POST = handle_request


def run():
    server = ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8443"))), Handler)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(os.environ.get("TLS_CERT", "/var/run/serving-cert/tls.crt"),
                            os.environ.get("TLS_KEY", "/var/run/serving-cert/tls.key"))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
