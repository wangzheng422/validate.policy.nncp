# AI-Author: Codex (OpenAI model not exposed by runtime)
"""Filter VAP failures, discard request bodies, retain bounded history."""

import hashlib
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import parse_qs, urlsplit

from .kube import APIError, Kube, events_path

ANNOTATION = "validation.policy.admission.k8s.io/validation_failure"


def events_from_audit(event):
    ref = event.get("objectRef", {})
    if (event.get("stage") != "ResponseComplete" or ref.get("apiGroup") != "nmstate.io"
            or ref.get("resource") != "nodenetworkconfigurationpolicies"
            or event.get("verb") not in ("create", "update", "patch")):
        return []
    raw = event.get("annotations", {}).get(ANNOTATION)
    if not isinstance(raw, str) or not event.get("auditID"):
        return []
    try:
        failures = json.loads(raw)
    except ValueError:
        return []
    if not isinstance(failures, list):
        return []
    result = []
    code = event.get("responseStatus", {}).get("code", 0)
    for failure in failures:
        if not isinstance(failure, dict) or failure.get("policy") != "network-guardrail":
            continue
        message = str(failure.get("message", ""))[:2048]
        match = re.match(r"(GR-\d+)\s+([A-Z_]+):", message)
        key = event["auditID"] + ":" + str(failure.get("expressionIndex", "")) + ":" + str(failure.get("binding", ""))
        name = "audit-" + hashlib.sha256(key.encode()).hexdigest()[:40]
        spec = {"timestamp": event.get("stageTimestamp", event.get("requestReceivedTimestamp", "")),
                "username": str(event.get("user", {}).get("username", ""))[:256],
                "sourceIPs": event.get("sourceIPs", [])[:8], "userAgent": str(event.get("userAgent", ""))[:256],
                "verb": event.get("verb", ""), "name": ref.get("name", ""),
                "action": "DENY" if "Deny" in failure.get("validationActions", []) and code >= 400 else "AUDIT",
                "reason": message, "rule": match[1] if match else "", "category": match[2] if match else "",
                "policy": failure["policy"], "binding": failure.get("binding", ""),
                "auditID": event["auditID"], "responseCode": code,
                "expressionIndex": failure.get("expressionIndex", -1),
                "dryRun": parse_qs(urlsplit(event.get("requestURI", "")).query).get("dryRun") == ["All"]}
        result.append({"apiVersion": "guardrail.openshift.io/v1alpha1", "kind": "NetworkGuardrailEvent",
                       "metadata": {"name": name, "labels": {"app.kubernetes.io/managed-by": "network-guardrail"}}, "spec": spec})
    return result


def persist(kube, event):
    for obj in events_from_audit(event):
        try:
            kube.request("POST", events_path(), obj)
        except APIError as exc:
            if exc.code != 409:
                raise


def retain(kube, limit):
    items = [x for x in kube.list(events_path())
             if x.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/managed-by") == "network-guardrail"]
    items.sort(key=lambda x: x.get("spec", {}).get("timestamp", ""), reverse=True)
    for obj in items[limit:]:
        try:
            kube.request("DELETE", events_path() + "/" + obj["metadata"]["name"],
                         {"apiVersion": "v1", "kind": "DeleteOptions",
                          "preconditions": {"uid": obj["metadata"]["uid"]}})
        except APIError as exc:
            if exc.code not in (404, 409):
                raise


class Tail:
    """Checkpoint complete lines only; drain renamed open file before rotation.

    The active file is replayed after pod replacement (emptyDir checkpoint),
    deduplicated by deterministic CR names. This is bounded demo history, not
    a durable audit archive. Rotation during collector downtime may lose lines.
    """
    def __init__(self, path, checkpoint):
        self.path, self.checkpoint = Path(path), Path(checkpoint)
        self.stream = None
        self.identity = None
        self.offset = 0

    def open(self):
        self.stream = self.path.open("rb")
        stat = os.fstat(self.stream.fileno())
        self.identity = [stat.st_dev, stat.st_ino]
        try:
            saved = json.loads(self.checkpoint.read_text())
            if saved["identity"] == self.identity and 0 <= saved["offset"] <= stat.st_size:
                self.stream.seek(saved["offset"])
        except (OSError, ValueError, KeyError):
            pass
        self.offset = self.stream.tell()

    def next(self):
        if self.stream is None:
            self.open()
        if os.fstat(self.stream.fileno()).st_size < self.offset:
            self.stream.seek(0)
            self.offset = 0
        start = self.stream.tell()
        line = self.stream.readline(4 * 1024 * 1024)
        if line and line.endswith(b"\n"):
            return line
        if line:
            if len(line) >= 4 * 1024 * 1024:
                # Never hold arbitrary-size request bodies in memory.
                while line and not line.endswith(b"\n"):
                    line = self.stream.readline(64 * 1024)
                self.ack()
                print("audit oversized line skipped", flush=True)
                return b"\n"
            self.stream.seek(start)
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return None
        if [stat.st_dev, stat.st_ino] != self.identity:
            self.stream.close()
            self.stream = None
            self.open()
            return self.next()
        return None

    def ack(self):
        self.offset = self.stream.tell()
        self.checkpoint.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.checkpoint.with_suffix(".tmp")
        tmp.write_text(json.dumps({"identity": self.identity, "offset": self.offset}))
        tmp.replace(self.checkpoint)

    def retry(self):
        if self.stream:
            self.stream.seek(self.offset)


def run():
    kube = Kube()
    tail = Tail(os.environ.get("AUDIT_PATH", "/var/log/kube-apiserver/audit.log"),
                os.environ.get("AUDIT_CHECKPOINT", "/var/lib/guardrail/checkpoint.json"))
    last_gc = 0
    while True:
        try:
            line = tail.next()
            if line:
                try:
                    event = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    print("audit malformed line skipped", flush=True)
                else:
                    if isinstance(event, dict):
                        persist(kube, event)
                tail.ack()
            if time.monotonic() - last_gc > 60:
                retain(kube, max(1, int(os.environ.get("EVENT_LIMIT", "500"))))
                last_gc = time.monotonic()
            if not line:
                time.sleep(1)
        except Exception as exc:
            tail.retry()
            print("audit collection failed: " + type(exc).__name__, flush=True)
            time.sleep(5)
