# AI-Author: Codex (OpenAI model not exposed by runtime)
"""Poll live resources and publish review candidates; never activate policy."""

import os
from pathlib import Path
import time
import yaml

from .discovery import discover
from .kube import GROUP, Kube, namespace


def policy():
    result = yaml.safe_load((Path(__file__).resolve().parent.parent / "policies/nncp-policy.yaml").read_text())
    result["apiVersion"] = os.environ.get("POLICY_API_VERSION", "admissionregistration.k8s.io/v1beta1")
    return result


def reconcile(kube):
    inventory, parameters = discover(kube.list("/api/v1/nodes"), kube.list(kube.collection("nmstate.io", "nodenetworkstates")))
    collection = GROUP + "/primarynetworkinventories"
    obj = {"apiVersion": "guardrail.openshift.io/v1alpha1", "kind": "PrimaryNetworkInventory",
           "metadata": {"name": "cluster"}, "spec": {}}
    kube.upsert(collection, obj)
    kube.request("PATCH", collection + "/cluster/status", {"status": inventory}, "application/merge-patch+json")
    cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "network-guardrail-candidate"},
          "data": {"parameters.yaml": yaml.safe_dump(parameters, sort_keys=False),
                   "policy.yaml": yaml.safe_dump(policy(), sort_keys=False), "revision": inventory["revision"]}}
    kube.upsert("/api/v1/namespaces/" + namespace() + "/configmaps", cm)
    return inventory


def run():
    kube = Kube()
    while True:
        try:
            inventory = reconcile(kube)
            print(f"discovery revision={inventory['revision']} ready={inventory['ready']}", flush=True)
        except Exception as exc:
            # Avoid exception bodies that may contain submitted configuration.
            print(f"discovery failed: {type(exc).__name__}", flush=True)
        time.sleep(max(10, int(os.environ.get("INTERVAL_SECONDS", "60"))))
