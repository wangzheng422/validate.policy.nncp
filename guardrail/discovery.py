# AI-Author: Codex (OpenAI model not exposed by runtime)
"""Conservative, read-only discovery from Node and NodeNetworkState snapshots."""

from datetime import datetime, timezone
import hashlib
import ipaddress
import json

BUILTINS = {"br-ex", "br-int", "ovn-k8s-mp0"}


def utcnow():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def is_default(destination):
    try:
        return ipaddress.ip_network(destination, strict=False).prefixlen == 0
    except (ValueError, TypeError):
        return False


def ports(value):
    """NMState represents bond ports as strings and bridge ports as objects."""
    result = set()
    if isinstance(value, list):
        for entry in value:
            if isinstance(entry, str):
                result.add(entry)
            elif isinstance(entry, dict):
                if isinstance(entry.get("name"), str):
                    result.add(entry["name"])
                result.update(ports(entry.get("link-aggregation", {}).get("port", [])))
    return result


def discover_node(node, nns):
    name = node["metadata"]["name"]
    labels = node["metadata"].get("labels", {})
    roles = sorted(k.split("/", 1)[1] for k in labels if k.startswith("node-role.kubernetes.io/"))
    result = {"name": name, "labels": labels, "roles": roles, "ready": False,
              "protectedInterfaces": sorted(BUILTINS), "primaryPath": [],
              "defaultRoutes": [], "edges": [], "evidence": [], "warnings": []}
    if not nns:
        result["warnings"].append("NodeNetworkState is missing; no complete primary path evidence.")
        return result
    state = nns.get("status", {}).get("currentState", {})
    interfaces = state.get("interfaces", [])
    by_name = {i["name"]: i for i in interfaces if isinstance(i.get("name"), str)}
    edges = set()
    logical_ports = set()
    for iface in interfaces:
        name_i = iface.get("name")
        if not name_i:
            continue
        dependencies = ports(iface.get("bridge", {}).get("port", []))
        dependencies |= ports(iface.get("link-aggregation", {}).get("port", []))
        dependencies |= ports(iface.get("vrf", {}).get("port", []))
        for port in iface.get("bridge", {}).get("port", []):
            if isinstance(port, dict) and port.get("name") and port.get("link-aggregation", {}).get("port"):
                logical_ports.add(port["name"])
        for typ in ("vlan", "vxlan", "mac-vlan", "mac-vtap", "ipvlan"):
            base = iface.get(typ, {}).get("base-iface")
            if isinstance(base, str):
                dependencies.add(base)
        for child in dependencies:
            if child != name_i:
                edges.add((name_i, child))
        controller = iface.get("controller")
        if isinstance(controller, str) and controller:
            edges.add((controller, name_i))
    routes = state.get("routes", {})
    defaults = [r for r in routes.get("running", routes.get("config", []))
                if is_default(r.get("destination")) and r.get("state") != "absent"]
    seeds = set(BUILTINS & by_name.keys())
    for route in defaults:
        interface = route.get("next-hop-interface")
        if not interface:
            result["warnings"].append("Default route without next-hop-interface is unresolved.")
            continue
        seeds.add(interface)
        result["defaultRoutes"].append({"destination": route["destination"], "interface": interface,
                                         "gateway": route.get("next-hop-address", ""),
                                         "table": route.get("table-id")})
        result["evidence"].append(f"Default route {route['destination']} uses {interface}.")
    internal_ips = {a["address"] for a in node.get("status", {}).get("addresses", [])
                    if a.get("type") == "InternalIP"}
    for iface in interfaces:
        ips = {a.get("ip") for family in ("ipv4", "ipv6")
               for a in iface.get(family, {}).get("address", [])}
        if ips & internal_ips:
            seeds.add(iface["name"])
            result["evidence"].append(f"Node InternalIP is assigned to {iface['name']}.")
    # Traverse both directions: a physical default-route device may be enslaved
    # to a controller, and all dependencies of that controller must be protected.
    protected = set(seeds)
    while True:
        next_set = protected | {b for a, b in edges if a in protected} | {a for a, b in edges if b in protected}
        if next_set == protected:
            break
        protected = next_set
    missing = protected - by_name.keys() - logical_ports
    if missing:
        result["warnings"].append("Unresolved interface dependencies: " + ", ".join(sorted(missing)))
    if not defaults:
        result["warnings"].append("No default route observed; primary path needs manual review.")
    if len({r.get("next-hop-interface") for r in defaults}) > 1:
        result["evidence"].append("Multiple default paths detected; all paths are protected.")
    aliases = set()
    for interface in protected:
        details = by_name.get(interface, {})
        if isinstance(details.get("profile-name"), str):
            aliases.add(details["profile-name"])
        aliases.update(ports(details.get("alt-names", [])))
    if aliases:
        result["evidence"].append("Also protecting observed profile and alternative names: " + ", ".join(sorted(aliases)))
    result["protectedInterfaces"] = sorted(protected | BUILTINS | aliases)
    result["primaryPath"] = sorted(protected)
    result["edges"] = [{"from": a, "to": b} for a, b in sorted(edges) if a in protected and b in protected]
    result["evidence"].append("Source: NodeNetworkState/" + name + " resourceVersion=" + nns["metadata"].get("resourceVersion", "unknown"))
    result["ready"] = bool(defaults and interfaces and not result["warnings"])
    return result


def discover(nodes, states):
    by_name = {n["metadata"]["name"]: n for n in states}
    inventory_nodes = [discover_node(n, by_name.get(n["metadata"]["name"]))
                       for n in sorted(nodes, key=lambda n: n["metadata"]["name"])]
    parameters = {"ready": bool(inventory_nodes) and all(n["ready"] for n in inventory_nodes),
                  "protectedInterfaces": sorted(BUILTINS | {i for n in inventory_nodes for i in n["protectedInterfaces"]}),
                  "nodes": [{k: n[k] for k in ("name", "labels", "roles", "protectedInterfaces", "ready")}
                            for n in inventory_nodes]}
    revision = hashlib.sha256(json.dumps(parameters, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
    parameters["revision"] = revision
    inventory = {"nodes": inventory_nodes, "revision": revision, "ready": parameters["ready"],
                 "discoveredAt": utcnow(), "warnings": []}
    if not parameters["ready"]:
        inventory["warnings"].append("Incomplete discovery: do not approve this parameter snapshot.")
    return inventory, {"apiVersion": "guardrail.openshift.io/v1alpha1", "kind": "NetworkGuardrailParameters",
                       "metadata": {"name": "cluster"}, "spec": parameters}
