#!/usr/bin/env bash
# AI-Author: Codex (OpenAI model not exposed by runtime)
# Local packaging/TLS test only; does not access a cluster.
set -euo pipefail
image="${1:-localhost/network-guardrail-console:validation}"
cert_dir="$(mktemp -d /tmp/network-guardrail-tls.XXXXXX)"
container_name="network-guardrail-test-$(date +%s)-$$"
container_id=""
cleanup() {
  if podman container exists "$container_name"; then podman rm -f "$container_name"; fi
  rm -rf "$cert_dir"
}
trap cleanup EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' \
  -keyout "$cert_dir/tls.key" -out "$cert_dir/tls.crt"
chmod 755 "$cert_dir"
chmod 640 "$cert_dir/tls.key"
container_id="$(podman run -d --name "$container_name" --user 10001:0 --read-only --tmpfs /tmp \
  --cap-drop=ALL --security-opt=no-new-privileges \
  -v "$cert_dir:/var/run/serving-cert:ro,Z" \
  -p 127.0.0.1::9443 "$image")"
port="$(podman port "$container_id" 9443/tcp | cut -d: -f2)"
curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 \
  --cacert "$cert_dir/tls.crt" "https://localhost:$port/healthz"
curl --fail --silent --show-error --cacert "$cert_dir/tls.crt" \
  "https://localhost:$port/plugin-manifest.json" > "$cert_dir/manifest.json"
python3 - "$cert_dir/manifest.json" <<'PY'
import json,sys
manifest=json.load(open(sys.argv[1]))
assert manifest['name']=='network-guardrail'
assert manifest['registrationMethod']=='callback'
assert manifest['loadScripts']==['plugin-entry.js']
print('PASS: manifest served over certificate-verified TLS')
PY
curl --fail --silent --show-error --cacert "$cert_dir/tls.crt" \
  "https://localhost:$port/plugin-entry.js" -o "$cert_dir/entry.js"
python3 - "$cert_dir/entry.js" <<'PY'
import sys
assert 'loadPluginEntry("network-guardrail@0.1.0"' in open(sys.argv[1]).read()
print('PASS: compiled plugin entry is available')
PY
podman logs "$container_id"
printf 'PASS: nginx runs as arbitrary UID 10001 with group 0, read-only root, no capabilities, HTTPS 9443\n'
