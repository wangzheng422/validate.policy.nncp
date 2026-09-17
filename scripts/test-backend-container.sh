#!/usr/bin/env bash
# AI-Author: Codex (OpenAI model not exposed by runtime)
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
image=${BACKEND_TEST_IMAGE:-localhost/network-guardrail:0.1.0}
work=$(mktemp -d /tmp/network-guardrail-backend.XXXXXX)
container=''
mkdir -m 0755 "$work/cert"
cleanup() {
  local result=$?
  if [[ -n "$container" ]]; then
    if [[ $result != 0 ]]; then
      podman logs "$container" >&2 || true
    fi
    podman rm -f "$container" >/dev/null || true
  fi
  rm -rf -- "$work"
  exit "$result"
}
trap cleanup EXIT
podman build --tag "$image" --file "$root/Containerfile" "$root"
printf '\nBuilt image identity (ID and any registry digests):\n'
podman image inspect --format '{{.Id}} {{json .RepoDigests}}' "$image"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$work/cert/tls.key" -out "$work/cert/tls.crt" \
  -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  > "$work/cert.stdout" 2> "$work/cert.stderr"
# Disposable localhost certificate only; parent temporary directory is mode 0700.
# The random container UID must be able to read the mounted test key.
chmod 0644 "$work/cert/tls.key" "$work/cert/tls.crt"
container=$(podman run --detach --user 10001:0 --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --volume "$work/cert:/var/run/serving-cert:ro,Z" \
  --publish 127.0.0.1::8443 "$image")
port=$(podman port "$container" 8443/tcp)
endpoint="https://$port"
ready=false
for attempt in $(seq 1 40); do
  if curl --silent --show-error --fail --max-time 2 --cacert "$work/cert/tls.crt" \
      "$endpoint/healthz" > "$work/health.json" 2> "$work/curl.stderr"; then
    ready=true
    break
  fi
  if [[ $(podman inspect --format '{{.State.Running}}' "$container") != true ]]; then
    break
  fi
  sleep 1
done
if [[ "$ready" != true ]]; then
  cat "$work/curl.stderr" >&2
  printf 'HTTPS health endpoint did not become ready\n' >&2
  exit 1
fi
printf '\nHTTPS health response:\n'
cat "$work/health.json"
printf '\nUnauthenticated overview response:\n'
code=$(curl --silent --show-error --max-time 5 --cacert "$work/cert/tls.crt" \
  --output "$work/unauth.json" --write-out '%{http_code}' "$endpoint/overview")
cat "$work/unauth.json"
printf '\nHTTP status: %s\n' "$code"
[[ "$code" == 401 ]]
python3 - "$work/health.json" "$work/unauth.json" <<'PY'
import json
import sys
from pathlib import Path
assert json.loads(Path(sys.argv[1]).read_text()) == {'status': 'ok'}
assert json.loads(Path(sys.argv[2]).read_text()) == {'error': 'Console user bearer token required'}
print('PASS HTTPS health and unauthenticated API boundary')
PY
printf '\nContainer runtime constraints:\n'
podman inspect --format 'User={{.Config.User}} ReadonlyRootfs={{.HostConfig.ReadonlyRootfs}} CapDrop={{json .HostConfig.CapDrop}} SecurityOpt={{json .HostConfig.SecurityOpt}}' "$container"
podman exec "$container" python -c 'import os; from pathlib import Path; assert os.geteuid() == 10001; assert not os.access("/opt/app-root/src", os.W_OK); print("PASS UID=10001 and application directory is not writable")'
printf '\nBackend container smoke test passed. No Kubernetes API was contacted.\n'
