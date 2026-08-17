#!/usr/bin/env bash
# Real end-to-end run against gVisor (no Kubernetes cluster required).
#
# Prerequisites (any Linux box; no GKE needed):
#   - Docker installed
#   - gVisor (runsc) installed and registered as a Docker runtime:
#       https://gvisor.dev/docs/user_guide/install/
#     Verify with:  docker info | grep -i runtimes   # should list "runsc"
#
# This demonstrates the key claim of the design: `runsc trace create` attaches a
# seccheck session to an ALREADY-RUNNING sandbox, and our collector receives the
# live point stream over the remote sink. The collector code path is identical to
# the cluster-free E2E — only the sender changes (real Sentry vs. fakesentry).
set -euo pipefail
cd "$(dirname "$0")/.."
export GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off

SOCK=/tmp/gvisor_events.sock
CONFIG="$(pwd)/configs/trace-session.json"

command -v docker >/dev/null || { echo "docker not found"; exit 1; }
command -v runsc  >/dev/null || echo "note: 'runsc' not on PATH; assuming Docker has it registered as a runtime"

echo "==> building collector"
go build -o /tmp/collector ./cmd/collector

echo "==> starting collector on $SOCK (leave running in this terminal)"
/tmp/collector -endpoint "$SOCK" -pretty &
COLLECTOR_PID=$!
trap 'kill $COLLECTOR_PID 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done

echo "==> launching a gVisor-sandboxed workload (models an agent actor)"
CID=$(docker run -d --runtime=runsc --rm alpine:3.20 \
        sh -c 'while true; do wget -q -O- http://example.com >/dev/null 2>&1; cat /etc/hostname >/dev/null; sleep 2; done')
echo "    container: $CID"

# Map the Docker container to its runsc sandbox id. With the default setup the
# sandbox id equals the container id; adjust if your runsc root differs.
SANDBOX_ID="$CID"

echo "==> attaching a seccheck trace session to the RUNNING sandbox"
echo "    (this is the dynamic-attach capability the design relies on)"
sudo runsc --root /var/run/docker/runtime-runc/moby \
     trace create --config "$CONFIG" "$SANDBOX_ID" || {
        echo "If the --root path is wrong, find it with:  sudo runsc list"
        echo "then re-run:  sudo runsc --root <root> trace create --config $CONFIG $SANDBOX_ID"
     }

echo "==> collector is now printing normalized node-agent events from inside the sandbox."
echo "    Ctrl-C to stop. To tear down:  docker kill $CID"
wait $COLLECTOR_PID
