#!/usr/bin/env bash
# End-to-end test WITHOUT a cluster, Docker, or runsc.
#
# Starts the collector (the monitoring process), then runs fakesentry, which
# replays a realistic agent-sandbox point stream over the real seccheck
# remote-sink wire protocol. Asserts that the collector decoded and normalized
# every point and mapped the expected ones onto node-agent event types.
#
# Exit code 0 = pass.
set -euo pipefail

cd "$(dirname "$0")/.."
export GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off

SOCK="$(mktemp -u /tmp/gvisor_events.XXXX.sock)"
OUT="$(mktemp /tmp/collector_out.XXXX.json)"
ERRLOG="$(mktemp /tmp/collector_err.XXXX.log)"
cleanup() { rm -f "$SOCK" "$OUT" "$ERRLOG"; }
trap cleanup EXIT

echo "==> building"
go build -o /tmp/collector ./cmd/collector
go build -o /tmp/fakesentry ./cmd/fakesentry

echo "==> starting collector on $SOCK"
/tmp/collector -endpoint "$SOCK" -oneshot >"$OUT" 2>"$ERRLOG" &
COLLECTOR_PID=$!

# Wait for the socket to appear (collector bound and listening).
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
if [ ! -S "$SOCK" ]; then echo "FAIL: collector never created socket"; cat "$ERRLOG"; exit 1; fi

echo "==> replaying agent-sandbox session with fakesentry"
/tmp/fakesentry -endpoint "$SOCK"

wait "$COLLECTOR_PID" || true

echo
echo "==> collector stderr:"
sed 's/^/    /' "$ERRLOG"
echo
echo "==> normalized events (stdout):"
sed 's/^/    /' "$OUT"
echo

# ---- assertions ----
fail() { echo "FAIL: $1"; exit 1; }
count() { grep -c "$1" "$OUT" || true; }

TOTAL=$(grep -c '"source":"gvisor/seccheck"' "$OUT")
[ "$TOTAL" -eq 8 ] || fail "expected 8 normalized events, got $TOTAL"

[ "$(count '"node_agent_event_type":"exec"')"    -ge 1 ] || fail "no exec event"
[ "$(count '"node_agent_event_type":"network"')" -ge 2 ] || fail "expected >=2 network events (socket+connect)"
[ "$(count '"node_agent_event_type":"open"')"     -ge 1 ] || fail "no open event"
[ "$(count '"node_agent_event_type":"fork"')"     -ge 1 ] || fail "no fork event"
[ "$(count '"node_agent_event_type":"exit"')"     -ge 1 ] || fail "no exit event"
[ "$(count '"node_agent_event_type":"ptrace"')"   -ge 1 ] || fail "no ptrace event"
grep -q '203.0.113.7:80' "$OUT" || fail "egress destination not decoded from connect()"
grep -q '"container_id":"agent-sandbox-actor-7f3a2b19"' "$OUT" || fail "container id not correlated"

echo "PASS: 8/8 points decoded from the real seccheck wire format and normalized to node-agent events."
