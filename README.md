# gVisor runtime visibility for Kubescape node-agent — working PoC

**Part B of [kubescape/kubescape#2557](https://github.com/kubescape/kubescape/issues/2557): a working proof-of-concept for one signal source, fed into the node-agent event shape.**

The node-agent sees process/network/file activity by attaching eBPF probes to the **host** kernel. A workload running under **gVisor** never issues host syscalls — its syscalls are serviced by the **Sentry** in userspace — so from the host kernel's point of view a gVisor-sandboxed agent actor is a black box. That is the visibility gap the issue calls out: *"gVisor-isolated actors currently remain opaque to kernel-level eBPF monitoring."*

This PoC closes it for one signal source. It runs a **monitoring process** that speaks gVisor's `seccheck` **remote sink** protocol, decodes the real Sentry trace-point stream, and **normalizes each point into the exact event shape node-agent already consumes** (`exec`, `network`, `open`, `fork`, `exit`, `ptrace`, …). The Sentry sees everything the sandboxed actor does; this is the adapter that gets those signals into Kubescape's existing detection pipeline.

## What works today

- A **collector** (`cmd/collector`) that binds the `SOCK_SEQPACKET` UDS, performs the seccheck handshake, decodes the protobuf point stream against **gVisor's real schemas**, normalizes it, and emits JSON.
- A **normalizer** (`internal/normalize`) with an explicit, documented seccheck→node-agent mapping table.
- A **cluster-free end-to-end test** (`make e2e`): a faithful `fakesentry` replays a realistic agent-sandbox session over the **real wire protocol** (handshake + 8-byte header + gVisor protobufs), and the collector decodes all of it. No cluster, no Docker, no runsc needed to see it work.
- A **real-gVisor path** (`scripts/run-with-runsc.sh`) that attaches a trace session to an already-running sandbox with `runsc trace create`.
- **Unit tests** over the decode + mapping (`go test ./...`).

The protobuf bindings in `internal/pb` are generated from the **actual gVisor `.proto` files** (vendored under `proto/` with provenance), so the bytes decoded here are the bytes a real Sentry emits.

## Quick start

```bash
make e2e     # build, run collector + fakesentry over the real seccheck protocol, assert
make test    # unit tests over decode + normalization
```

Expected tail of `make e2e`:

```
PASS: 8/8 points decoded from the real seccheck wire format and normalized to node-agent events.
```

Sample normalized event (a `connect()` from inside the sandbox — invisible to host eBPF):

```json
{
  "source": "gvisor/seccheck",
  "seccheck_message": "MESSAGE_SYSCALL_CONNECT",
  "node_agent_event_type": "network",
  "node_agent_mapped": true,
  "container_id": "agent-sandbox-actor-7f3a2b19",
  "pid": 42,
  "process_name": "curl",
  "details": { "fd": 3, "remote": "203.0.113.7:80" }
}
```

## Run against real gVisor (no cluster)

Needs Docker + [runsc installed](https://gvisor.dev/docs/user_guide/install/). Then:

```bash
./scripts/run-with-runsc.sh
```

It starts the collector, launches a `--runtime=runsc` container, and attaches a
seccheck session to the **running** sandbox with `runsc trace create`. The
collector prints normalized events for the live workload. The collector code path
is identical to `make e2e`; only the sender differs (real Sentry vs. replayer).

## Signal-source mapping

| seccheck message | node-agent `EventType` | mapped |
|---|---|---|
| `MESSAGE_SYSCALL_EXECVE`, `MESSAGE_SENTRY_EXEC` | `exec` | ✅ |
| `MESSAGE_SYSCALL_CONNECT/SOCKET/BIND/ACCEPT/LISTEN` | `network` | ✅ |
| `MESSAGE_SYSCALL_OPEN` | `open` | ✅ |
| `MESSAGE_SENTRY_CLONE`, `MESSAGE_SYSCALL_CLONE/FORK` | `fork` | ✅ |
| `MESSAGE_SENTRY_TASK_EXIT`, `MESSAGE_SENTRY_EXIT_NOTIFY_PARENT` | `exit` | ✅ |
| `MESSAGE_SYSCALL_PTRACE` | `ptrace` | ✅ |
| `MESSAGE_SYSCALL_RAW` | `syscall` | ✅ |
| `MESSAGE_CONTAINER_START` | — (metadata: sandbox↔container correlation) | ⬜ |

## The `Default`-session constraint (called out honestly)

gVisor currently allows **exactly one** trace session, and it must be named
`Default` (`pkg/sentry/seccheck/config.go`: `only a single "Default" session is
supported`). If the platform or another tool already holds that session,
node-agent cannot attach a second one. This is the single most important
operational constraint for productionizing Part B. The design doc analyzes it and
proposes a contention/fallback strategy (host-boundary signals + a shared-sink
broker). See [`docs/DESIGN.md`](docs/DESIGN.md).

## Layout

```
cmd/collector     monitoring process: UDS server, decode, normalize, emit JSON
cmd/fakesentry    replays a real seccheck point stream (cluster-free E2E sender)
internal/wire     8-byte remote-sink header framing (faithful to gVisor)
internal/pb       protobuf bindings generated from gVisor's real .proto files
internal/normalize seccheck point -> node-agent event mapping (+ tests)
configs/          runsc trace-session.json (points + remote sink)
scripts/          e2e.sh (cluster-free), run-with-runsc.sh (real gVisor)
proto/            vendored gVisor .proto (provenance for internal/pb)
third_party/      pinned protobuf runtime clones for fully-offline builds
```

## Scope and non-goals

This is a **PoC for one signal source**, per the issue's minimum Part B ask. It
proves the pipe end to end and the node-agent event mapping. It is **not** a
production node-agent integration: wiring the collector in as a node-agent
`containerwatcher` tracer, DNS derivation from connect payloads, and the
multi-sandbox sink broker are the natural next steps, sketched in the design doc.

## Provenance / licensing

`proto/*.proto` are copied from [google/gvisor](https://github.com/google/gvisor)
(`pkg/sentry/seccheck/points/`, Apache-2.0) with import paths flattened.
`internal/wire` reimplements gVisor's remote-sink header (Apache-2.0). The
protobuf runtime under `third_party/` is a pinned upstream clone, kept local so
the PoC builds without a module proxy.
