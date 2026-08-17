# Design: gVisor runtime visibility for node-agent — signal sources, session contention, and a seccheck PoC

Status: draft for discussion · Relates to: kubescape/kubescape#2557 (Part B),
builds on designs-and-proposals#10 (posture scanning of agent-runtime CRDs) ·
Companion PoC: `cmd/collector` + `make e2e` in this repository.

## 1. Problem

The node-agent derives runtime signals — process exec, network connections, file
access, capability use — from eBPF programs attached to the **host** kernel via
Inspektor Gadget. That model assumes the workload's syscalls reach the host
kernel. Under **gVisor**, they do not: the sandboxed process traps into the
**Sentry**, a userspace kernel, which services the syscall and only occasionally,
and selectively, touches the host. From the host kernel's vantage point a gVisor
actor makes almost no syscalls at all. The eBPF probes therefore see a black box.

This matters specifically for the agent-runtime world that #2557 and
designs-and-proposals#10 target. GKE Agent Sandbox runs model-generated,
untrusted code precisely *because* gVisor contains it. The static posture work
(the "Agent Runtime Hardening" framework) verifies that an `ActorTemplate` or
`SandboxTemplate` is configured to use gVisor and to deny egress. But once the
actor is running, the thing we most want to watch — what that untrusted code
actually does — is the thing the current sensor cannot see. Static posture says
"the door is locked"; runtime visibility says "someone is climbing through the
window anyway." Part B is about getting eyes inside the sandbox.

## 2. Candidate signal sources

There are three plausible ways to recover visibility into a gVisor sandbox. They
are not mutually exclusive; the recommendation is to lead with one and keep a
second as a fallback.

### 2.1 Sentry `seccheck` remote sink (recommended primary)

gVisor ships a first-class trace subsystem, `seccheck`, with ~hundreds of
instrumentation points across syscalls and Sentry lifecycle events. Its `remote`
sink serializes each point as a protobuf and streams it over a `SOCK_SEQPACKET`
Unix-domain socket to an external monitoring process. This is purpose-built for
exactly our use case: a security monitor observing sandbox behavior.

Key properties (verified against gVisor source and exercised by the PoC):

- **Rich, structured, typed.** Points carry `ContextData` (container id, thread
  id/tgid, process name, cwd, credentials, timestamps) plus per-syscall fields —
  e.g. `connect()` carries the raw destination sockaddr, `execve()` carries argv
  and the resolved binary path and even a SHA-256 of the binary.
- **Dynamically attachable.** `runsc trace create --config <file> <sandbox-id>`
  installs a session on an **already-running** sandbox. Visibility does not have
  to be decided at pod-launch time; node-agent can attach when it starts, or when
  it first observes a gVisor sandbox. This is the single most important property
  for a DaemonSet sensor and it is demonstrated in `scripts/run-with-runsc.sh`.
- **Cheap to consume.** The wire format is an 8-byte header + a protobuf; the
  monitoring side is a few hundred lines of Go (see `cmd/collector`).

Costs: it is a **Sentry-side** signal, so it trusts the Sentry (acceptable — the
Sentry is the isolation boundary, not the sandboxed workload, and gVisor's own
threat model treats the *workload* as the adversary, which the monitor must still
guard against by bounding all field sizes). And it carries the `Default`-session
constraint discussed in §4.

### 2.2 `runsc --strace` / debug-log export (fallback / dev-only)

`runsc` can emit a strace-style log of sandbox syscalls to its debug log. It
requires no extra socket and is trivially available. But it is a **text log**
designed for debugging, not a stable machine interface: it is line-oriented,
lossy under load, expensive (string formatting per syscall), and its format is
not a compatibility-guaranteed API. Viable as a stop-gap or in dev clusters; a
poor foundation for a production sensor.

### 2.3 Host-boundary signals (complementary, always-available)

Some sandbox behavior *does* cross the host boundary and is therefore visible to
the existing host-kernel eBPF without any gVisor cooperation:

- **Egress**, when the sandbox's traffic egresses the node, is observable at the
  CNI / conntrack layer and via NetworkPolicy enforcement — this is the same
  signal the C-0301 agent egress control governs statically.
- **Sentry process lifecycle**: the `runsc` Sentry processes themselves are host
  processes; their creation/exit, resource usage, and host-syscall surface are
  visible to node-agent today.

These never give per-actor syscall-level detail, but they are **always available**
and require no session, so they are the natural fallback when §2.1 is unavailable
(see §4). They also cross-check the Sentry-trusted signal against an
independently-sourced one.

### 2.4 Comparison

| Dimension | seccheck remote sink (2.1) | strace export (2.2) | host-boundary (2.3) |
|---|---|---|---|
| Granularity | per-syscall, structured | per-syscall, text | coarse (egress, process) |
| Stable interface | yes (versioned protobuf + handshake) | no (debug format) | yes (host kernel) |
| Dynamic attach to running sandbox | yes (`trace create`) | partial (needs debug flags) | n/a (always on) |
| Cost | low (protobuf) | high (string fmt) | low |
| Trusts the Sentry | yes | yes | no |
| Session contention | yes — single `Default` (§4) | no | no |
| Maps to node-agent events | directly (this PoC) | with parsing | partially |
| Production-suitable | **yes (primary)** | dev only | **yes (fallback/augment)** |

**Recommendation:** lead with the seccheck remote sink; keep host-boundary
signals as the always-available fallback and cross-check; treat strace export as
dev-only.

## 3. PoC (what is implemented and proven)

The companion code implements the §2.1 path end to end:

- `cmd/collector` — the monitoring process. Binds the `SOCK_SEQPACKET` UDS with
  only the Go standard library, performs the seccheck handshake, reads the point
  stream, decodes each payload against gVisor's real protobuf schemas, normalizes
  it, and emits JSON.
- `internal/normalize` — the seccheck → node-agent mapping (§5), with unit tests.
- `internal/pb` — bindings generated from the **actual gVisor `.proto`** files
  (vendored under `proto/` for provenance), so the decode is byte-faithful.
- `cmd/fakesentry` + `make e2e` — a **cluster-free** end-to-end test. `fakesentry`
  is a faithful stand-in for the Sentry side: it connects, performs the real
  handshake, and writes header+protobuf datagrams for a scripted agent-sandbox
  session (start → clone → exec `sh -c curl…|sh` → socket → connect to an
  external IP → open `/etc/shadow` → `ptrace(PTRACE_ATTACH)` → exit). The
  collector decodes all 8 points and maps 7 of them onto node-agent event types.
- `scripts/run-with-runsc.sh` — the **real-gVisor** path: launch a
  `--runtime=runsc` container and `runsc trace create` a session against the
  running sandbox. Same collector code; only the sender changes.

The E2E asserts, among other things, that the egress destination `203.0.113.7:80`
is recovered from the raw `connect()` sockaddr and that every event is attributed
to the sandbox container id — i.e. signals that are completely invisible to
host-kernel eBPF are recovered and correlated.

## 4. The `Default`-session constraint and the fallback design

gVisor today supports **exactly one** trace session, and it must be named
`Default` (`pkg/sentry/seccheck/config.go`: `only a single "Default" session is
supported`). Consequences and mitigations:

1. **Contention.** If the platform (or another security tool) already installed
   the `Default` session, node-agent's `trace create` fails. node-agent must
   detect this rather than assume it owns the sandbox.
2. **Detection.** On attach failure with "session already exists", node-agent
   should (a) log a clear, actionable event, (b) fall back to §2.3 host-boundary
   signals for that sandbox so coverage degrades gracefully rather than going
   dark, and (c) surface a posture finding that runtime visibility is unavailable
   for that node — itself a security-relevant condition.
3. **Sharing (medium term).** Where node-agent *can* own the session, run a
   single per-node **sink broker**: node-agent holds the one `Default` session and
   re-publishes the normalized stream to multiple internal consumers (rule engine,
   exporters), so "one session" is not "one consumer." The collector in this PoC
   is already structured as that broker's front half.
4. **Upstream (long term).** Multi-session support is contemplated in gVisor's own
   comments (`DefaultSessionName … When multiple sessions are supported, this can
   be removed`). An upstream contribution to name/multiplex sessions would remove
   the constraint at the root; worth a gVisor issue referencing this use case.

This constraint is the crux of productionizing Part B, which is why the PoC
surfaces it explicitly (README §"The `Default`-session constraint") rather than
hiding it.

## 5. node-agent integration path

The normalized `Event` in `internal/normalize` deliberately mirrors what a
node-agent tracer callback assembles before handing off to the reporters and rule
engine. Integration is therefore:

1. Wrap the collector as a node-agent **`containerwatcher` tracer** implementation
   (`pkg/containerwatcher`), started when a gVisor runtime class is detected on
   the node.
2. Translate the normalized `Event` into the concrete node-agent event structs
   (`ExecEvent`, `NetworkEvent`, `OpenEvent`, …) and feed the existing
   `eventreporters` / rule-manager path — so existing runtime rules fire on
   sandboxed actors with no rule changes.
3. Correlate the seccheck `container_id` to the Kubernetes pod/actor via the same
   container→workload mapping node-agent already maintains, seeded by the
   `MESSAGE_CONTAINER_START` metadata point.
4. Derive higher-level signals where cheap: DNS from `connect()`/socket payloads,
   sensitive-file access from `open()` paths — reusing existing node-agent rules.

## 6. Open questions

- **Session ownership policy.** Should node-agent always try to own `Default`, or
  only when no other owner is detected? Interaction with GKE-managed tooling that
  may want the session is unknown and needs a real GKE Agent Sandbox cluster to
  settle (a term-time task; the PoC needs none of it).
- **Field selection vs. cost.** Which points/fields to enable by default. Enabling
  `execve` binary hashing is powerful but expensive; likely opt-in.
- **Standalone vs. under CADR.** Mirrors the open question in
  designs-and-proposals#10: ship this as its own node-agent capability or fold the
  runtime-visibility story under the CADR design. Recommendation: land the sensor
  standalone (it is independently useful) and reference it from CADR.

## 7. Scope

In scope: the seccheck signal source, the normalization to node-agent events, the
session-contention handling, and the node-agent tracer seam. Out of scope here:
the static posture controls and the framework (designs-and-proposals#10 and the
regolibrary work), and full multi-sandbox broker implementation (sketched, not
built).
