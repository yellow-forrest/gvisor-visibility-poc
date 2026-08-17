// Package normalize converts decoded gVisor seccheck trace points into the
// event shape the Kubescape node-agent already understands.
//
// The node-agent's runtime detection engine keys everything off a small set of
// event types (pkg/utils/events.go: ExecveEventType="exec", NetworkEventType=
// "network", OpenEventType="open", ForkEventType="fork", ExitEventType="exit",
// PtraceEventType="ptrace", SyscallEventType="syscall", ...). Today those events
// come from an eBPF/IG tracer on the host kernel — which is blind to anything
// running inside a gVisor sandbox, because the sandboxed workload's syscalls are
// serviced by the Sentry in userspace and never reach the host kernel where the
// eBPF probes live.
//
// gVisor's seccheck "remote" sink is the Sentry-side equivalent of those probes:
// it emits the same class of signal (exec, connect, open, clone, exit, ...) from
// inside the sandbox. This package is the adapter: seccheck point -> normalized
// event carrying the node-agent EventType it maps onto, so the sandboxed signal
// can be fed into the existing detection pipeline instead of being lost.
//
// The mapping is deliberately honest: where a seccheck point has a clean
// node-agent counterpart we label it and set Mapped=true; where it does not
// (e.g. container/start, which node-agent has no event type for but which we
// need for sandbox<->container correlation) we set Mapped=false and keep it as
// metadata rather than pretending it is something it is not.
package normalize

import (
	"encoding/binary"
	"fmt"
	"net"

	"google.golang.org/protobuf/proto"

	pb "github.com/yellow-forrest/gvisor-visibility-poc/internal/pb"
)

// node-agent EventType string constants, mirrored from
// github.com/kubescape/node-agent/pkg/utils/events.go so this PoC does not need
// to vendor the whole node-agent module. Keep in sync with upstream.
const (
	NAExec    = "exec"
	NANetwork = "network"
	NAOpen    = "open"
	NAFork    = "fork"
	NAExit    = "exit"
	NAPtrace  = "ptrace"
	NASyscall = "syscall"
	// NAUnmapped marks a seccheck signal with no direct node-agent event type.
	NAUnmapped = ""
)

// Event is the normalized, transport-neutral representation the collector emits.
// It is intentionally close to what a node-agent tracer callback would build
// before handing off to the reporters/rule engine.
type Event struct {
	Source          string         `json:"source"`                    // always "gvisor/seccheck"
	SeccheckMessage string         `json:"seccheck_message"`          // e.g. "MESSAGE_SYSCALL_EXECVE"
	NodeAgentType   string         `json:"node_agent_event_type"`     // e.g. "exec"; "" if unmapped
	Mapped          bool           `json:"node_agent_mapped"`         // true if it maps to a real node-agent EventType
	ContainerID     string         `json:"container_id,omitempty"`    // sandbox container id (from ContextData)
	PID             int32          `json:"pid,omitempty"`             // thread id in root pid ns
	TGID            int32          `json:"tgid,omitempty"`            // thread group id
	ProcessName     string         `json:"process_name,omitempty"`    // comm
	CWD             string         `json:"cwd,omitempty"`             //
	TimeNS          int64          `json:"time_ns,omitempty"`         // sentry monotonic time of the point
	Details         map[string]any `json:"details,omitempty"`         // event-specific fields
}

// Mapping is the seccheck-message -> node-agent-event-type table. It is exported
// so tests and documentation can assert on it directly.
var Mapping = map[pb.MessageType]string{
	pb.MessageType_MESSAGE_SYSCALL_EXECVE:            NAExec,
	pb.MessageType_MESSAGE_SENTRY_EXEC:               NAExec,
	pb.MessageType_MESSAGE_SYSCALL_CONNECT:           NANetwork,
	pb.MessageType_MESSAGE_SYSCALL_SOCKET:            NANetwork,
	pb.MessageType_MESSAGE_SYSCALL_BIND:              NANetwork,
	pb.MessageType_MESSAGE_SYSCALL_ACCEPT:            NANetwork,
	pb.MessageType_MESSAGE_SYSCALL_LISTEN:            NANetwork,
	pb.MessageType_MESSAGE_SYSCALL_OPEN:              NAOpen,
	pb.MessageType_MESSAGE_SENTRY_CLONE:              NAFork,
	pb.MessageType_MESSAGE_SYSCALL_CLONE:             NAFork,
	pb.MessageType_MESSAGE_SYSCALL_FORK:              NAFork,
	pb.MessageType_MESSAGE_SENTRY_TASK_EXIT:          NAExit,
	pb.MessageType_MESSAGE_SENTRY_EXIT_NOTIFY_PARENT: NAExit,
	pb.MessageType_MESSAGE_SYSCALL_PTRACE:            NAPtrace,
	pb.MessageType_MESSAGE_SYSCALL_RAW:               NASyscall,
	// container/start has no node-agent EventType; kept as unmapped metadata,
	// but it is essential: it carries the sandbox container id that lets us
	// attribute every subsequent point to a Kubernetes workload.
	pb.MessageType_MESSAGE_CONTAINER_START: NAUnmapped,
}

// ctx pulls the common ContextData carried by (almost) every point.
func fillFromContext(e *Event, c *pb.ContextData) {
	if c == nil {
		return
	}
	e.ContainerID = c.GetContainerId()
	e.PID = c.GetThreadId()
	e.TGID = c.GetThreadGroupId()
	e.ProcessName = c.GetProcessName()
	e.CWD = c.GetCwd()
	e.TimeNS = c.GetTimeNs()
}

// Normalize decodes one seccheck payload of the given wire message type and
// returns the normalized event. The returned error is non-nil only for a
// genuine decode failure; an unknown-but-well-formed message type yields a
// best-effort event with Mapped=false so consumers can ignore it gracefully
// (per gVisor's forward-compat contract: consumers must tolerate unknown types).
func Normalize(msgType pb.MessageType, payload []byte) (*Event, error) {
	e := &Event{
		Source:          "gvisor/seccheck",
		SeccheckMessage: msgType.String(),
		NodeAgentType:   Mapping[msgType],
		Details:         map[string]any{},
	}
	e.Mapped = e.NodeAgentType != NAUnmapped

	switch msgType {
	case pb.MessageType_MESSAGE_CONTAINER_START:
		var m pb.Start
		if err := proto.Unmarshal(payload, &m); err != nil {
			return nil, err
		}
		fillFromContext(e, m.GetContextData())
		if e.ContainerID == "" {
			e.ContainerID = m.GetId()
		}
		e.Details["id"] = m.GetId()
		e.Details["cwd"] = m.GetCwd()
		e.Details["args"] = m.GetArgs()

	case pb.MessageType_MESSAGE_SYSCALL_EXECVE:
		var m pb.Execve
		if err := proto.Unmarshal(payload, &m); err != nil {
			return nil, err
		}
		fillFromContext(e, m.GetContextData())
		e.Details["pathname"] = m.GetPathname()
		e.Details["argv"] = m.GetArgv()
		e.Details["envv_count"] = len(m.GetEnvv())
		addExit(e, m.GetExit())

	case pb.MessageType_MESSAGE_SENTRY_EXEC:
		var m pb.ExecveInfo
		if err := proto.Unmarshal(payload, &m); err != nil {
			return nil, err
		}
		fillFromContext(e, m.GetContextData())
		e.Details["binary_path"] = m.GetBinaryPath()
		e.Details["argv"] = m.GetArgv()

	case pb.MessageType_MESSAGE_SYSCALL_CONNECT:
		var m pb.Connect
		if err := proto.Unmarshal(payload, &m); err != nil {
			return nil, err
		}
		fillFromContext(e, m.GetContextData())
		e.Details["fd"] = m.GetFd()
		if dst := decodeSockaddr(m.GetAddress()); dst != "" {
			e.Details["remote"] = dst // the egress destination — the whole point of Part B
		}
		addExit(e, m.GetExit())

	case pb.MessageType_MESSAGE_SYSCALL_SOCKET:
		var m pb.Socket
		if err := proto.Unmarshal(payload, &m); err != nil {
			return nil, err
		}
		fillFromContext(e, m.GetContextData())
		e.Details["domain"] = m.GetDomain()
		e.Details["type"] = m.GetType()
		e.Details["protocol"] = m.GetProtocol()

	case pb.MessageType_MESSAGE_SYSCALL_OPEN:
		var m pb.Open
		if err := proto.Unmarshal(payload, &m); err != nil {
			return nil, err
		}
		fillFromContext(e, m.GetContextData())
		e.Details["pathname"] = m.GetPathname()
		e.Details["fd_path"] = m.GetFdPath()
		e.Details["flags"] = m.GetFlags()
		addExit(e, m.GetExit())

	case pb.MessageType_MESSAGE_SENTRY_CLONE:
		var m pb.CloneInfo
		if err := proto.Unmarshal(payload, &m); err != nil {
			return nil, err
		}
		fillFromContext(e, m.GetContextData())
		e.Details["created_thread_id"] = m.GetCreatedThreadId()
		e.Details["created_thread_group_id"] = m.GetCreatedThreadGroupId()

	case pb.MessageType_MESSAGE_SENTRY_TASK_EXIT:
		var m pb.TaskExit
		if err := proto.Unmarshal(payload, &m); err != nil {
			return nil, err
		}
		fillFromContext(e, m.GetContextData())
		e.Details["exit_status"] = m.GetExitStatus()

	case pb.MessageType_MESSAGE_SENTRY_EXIT_NOTIFY_PARENT:
		var m pb.ExitNotifyParentInfo
		if err := proto.Unmarshal(payload, &m); err != nil {
			return nil, err
		}
		fillFromContext(e, m.GetContextData())
		e.Details["exit_status"] = m.GetExitStatus()

	case pb.MessageType_MESSAGE_SYSCALL_PTRACE:
		var m pb.Ptrace
		if err := proto.Unmarshal(payload, &m); err != nil {
			return nil, err
		}
		fillFromContext(e, m.GetContextData())
		e.Details["request"] = m.GetRequest()
		e.Details["pid"] = m.GetPid()
		addExit(e, m.GetExit())

	case pb.MessageType_MESSAGE_SYSCALL_RAW:
		var m pb.Syscall
		if err := proto.Unmarshal(payload, &m); err != nil {
			return nil, err
		}
		fillFromContext(e, m.GetContextData())
		e.Details["sysno"] = m.GetSysno()
		addExit(e, m.GetExit())

	default:
		// Well-formed but not one we specialize. Per gVisor's compat contract we
		// tolerate it: surface the raw type, leave it unmapped.
		e.Mapped = false
	}

	return e, nil
}

func addExit(e *Event, x *pb.Exit) {
	if x == nil {
		return
	}
	e.Details["exit_result"] = x.GetResult()
	e.Details["exit_errno"] = x.GetErrorno()
}

// decodeSockaddr turns a raw sockaddr (as carried in Connect.address) into a
// human-readable ip:port for AF_INET / AF_INET6. Returns "" if it cannot.
// sa_family is host-endian; port is network byte order (big-endian).
func decodeSockaddr(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	family := binary.LittleEndian.Uint16(b[0:2])
	switch family {
	case 2: // AF_INET
		if len(b) < 8 {
			return ""
		}
		port := binary.BigEndian.Uint16(b[2:4])
		ip := net.IP(b[4:8])
		return fmt.Sprintf("%s:%d", ip.String(), port)
	case 10: // AF_INET6
		if len(b) < 24 {
			return ""
		}
		port := binary.BigEndian.Uint16(b[2:4])
		ip := net.IP(b[8:24])
		return fmt.Sprintf("[%s]:%d", ip.String(), port)
	default:
		return ""
	}
}
