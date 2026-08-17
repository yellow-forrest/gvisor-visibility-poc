// Command collector is a standalone monitoring process for gVisor's seccheck
// "remote" sink. It plays the role node-agent would play in production: it
// creates the Unix-domain socket, accepts a connection from a gVisor Sentry (or
// from the bundled fakesentry replayer for cluster-free testing), decodes the
// protobuf trace-point stream, normalizes each point into the node-agent event
// shape, and prints it as JSON on stdout.
//
// It uses only the Go standard library for the socket work (AF_UNIX +
// SOCK_SEQPACKET via package syscall), so it builds and runs anywhere without a
// gVisor/Bazel workspace. The only third-party dependency is the protobuf
// runtime used to decode gVisor's real point schemas.
//
// Wire protocol (see internal/wire and gVisor's remote-sink README):
//   - transport: AF_UNIX, SOCK_SEQPACKET (message boundaries preserved)
//   - on connect: peer sends a Handshake{version}; we reply with our version
//   - then a stream of [8-byte header][protobuf payload] datagrams
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/protobuf/proto"

	pb "github.com/yellow-forrest/gvisor-visibility-poc/internal/pb"
	"github.com/yellow-forrest/gvisor-visibility-poc/internal/normalize"
	"github.com/yellow-forrest/gvisor-visibility-poc/internal/wire"
)

const maxMessageSize = 1 << 20 // 1 MiB, matches gVisor's server read buffer

func main() {
	endpoint := flag.String("endpoint", "/tmp/gvisor_events.sock", "UDS path to listen on (the seccheck remote-sink endpoint)")
	oneshot := flag.Bool("oneshot", false, "exit after the first client disconnects (used by the E2E test)")
	pretty := flag.Bool("pretty", false, "pretty-print each normalized JSON event")
	flag.Parse()

	// Fresh socket file.
	_ = os.Remove(*endpoint)

	lfd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		fatal("socket(AF_UNIX, SOCK_SEQPACKET): %v", err)
	}
	if err := syscall.Bind(lfd, &syscall.SockaddrUnix{Name: *endpoint}); err != nil {
		fatal("bind(%q): %v", *endpoint, err)
	}
	if err := syscall.Listen(lfd, 8); err != nil {
		fatal("listen: %v", err)
	}
	defer func() {
		_ = syscall.Close(lfd)
		_ = os.Remove(*endpoint)
	}()

	fmt.Fprintf(os.Stderr, "collector: listening on %s (SOCK_SEQPACKET). Waiting for a Sentry to connect...\n", *endpoint)

	// Clean shutdown on Ctrl-C so the socket file is removed.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigc
		_ = syscall.Close(lfd)
		_ = os.Remove(*endpoint)
		os.Exit(0)
	}()

	enc := json.NewEncoder(os.Stdout)
	if *pretty {
		enc.SetIndent("", "  ")
	}

	for {
		cfd, _, err := syscall.Accept(lfd)
		if err != nil {
			fatal("accept: %v", err)
		}
		stats := handleClient(cfd, enc)
		fmt.Fprintf(os.Stderr, "collector: client disconnected. points=%d mapped=%d unmapped=%d dropped(reported by sender)=%d\n",
			stats.total, stats.mapped, stats.unmapped, stats.dropped)
		if *oneshot {
			return
		}
	}
}

type stats struct {
	total, mapped, unmapped int
	dropped                 uint32
}

func handleClient(cfd int, enc *json.Encoder) stats {
	defer syscall.Close(cfd)
	buf := make([]byte, maxMessageSize)

	// ---- Handshake ----
	n, err := syscall.Read(cfd, buf)
	if err != nil || n == 0 {
		fmt.Fprintf(os.Stderr, "collector: handshake read failed: %v\n", err)
		return stats{}
	}
	var hsIn pb.Handshake
	if err := proto.Unmarshal(buf[:n], &hsIn); err != nil {
		fmt.Fprintf(os.Stderr, "collector: bad handshake: %v\n", err)
		return stats{}
	}
	hsOut, _ := proto.Marshal(&pb.Handshake{Version: wire.CurrentVersion})
	if _, err := syscall.Write(cfd, hsOut); err != nil {
		fmt.Fprintf(os.Stderr, "collector: handshake write failed: %v\n", err)
		return stats{}
	}
	fmt.Fprintf(os.Stderr, "collector: handshake ok (peer version=%d)\n", hsIn.GetVersion())

	// ---- Point stream ----
	var s stats
	for {
		n, err := syscall.Read(cfd, buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "collector: read: %v\n", err)
			return s
		}
		if n == 0 {
			return s // peer closed
		}
		if n < wire.HeaderStructSize {
			fmt.Fprintf(os.Stderr, "collector: short message (%d bytes), skipping\n", n)
			continue
		}
		var hdr wire.Header
		if err := hdr.Unmarshal(buf[:wire.HeaderStructSize]); err != nil {
			fmt.Fprintf(os.Stderr, "collector: %v\n", err)
			continue
		}
		if int(hdr.HeaderSize) > n {
			fmt.Fprintf(os.Stderr, "collector: truncated message: header says %d, read %d\n", hdr.HeaderSize, n)
			continue
		}
		s.dropped = hdr.DroppedCount
		payload := buf[hdr.HeaderSize:n]

		ev, err := normalize.Normalize(pb.MessageType(hdr.MessageType), payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "collector: decode msgType=%d: %v\n", hdr.MessageType, err)
			continue
		}
		s.total++
		if ev.Mapped {
			s.mapped++
		} else {
			s.unmapped++
		}
		if err := enc.Encode(ev); err != nil {
			fmt.Fprintf(os.Stderr, "collector: encode: %v\n", err)
		}
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "collector: "+format+"\n", args...)
	os.Exit(1)
}
