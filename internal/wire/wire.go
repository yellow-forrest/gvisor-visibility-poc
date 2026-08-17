// Package wire implements the gVisor seccheck "remote" sink wire framing.
//
// This is a faithful, dependency-free reimplementation of the 8-byte message
// header that gVisor's Sentry prepends to every trace point it streams over the
// SOCK_SEQPACKET Unix-domain socket. The canonical definition lives in gVisor at
// pkg/sentry/seccheck/sinks/remote/wire/wire.go (Apache-2.0). We reimplement it
// (rather than import the whole gVisor tree) so the collector stays small and
// buildable outside a Bazel workspace.
//
// Header layout (matches gVisor exactly):
//
//	0 --------- 16 ---------- 32 ----------- 64 -----------+
//	| HeaderSize | MessageType | DroppedCount | Payload... |
//	+---- 16 ----+---- 16 -----+----- 32 -----+------------+
//
// gVisor marshals the header with MarshalUnsafe, i.e. host byte order. On the
// amd64/arm64 hosts gVisor supports that is little-endian, so we encode/decode
// little-endian explicitly. The collector and the fakesentry replayer share this
// package, so the end-to-end demo is self-consistent regardless of host, and it
// is byte-compatible with a real Sentry on any little-endian host.
package wire

import (
	"encoding/binary"
	"fmt"
)

// CurrentVersion is the wire/protocol version negotiated in the handshake.
// Mirrors gVisor's wire.CurrentVersion.
const CurrentVersion = 1

// HeaderStructSize is the size of Header in bytes.
const HeaderStructSize = 8

// Header describes a single message on the wire.
type Header struct {
	// HeaderSize is the size of the header in bytes. Kept as a field (rather than
	// a constant) so the header can grow in the future without breaking older
	// consumers, exactly as gVisor documents.
	HeaderSize uint16
	// MessageType is one of the pb.MessageType values. It selects how the payload
	// that follows the header is deserialized.
	MessageType uint16
	// DroppedCount is the cumulative number of points the sender had to drop
	// (e.g. because the socket buffer was full). It wraps at max(uint32).
	DroppedCount uint32
}

// Marshal encodes the header into an 8-byte little-endian buffer.
func (h Header) Marshal() []byte {
	b := make([]byte, HeaderStructSize)
	binary.LittleEndian.PutUint16(b[0:2], h.HeaderSize)
	binary.LittleEndian.PutUint16(b[2:4], h.MessageType)
	binary.LittleEndian.PutUint32(b[4:8], h.DroppedCount)
	return b
}

// Unmarshal decodes an 8-byte header from the front of b.
func (h *Header) Unmarshal(b []byte) error {
	if len(b) < HeaderStructSize {
		return fmt.Errorf("wire: header too small: got %d bytes, need %d", len(b), HeaderStructSize)
	}
	h.HeaderSize = binary.LittleEndian.Uint16(b[0:2])
	h.MessageType = binary.LittleEndian.Uint16(b[2:4])
	h.DroppedCount = binary.LittleEndian.Uint32(b[4:8])
	return nil
}
