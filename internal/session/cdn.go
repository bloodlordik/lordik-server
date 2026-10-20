package session

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/telegramdesktop/tproxy-server/internal/frame"
)

var (
	ErrInvalidGLTF = errors.New("invalid glTF header")
)

const (
	GLTFHeaderSize = 12
	GLTFMagic      = "glTF" // 0x67, 0x6c, 0x54, 0x46
	GLTFVersion    = 2
)

// FrameStreamParser accumulates bytes from stream-oriented chunks and extracts
// full frames. It enforces a strict upper bound on pending incomplete frame bytes.
type FrameStreamParser struct {
	pending         []byte
	maxPayload      int
	maxPendingBytes int
}

// NewFrameStreamParser creates a FrameStreamParser with the specified maxPayload limit.
func NewFrameStreamParser(maxPayload int) *FrameStreamParser {
	if maxPayload <= 0 || maxPayload > frame.MaxPayload {
		maxPayload = frame.MaxPayload
	}
	return &FrameStreamParser{
		pending:         nil,
		maxPayload:      maxPayload,
		maxPendingBytes: maxPayload + frame.HeaderSize,
	}
}

// Feed ingests a chunk of bytes, parses and validates complete frames, and retains
// unconsumed bytes for the next Feed invocation.
func (p *FrameStreamParser) Feed(chunk []byte) ([]frame.Frame, error) {
	if len(chunk) == 0 {
		return nil, nil
	}
	if len(p.pending)+len(chunk) > p.maxPendingBytes {
		return nil, ErrLimit
	}
	p.pending = append(p.pending, chunk...)

	var ready []frame.Frame
	for len(p.pending) >= frame.HeaderSize {
		if len(ready) == frame.MaxBatchFrames {
			return nil, ErrProtocol
		}
		length := uint64(binary.BigEndian.Uint32(p.pending[4:8]))
		if length > uint64(p.maxPayload) {
			return nil, ErrProtocol
		}
		full := int(frame.HeaderSize + length)
		if len(p.pending) < full {
			break
		}

		streamID := uint32(p.pending[1])<<16 | uint32(p.pending[2])<<8 | uint32(p.pending[3])
		f := frame.Frame{
			Type:     frame.Type(p.pending[0]),
			StreamID: streamID,
			Payload:  make([]byte, length),
		}
		copy(f.Payload, p.pending[frame.HeaderSize:full])

		if err := frame.ValidateClientShape(f); err != nil {
			return nil, ErrProtocol
		}

		ready = append(ready, f)
		p.pending = p.pending[full:]
	}

	if len(p.pending) == 0 {
		p.pending = nil
	} else if cap(p.pending) > p.maxPendingBytes/2 && len(p.pending) < 4096 {
		compact := make([]byte, len(p.pending))
		copy(compact, p.pending)
		p.pending = compact
	}

	return ready, nil
}

// ReassemblyBuffer handles out-of-order uplink chunks, sliding window enforcement,
// idempotency for retransmitted sequences, and sequential frame feeding into FrameStreamParser.
type ReassemblyBuffer struct {
	expectedUpSeq uint64
	outOfOrder    map[uint64][]byte
	windowSize    uint64
	parser        *FrameStreamParser
}

// NewReassemblyBuffer constructs a ReassemblyBuffer starting at seq 1.
func NewReassemblyBuffer(windowSize uint64, maxPayload int) *ReassemblyBuffer {
	if windowSize == 0 {
		windowSize = 16
	}
	return &ReassemblyBuffer{
		expectedUpSeq: 1,
		outOfOrder:    make(map[uint64][]byte),
		windowSize:    windowSize,
		parser:        NewFrameStreamParser(maxPayload),
	}
}

// Push ingests a numbered chunk.
// - If seq < expectedUpSeq: duplicate (retry), returns readyFrames=nil, duplicate=true, err=nil.
// - If seq > expectedUpSeq + windowSize: window overflow, returns ErrProtocol.
// - If seq > expectedUpSeq: out-of-order within window, buffered, returns duplicate=false, err=nil.
// - If seq == expectedUpSeq: fed to parser, drains consecutive buffered chunks, returns readyFrames.
func (b *ReassemblyBuffer) Push(seq uint64, chunk []byte) ([]frame.Frame, bool, error) {
	if seq < b.expectedUpSeq {
		return nil, true, nil
	}
	if seq > b.expectedUpSeq+b.windowSize {
		return nil, false, ErrProtocol
	}
	if seq > b.expectedUpSeq {
		if uint64(len(b.outOfOrder)) >= b.windowSize {
			return nil, false, ErrLimit
		}
		if _, exists := b.outOfOrder[seq]; !exists {
			chunkCopy := make([]byte, len(chunk))
			copy(chunkCopy, chunk)
			b.outOfOrder[seq] = chunkCopy
		}
		return nil, false, nil
	}

	// seq == b.expectedUpSeq
	ready, err := b.parser.Feed(chunk)
	if err != nil {
		return nil, false, err
	}
	b.expectedUpSeq++

	for {
		nextChunk, ok := b.outOfOrder[b.expectedUpSeq]
		if !ok {
			break
		}
		delete(b.outOfOrder, b.expectedUpSeq)
		more, err := b.parser.Feed(nextChunk)
		if err != nil {
			return ready, false, err
		}
		ready = append(ready, more...)
		b.expectedUpSeq++
	}

	return ready, false, nil
}

// ExpectedUpSeq returns the current in-order sequence expected next.
func (b *ReassemblyBuffer) ExpectedUpSeq() uint64 {
	return b.expectedUpSeq
}

// WrapGLTF wraps batch frames into a glTF 2.0 binary payload with 12-byte header:
// - bytes 0..3: magic "glTF"
// - bytes 4..7: version 2 in Little-Endian
// - bytes 8..11: cursor in Big-Endian
func WrapGLTF(batch []byte, cursor uint64) []byte {
	out := make([]byte, GLTFHeaderSize+len(batch))
	copy(out[0:4], GLTFMagic)
	binary.LittleEndian.PutUint32(out[4:8], GLTFVersion)
	binary.BigEndian.PutUint32(out[8:12], uint32(cursor))
	copy(out[GLTFHeaderSize:], batch)
	return out
}

// UnwrapGLTF extracts downCursor and frame payload from a glTF 2.0 binary body.
func UnwrapGLTF(data []byte) (uint32, []byte, error) {
	if len(data) < GLTFHeaderSize {
		return 0, nil, ErrInvalidGLTF
	}
	if string(data[0:4]) != GLTFMagic {
		return 0, nil, ErrInvalidGLTF
	}
	ver := binary.LittleEndian.Uint32(data[4:8])
	if ver != GLTFVersion {
		return 0, nil, fmt.Errorf("%w: unsupported version %d", ErrInvalidGLTF, ver)
	}
	cursor := binary.BigEndian.Uint32(data[8:12])
	return cursor, data[GLTFHeaderSize:], nil
}

// DecodeCDNPayload decodes base64url payload split across URL path and sharded headers.
func DecodeCDNPayload(urlPart string, headers []string) ([]byte, error) {
	var sb strings.Builder
	sb.WriteString(urlPart)
	for _, h := range headers {
		sb.WriteString(strings.TrimSpace(h))
	}
	raw := sb.String()
	if raw == "" {
		return nil, nil
	}
	// Support unpadded and padded Base64URL
	if pad := len(raw) % 4; pad != 0 {
		raw += strings.Repeat("=", 4-pad)
	}
	return base64.URLEncoding.DecodeString(raw)
}

// EncodeCDNPayload encodes binary data into base64url and shards it into URL part
// (up to maxURLPart characters) and subsequent header chunks (up to maxHeaderPart chars each).
func EncodeCDNPayload(data []byte, maxURLPart, maxHeaderPart int) (string, []string) {
	encoded := base64.RawURLEncoding.EncodeToString(data)
	if maxURLPart <= 0 || len(encoded) <= maxURLPart {
		return encoded, nil
	}
	urlPart := encoded[:maxURLPart]
	remaining := encoded[maxURLPart:]

	if maxHeaderPart <= 0 {
		maxHeaderPart = 3584
	}

	var headers []string
	for len(remaining) > 0 {
		take := len(remaining)
		if take > maxHeaderPart {
			take = maxHeaderPart
		}
		headers = append(headers, remaining[:take])
		remaining = remaining[take:]
	}
	return urlPart, headers
}
