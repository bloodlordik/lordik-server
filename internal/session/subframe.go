package session

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/telegramdesktop/tproxy-server/internal/frame"
	"github.com/telegramdesktop/tproxy-server/internal/logger"
)

const (
	// SubFrameHeaderSize is the 9-byte header of a QUIC-style subframe:
	// [Type: 1B][StreamID: 3B BE][StreamSeq: 2B BE][SubFlags: 1B][SubLen: 2B BE]
	SubFrameHeaderSize = 9

	// SubFlagFirst indicates this subframe starts a new original frame.
	SubFlagFirst uint8 = 0x01

	// SubFlagFin indicates this subframe is the final fragment of the frame.
	SubFlagFin uint8 = 0x02

	// maxStreamWindowSpan limits the sliding window for out-of-order subframes per stream.
	// 256 subframes (~1.5 MiB) prevents false ErrProtocol when 8 parallel CDN GET requests
	// experience edge jitter during large media uploads.
	maxStreamWindowSpan uint16 = 256

	// maxStreamBufferSize limits total buffered out-of-order and partial frame bytes per stream (2 MiB).
	maxStreamBufferSize = 2 * 1024 * 1024

	// maxSubFramePayload is the maximum payload per subframe (6000 - 9 = 5991).
	maxSubFramePayload = 5991
)

// SubFrame represents a single per-stream packet on the uplink.
type SubFrame struct {
	Type     frame.Type
	StreamID uint32
	Seq      uint16
	Flags    uint8
	Payload  []byte
}

// ParseSubFrames parses one or more subframes from data.
// Returns an error if any header or length is malformed.
func ParseSubFrames(data []byte) ([]SubFrame, error) {
	if len(data) == 0 {
		return nil, errors.New("empty subframe data")
	}
	result := make([]SubFrame, 0, 4)
	for len(data) > 0 {
		if len(data) < SubFrameHeaderSize {
			logger.Warn(fmt.Sprintf("[QUIC SUBFRAME PROTOCOL] subframe truncated header: len=%d < %d", len(data), SubFrameHeaderSize), "len", len(data))
			return nil, ErrProtocol
		}
		t := frame.Type(data[0])
		if t != frame.Open && t != frame.Data && t != frame.Close && t != frame.Window && t != frame.Pong {
			logger.Warn(fmt.Sprintf("[QUIC SUBFRAME PROTOCOL] invalid subframe type: 0x%02x", data[0]), "type", data[0])
			return nil, ErrProtocol
		}
		streamID := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
		seq := binary.BigEndian.Uint16(data[4:6])
		flags := data[6]
		subLen := int(binary.BigEndian.Uint16(data[7:9]))

		if subLen > maxSubFramePayload || len(data) < SubFrameHeaderSize+subLen {
			logger.Warn(fmt.Sprintf("[QUIC SUBFRAME PROTOCOL] invalid subframe payload len: streamID=%d seq=%d subLen=%d max=%d available=%d", streamID, seq, subLen, maxSubFramePayload, len(data)-SubFrameHeaderSize), "stream_id", streamID, "seq", seq, "sub_len", subLen, "max", maxSubFramePayload)
			return nil, ErrProtocol
		}
		// Copy slice to decouple from temporary HTTP request buffer when stored out-of-order
		payload := make([]byte, subLen)
		copy(payload, data[SubFrameHeaderSize:SubFrameHeaderSize+subLen])
		result = append(result, SubFrame{
			Type:     t,
			StreamID: streamID,
			Seq:      seq,
			Flags:    flags,
			Payload:  payload,
		})
		data = data[SubFrameHeaderSize+subLen:]
	}
	return result, nil
}

// StreamReassembly reassembles per-stream subframes into complete frames.
type StreamReassembly struct {
	expectedSeq     uint16
	outOfOrder      map[uint16]SubFrame
	accumulated     []byte
	accumulatedType frame.Type
	bufferedBytes   int
}

// NewStreamReassembly creates an initialized StreamReassembly instance.
func NewStreamReassembly() *StreamReassembly {
	return &StreamReassembly{
		expectedSeq: 1,
		outOfOrder:  make(map[uint16]SubFrame),
	}
}

func (r *StreamReassembly) appendSub(sub SubFrame) ([]frame.Frame, error) {
	switch sub.Flags & (SubFlagFirst | SubFlagFin) {
	case SubFlagFirst | SubFlagFin:
		if len(r.accumulated) > 0 {
			logger.Warn(fmt.Sprintf("[QUIC SUBFRAME PROTOCOL] FIRST fragment arrived with non-empty accumulated buffer: streamID=%d seq=%d acc_len=%d", sub.StreamID, sub.Seq, len(r.accumulated)), "stream_id", sub.StreamID, "seq", sub.Seq, "accumulated_len", len(r.accumulated))
			return nil, ErrProtocol
		}
		f := frame.Frame{
			Type:     sub.Type,
			StreamID: sub.StreamID,
			Payload:  sub.Payload,
		}
		if err := frame.ValidateClientShape(f); err != nil {
			logger.Warn(fmt.Sprintf("[QUIC SUBFRAME PROTOCOL] ValidateClientShape failed: streamID=%d seq=%d err=%v", sub.StreamID, sub.Seq, err), "stream_id", sub.StreamID, "seq", sub.Seq, "err", err)
			return nil, ErrProtocol
		}
		return []frame.Frame{f}, nil

	case SubFlagFirst:
		if len(r.accumulated) > 0 {
			logger.Warn(fmt.Sprintf("[QUIC SUBFRAME PROTOCOL] FIRST fragment arrived with non-empty accumulated buffer: streamID=%d seq=%d acc_len=%d", sub.StreamID, sub.Seq, len(r.accumulated)), "stream_id", sub.StreamID, "seq", sub.Seq, "accumulated_len", len(r.accumulated))
			return nil, ErrProtocol
		}
		r.accumulated = append([]byte(nil), sub.Payload...)
		r.accumulatedType = sub.Type
		r.bufferedBytes += len(sub.Payload)
		if r.bufferedBytes > maxStreamBufferSize {
			logger.Warn(fmt.Sprintf("[QUIC SUBFRAME LIMIT] stream buffer exceeded on FIRST: streamID=%d seq=%d buffered=%d > max=%d", sub.StreamID, sub.Seq, r.bufferedBytes, maxStreamBufferSize), "stream_id", sub.StreamID, "seq", sub.Seq, "buffered", r.bufferedBytes, "max", maxStreamBufferSize)
			return nil, ErrLimit
		}
		return nil, nil

	case SubFlagFin:
		if len(r.accumulated) == 0 {
			logger.Warn(fmt.Sprintf("[QUIC SUBFRAME PROTOCOL] FIN fragment without preceding FIRST: streamID=%d seq=%d", sub.StreamID, sub.Seq), "stream_id", sub.StreamID, "seq", sub.Seq)
			return nil, ErrProtocol
		}
		r.accumulated = append(r.accumulated, sub.Payload...)
		if len(r.accumulated) > frame.MaxPayload {
			logger.Warn(fmt.Sprintf("[QUIC SUBFRAME LIMIT] accumulated frame exceeded MaxPayload on FIN: streamID=%d seq=%d len=%d > max=%d", sub.StreamID, sub.Seq, len(r.accumulated), frame.MaxPayload), "stream_id", sub.StreamID, "seq", sub.Seq, "len", len(r.accumulated), "max", frame.MaxPayload)
			return nil, ErrLimit
		}
		f := frame.Frame{
			Type:     r.accumulatedType,
			StreamID: sub.StreamID,
			Payload:  r.accumulated,
		}
		if err := frame.ValidateClientShape(f); err != nil {
			logger.Warn(fmt.Sprintf("[QUIC SUBFRAME PROTOCOL] ValidateClientShape failed: streamID=%d seq=%d err=%v", sub.StreamID, sub.Seq, err), "stream_id", sub.StreamID, "seq", sub.Seq, "err", err)
			return nil, ErrProtocol
		}
		r.bufferedBytes -= len(r.accumulated) - len(sub.Payload)
		if r.bufferedBytes < 0 {
			r.bufferedBytes = 0
		}
		r.accumulated = nil
		return []frame.Frame{f}, nil

	default: // middle fragment
		if len(r.accumulated) == 0 {
			logger.Warn(fmt.Sprintf("[QUIC SUBFRAME PROTOCOL] middle fragment without preceding FIRST: streamID=%d seq=%d", sub.StreamID, sub.Seq), "stream_id", sub.StreamID, "seq", sub.Seq)
			return nil, ErrProtocol
		}
		r.accumulated = append(r.accumulated, sub.Payload...)
		r.bufferedBytes += len(sub.Payload)
		if r.bufferedBytes > maxStreamBufferSize || len(r.accumulated) > frame.MaxPayload {
			logger.Warn(fmt.Sprintf("[QUIC SUBFRAME LIMIT] stream buffer or MaxPayload exceeded on middle fragment: streamID=%d seq=%d buffered=%d acc_len=%d", sub.StreamID, sub.Seq, r.bufferedBytes, len(r.accumulated)), "stream_id", sub.StreamID, "seq", sub.Seq, "buffered", r.bufferedBytes, "acc_len", len(r.accumulated))
			return nil, ErrLimit
		}
		return nil, nil
	}
}

// Push applies a single subframe using RFC 1982 modular comparison.
func (r *StreamReassembly) Push(sub SubFrame) ([]frame.Frame, error) {
	diff := uint16(sub.Seq - r.expectedSeq)
	if diff >= 0x8000 {
		// Old duplicate from retransmit; safely ignore
		return nil, nil
	}
	if diff > 0 {
		if diff > maxStreamWindowSpan {
			// Return ErrLimit (backpressure/retryable) instead of killing the session with ErrProtocol
			logger.Warn(fmt.Sprintf("[QUIC SUBFRAME LIMIT] stream window span exceeded: streamID=%d seq=%d expected=%d diff=%d max=%d", sub.StreamID, sub.Seq, r.expectedSeq, diff, maxStreamWindowSpan), "stream_id", sub.StreamID, "seq", sub.Seq, "expected", r.expectedSeq, "diff", diff, "max", maxStreamWindowSpan)
			return nil, ErrLimit
		}
		if _, exists := r.outOfOrder[sub.Seq]; exists {
			// In-window duplicate; ignore
			return nil, nil
		}
		if r.bufferedBytes+len(sub.Payload) > maxStreamBufferSize {
			logger.Warn(fmt.Sprintf("[QUIC SUBFRAME LIMIT] stream buffer exceeded: streamID=%d buffered=%d payload=%d max=%d", sub.StreamID, r.bufferedBytes, len(sub.Payload), maxStreamBufferSize), "stream_id", sub.StreamID, "buffered", r.bufferedBytes, "payload", len(sub.Payload), "max", maxStreamBufferSize)
			return nil, ErrLimit
		}
		r.outOfOrder[sub.Seq] = sub
		r.bufferedBytes += len(sub.Payload)
		return nil, nil
	}

	// diff == 0: exact expected sequence
	ready, err := r.appendSub(sub)
	if err != nil {
		return nil, err
	}
	r.expectedSeq++

	// Drain any contiguous out-of-order subframes
	for {
		next, ok := r.outOfOrder[r.expectedSeq]
		if !ok {
			break
		}
		delete(r.outOfOrder, r.expectedSeq)
		r.bufferedBytes -= len(next.Payload)
		if r.bufferedBytes < 0 {
			r.bufferedBytes = 0
		}
		nextFrames, err := r.appendSub(next)
		if err != nil {
			return nil, err
		}
		if len(nextFrames) > 0 {
			ready = append(ready, nextFrames...)
		}
		r.expectedSeq++
	}

	return ready, nil
}

// HasHoles returns true if this stream has out-of-order packets or unfinished composite frames.
func (r *StreamReassembly) HasHoles() bool {
	return len(r.outOfOrder) > 0 || len(r.accumulated) > 0
}

// PerStreamReassembly manages independent reassembly buffers for all streams of a session.
type PerStreamReassembly struct {
	streams map[uint32]*StreamReassembly
}

// NewPerStreamReassembly creates an empty PerStreamReassembly instance.
func NewPerStreamReassembly() *PerStreamReassembly {
	return &PerStreamReassembly{
		streams: make(map[uint32]*StreamReassembly),
	}
}

// HasHoles checks if any active stream has reassembly gaps or unfinished fragments.
func (p *PerStreamReassembly) HasHoles() bool {
	if p == nil {
		return false
	}
	for _, s := range p.streams {
		if s.HasHoles() {
			return true
		}
	}
	return false
}

// PushChunk parses and applies subframes from an uplink chunk.
func (p *PerStreamReassembly) PushChunk(chunk []byte, closedStreams map[uint32]struct{}, maxStreams int) ([]frame.Frame, error) {
	subFrames, err := ParseSubFrames(chunk)
	if err != nil {
		return nil, err
	}

	var readyFrames []frame.Frame
	for _, sub := range subFrames {
		if closedStreams != nil {
			if _, closed := closedStreams[sub.StreamID]; closed {
				delete(p.streams, sub.StreamID)
				continue
			}
		}

		st, exists := p.streams[sub.StreamID]
		if !exists {
			if maxStreams > 0 && len(p.streams) >= maxStreams+64 {
				logger.Warn(fmt.Sprintf("[QUIC SUBFRAME LIMIT] max streams per session exceeded: streamID=%d active=%d limit=%d", sub.StreamID, len(p.streams), maxStreams+64), "stream_id", sub.StreamID, "active_streams", len(p.streams), "limit", maxStreams+64)
				return nil, ErrLimit
			}
			st = NewStreamReassembly()
			p.streams[sub.StreamID] = st
		}

		frames, err := st.Push(sub)
		if err != nil {
			return nil, err
		}
		for _, f := range frames {
			if f.Type == frame.Close {
				delete(p.streams, f.StreamID)
			}
			readyFrames = append(readyFrames, f)
		}
	}

	return readyFrames, nil
}

// Clear frees all internal reassembly state.
func (p *PerStreamReassembly) Clear() {
	if p == nil {
		return
	}
	for k := range p.streams {
		delete(p.streams, k)
	}
	p.streams = nil
}
