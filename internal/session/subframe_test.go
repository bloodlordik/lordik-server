package session

import (
	"encoding/binary"
	"testing"

	"github.com/telegramdesktop/tproxy-server/internal/frame"
)

func encodeTestSubFrame(t frame.Type, streamID uint32, seq uint16, flags uint8, payload []byte) []byte {
	buf := make([]byte, SubFrameHeaderSize+len(payload))
	buf[0] = byte(t)
	buf[1] = byte(streamID >> 16)
	buf[2] = byte(streamID >> 8)
	buf[3] = byte(streamID)
	binary.BigEndian.PutUint16(buf[4:6], seq)
	buf[6] = flags
	binary.BigEndian.PutUint16(buf[7:9], uint16(len(payload)))
	copy(buf[SubFrameHeaderSize:], payload)
	return buf
}

func TestParseSubFrames(t *testing.T) {
	// 1. Single valid SubFrame
	payload := []byte("hello stream")
	encoded := encodeTestSubFrame(frame.Data, 10, 1, SubFlagFirst|SubFlagFin, payload)

	subs, err := ParseSubFrames(encoded)
	if err != nil {
		t.Fatalf("unexpected error parsing valid subframe: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("expected 1 subframe, got %d", len(subs))
	}
	if subs[0].Type != frame.Data || subs[0].StreamID != 10 || subs[0].Seq != 1 || subs[0].Flags != 0x03 {
		t.Fatalf("subframe fields mismatch: %+v", subs[0])
	}
	if string(subs[0].Payload) != "hello stream" {
		t.Fatalf("payload mismatch: %q", string(subs[0].Payload))
	}

	// 2. Coalesced multiple subframes
	sub1 := encodeTestSubFrame(frame.Open, 1, 1, SubFlagFirst|SubFlagFin, nil)
	sub2 := encodeTestSubFrame(frame.Data, 1, 2, SubFlagFirst|SubFlagFin, []byte("data1"))
	sub3 := encodeTestSubFrame(frame.Window, 2, 1, SubFlagFirst|SubFlagFin, frame.WindowPayload(65536))
	multi := append(append(sub1, sub2...), sub3...)

	subsMulti, err := ParseSubFrames(multi)
	if err != nil {
		t.Fatalf("unexpected error parsing coalesced subframes: %v", err)
	}
	if len(subsMulti) != 3 {
		t.Fatalf("expected 3 subframes, got %d", len(subsMulti))
	}
	if subsMulti[0].StreamID != 1 || subsMulti[1].StreamID != 1 || subsMulti[2].StreamID != 2 {
		t.Fatalf("stream IDs mismatch in coalesced subframes")
	}

	// 3. Incomplete header (< 9 bytes)
	if _, err := ParseSubFrames(encoded[:5]); err == nil {
		t.Fatal("expected error on truncated header")
	}

	// 4. Incomplete payload
	if _, err := ParseSubFrames(encoded[:SubFrameHeaderSize+len(payload)-1]); err == nil {
		t.Fatal("expected error on truncated payload")
	}

	// 5. Invalid frame type
	badType := make([]byte, len(encoded))
	copy(badType, encoded)
	badType[0] = 0xFE
	if _, err := ParseSubFrames(badType); err == nil {
		t.Fatal("expected error on invalid frame type")
	}
}

func TestStreamReassemblySingleAndComposite(t *testing.T) {
	st := NewStreamReassembly()

	// 1. Single OPEN (seq=1)
	openSub := SubFrame{
		Type:     frame.Open,
		StreamID: 5,
		Seq:      1,
		Flags:    SubFlagFirst | SubFlagFin,
		Payload:  nil,
	}
	frames, err := st.Push(openSub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(frames) != 1 || frames[0].Type != frame.Open || frames[0].StreamID != 5 {
		t.Fatalf("expected 1 OPEN frame, got %+v", frames)
	}

	// 2. Composite DATA frame in 3 fragments (seq=2, 3, 4)
	part1 := SubFrame{
		Type:     frame.Data,
		StreamID: 5,
		Seq:      2,
		Flags:    SubFlagFirst,
		Payload:  []byte("part1_"),
	}
	part2 := SubFrame{
		Type:     frame.Data,
		StreamID: 5,
		Seq:      3,
		Flags:    0,
		Payload:  []byte("part2_"),
	}
	part3 := SubFrame{
		Type:     frame.Data,
		StreamID: 5,
		Seq:      4,
		Flags:    SubFlagFin,
		Payload:  []byte("part3"),
	}

	frames, err = st.Push(part1)
	if err != nil || len(frames) != 0 {
		t.Fatalf("part1 should not yield complete frames: %v, %v", err, frames)
	}
	if !st.HasHoles() {
		t.Fatal("st should have holes while composite frame is in progress")
	}

	frames, err = st.Push(part2)
	if err != nil || len(frames) != 0 {
		t.Fatalf("part2 should not yield complete frames: %v, %v", err, frames)
	}

	frames, err = st.Push(part3)
	if err != nil {
		t.Fatalf("unexpected error on part3: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 assembled frame, got %d", len(frames))
	}
	if string(frames[0].Payload) != "part1_part2_part3" {
		t.Fatalf("assembled payload mismatch: %q", string(frames[0].Payload))
	}
	if st.HasHoles() {
		t.Fatal("st should not have holes after composite frame is finished")
	}
}

func TestStreamReassemblyModularArithmeticRFC1982(t *testing.T) {
	st := NewStreamReassembly()

	// Seq=2 arrives before Seq=1 (out-of-order)
	sub2 := SubFrame{
		Type:     frame.Data,
		StreamID: 1,
		Seq:      2,
		Flags:    SubFlagFirst | SubFlagFin,
		Payload:  []byte("second"),
	}
	frames, err := st.Push(sub2)
	if err != nil || len(frames) != 0 {
		t.Fatalf("out-of-order Seq=2 should not yield frames: %v, %v", err, frames)
	}
	if !st.HasHoles() {
		t.Fatal("expected HasHoles=true when Seq=2 is buffered")
	}

	// Seq=1 arrives (gap healed)
	sub1 := SubFrame{
		Type:     frame.Open,
		StreamID: 1,
		Seq:      1,
		Flags:    SubFlagFirst | SubFlagFin,
		Payload:  nil,
	}
	frames, err = st.Push(sub1)
	if err != nil {
		t.Fatalf("unexpected error on Seq=1: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames [OPEN, DATA], got %d", len(frames))
	}
	if frames[0].Type != frame.Open || frames[1].Type != frame.Data {
		t.Fatalf("frames out of order: %+v", frames)
	}
	if string(frames[1].Payload) != "second" {
		t.Fatalf("payload mismatch: %q", string(frames[1].Payload))
	}
	if st.HasHoles() {
		t.Fatal("expected no holes after draining")
	}

	// Duplicate Seq=2 arrives again -> ignored
	frames, err = st.Push(sub2)
	if err != nil || len(frames) != 0 {
		t.Fatalf("old duplicate should be ignored: %v, %v", err, frames)
	}

	// Jump too far ahead (> 256)
	subFar := SubFrame{
		Type:     frame.Data,
		StreamID: 1,
		Seq:      300,
		Flags:    SubFlagFirst | SubFlagFin,
		Payload:  []byte("too far"),
	}
	if _, err := st.Push(subFar); err != ErrLimit {
		t.Fatalf("expected ErrLimit for jump > maxStreamWindowSpan, got: %v", err)
	}
}

func TestStreamReassemblySequenceWrapAround(t *testing.T) {
	st := NewStreamReassembly()
	st.expectedSeq = 65535

	// SubFrame at 65535
	subLast := SubFrame{
		Type:     frame.Data,
		StreamID: 1,
		Seq:      65535,
		Flags:    SubFlagFirst | SubFlagFin,
		Payload:  []byte("last"),
	}
	frames, err := st.Push(subLast)
	if err != nil || len(frames) != 1 {
		t.Fatalf("failed at 65535: %v, %v", err, frames)
	}
	if st.expectedSeq != 0 {
		t.Fatalf("expected wrap around to 0, got %d", st.expectedSeq)
	}

	// Next SubFrame at 0
	subZero := SubFrame{
		Type:     frame.Data,
		StreamID: 1,
		Seq:      0,
		Flags:    SubFlagFirst | SubFlagFin,
		Payload:  []byte("zero"),
	}
	frames, err = st.Push(subZero)
	if err != nil || len(frames) != 1 {
		t.Fatalf("failed at 0: %v, %v", err, frames)
	}
	if st.expectedSeq != 1 {
		t.Fatalf("expected sequence 1, got %d", st.expectedSeq)
	}
}

func TestPerStreamReassemblyNoHeadOfLineBlocking(t *testing.T) {
	psr := NewPerStreamReassembly()

	// Stream 4 sends fragment Seq=2 (gap: Seq=1 missing)
	chunkStream4 := encodeTestSubFrame(frame.Data, 4, 2, SubFlagFirst|SubFlagFin, []byte("stream4_data"))
	frames, err := psr.PushChunk(chunkStream4, nil, 32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(frames) != 0 {
		t.Fatalf("stream 4 should be waiting for Seq=1, got frames: %+v", frames)
	}
	if !psr.HasHoles() {
		t.Fatal("psr should report holes for stream 4")
	}

	// Stream 1 sends Seq=1 (chat/UI message)
	chunkStream1 := encodeTestSubFrame(frame.Open, 1, 1, SubFlagFirst|SubFlagFin, nil)
	frames, err = psr.PushChunk(chunkStream1, nil, 32)
	if err != nil {
		t.Fatalf("unexpected error on stream 1: %v", err)
	}
	// Stream 1 MUST NOT be blocked by Stream 4!
	if len(frames) != 1 || frames[0].StreamID != 1 {
		t.Fatalf("stream 1 was blocked by stream 4! frames: %+v", frames)
	}

	// Now Stream 4 sends Seq=1 (heals Stream 4 gap)
	chunkStream4Open := encodeTestSubFrame(frame.Open, 4, 1, SubFlagFirst|SubFlagFin, nil)
	frames, err = psr.PushChunk(chunkStream4Open, nil, 32)
	if err != nil {
		t.Fatalf("unexpected error on stream 4 Seq=1: %v", err)
	}
	// Both OPEN and DATA for Stream 4 are delivered
	if len(frames) != 2 || frames[0].StreamID != 4 || frames[1].StreamID != 4 {
		t.Fatalf("expected 2 frames for stream 4, got: %+v", frames)
	}
	if psr.HasHoles() {
		t.Fatal("expected no holes after healing")
	}
}

func TestPerStreamReassemblyClosedStreams(t *testing.T) {
	psr := NewPerStreamReassembly()
	closed := map[uint32]struct{}{
		5: {},
	}

	// Packet for closed stream 5 is ignored
	chunk := encodeTestSubFrame(frame.Data, 5, 1, SubFlagFirst|SubFlagFin, []byte("late data"))
	frames, err := psr.PushChunk(chunk, closed, 32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(frames) != 0 {
		t.Fatalf("closed stream frame should be dropped, got: %+v", frames)
	}
	if len(psr.streams) != 0 {
		t.Fatal("closed stream should not create a reassembly entry")
	}
}
