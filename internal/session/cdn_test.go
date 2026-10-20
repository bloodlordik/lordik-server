package session

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/telegramdesktop/tproxy-server/internal/frame"
)

func TestBase64urlHeaderSharding(t *testing.T) {
	data := make([]byte, 12288)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	urlPart, headers := EncodeCDNPayload(data, 2048, 3584)
	if len(urlPart) > 2048 {
		t.Fatalf("urlPart length %d exceeds maxURLPart 2048", len(urlPart))
	}
	for i, h := range headers {
		if len(h) > 3584 {
			t.Fatalf("header %d length %d exceeds maxHeaderPart 3584", i, len(h))
		}
	}

	decoded, err := DecodeCDNPayload(urlPart, headers)
	if err != nil {
		t.Fatalf("DecodeCDNPayload failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Fatal("decoded data does not match original data")
	}
}

func TestReassemblyBufferOutOfOrder(t *testing.T) {
	buf := NewReassemblyBuffer(16, 1024*1024)

	// Create a 60 KiB frame payload
	payload := make([]byte, 60*1024)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	encoded := frame.Encode(frame.Data, 42, payload)

	// Split into 5 chunks of equal size
	chunkSize := (len(encoded) + 4) / 5
	var chunks [][]byte
	for off := 0; off < len(encoded); off += chunkSize {
		end := off + chunkSize
		if end > len(encoded) {
			end = len(encoded)
		}
		chunks = append(chunks, encoded[off:end])
	}
	if len(chunks) != 5 {
		t.Fatalf("expected 5 chunks, got %d", len(chunks))
	}

	// Push in out-of-order sequence: 1, 3, 2, 5, 4
	order := []uint64{1, 3, 2, 5, 4}
	var allFrames []frame.Frame

	for _, seq := range order {
		chunkIndex := int(seq - 1)
		frames, dup, err := buf.Push(seq, chunks[chunkIndex])
		if err != nil {
			t.Fatalf("Push seq %d failed: %v", seq, err)
		}
		if dup {
			t.Fatalf("unexpected dup for seq %d", seq)
		}
		allFrames = append(allFrames, frames...)
	}

	if len(allFrames) != 1 {
		t.Fatalf("expected 1 complete reassembled frame, got %d", len(allFrames))
	}
	f := allFrames[0]
	if f.Type != frame.Data || f.StreamID != 42 || !bytes.Equal(f.Payload, payload) {
		t.Fatal("reassembled frame does not match original")
	}
	if buf.ExpectedUpSeq() != 6 {
		t.Fatalf("expected next seq 6, got %d", buf.ExpectedUpSeq())
	}
}

func TestReassemblyBufferRetries(t *testing.T) {
	buf := NewReassemblyBuffer(16, 1024*1024)

	f1 := frame.Encode(frame.Open, 10, nil)
	ready, dup, err := buf.Push(1, f1)
	if err != nil || dup || len(ready) != 1 {
		t.Fatalf("initial Push failed: ready=%d, dup=%v, err=%v", len(ready), dup, err)
	}

	// Retransmit seq 1
	ready2, dup2, err2 := buf.Push(1, f1)
	if err2 != nil {
		t.Fatalf("retry failed with error: %v", err2)
	}
	if !dup2 {
		t.Fatal("expected duplicate=true for retransmitted seq")
	}
	if len(ready2) != 0 {
		t.Fatalf("expected 0 frames for duplicate, got %d", len(ready2))
	}
}

func TestGLTFPrefixAndDownlinkDemux(t *testing.T) {
	f1 := frame.Encode(frame.Data, 1, []byte("hello"))
	f2 := frame.Encode(frame.Data, 2, []byte("world"))
	batch := append(f1, f2...)
	cursor := uint64(123456)

	wrapped := WrapGLTF(batch, cursor)
	if len(wrapped) != GLTFHeaderSize+len(batch) {
		t.Fatalf("expected len %d, got %d", GLTFHeaderSize+len(batch), len(wrapped))
	}

	unwrappedCursor, unwrappedBatch, err := UnwrapGLTF(wrapped)
	if err != nil {
		t.Fatalf("UnwrapGLTF failed: %v", err)
	}
	if uint64(unwrappedCursor) != cursor {
		t.Fatalf("expected cursor %d, got %d", cursor, unwrappedCursor)
	}
	if !bytes.Equal(unwrappedBatch, batch) {
		t.Fatal("unwrapped batch payload mismatch")
	}

	frames, err := frame.ParseAll(unwrappedBatch, 1024*1024)
	if err != nil {
		t.Fatalf("ParseAll failed on demuxed batch: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}
	if string(frames[0].Payload) != "hello" || string(frames[1].Payload) != "world" {
		t.Fatal("frames content mismatch")
	}

	// Corrupt header
	corrupted := make([]byte, len(wrapped))
	copy(corrupted, wrapped)
	corrupted[0] = 'X'
	if _, _, err := UnwrapGLTF(corrupted); !errors.Is(err, ErrInvalidGLTF) {
		t.Fatalf("expected ErrInvalidGLTF on corrupted magic, got %v", err)
	}
}

func TestCDNMemoryAndBoundaryLimits(t *testing.T) {
	buf := NewReassemblyBuffer(4, 1024)

	// Sliding window overflow: expected 1, send seq 6 (> 1 + 4)
	_, _, err := buf.Push(6, []byte("overflow"))
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("expected ErrProtocol for sliding window overrun, got %v", err)
	}

	// Frame parser overflow: feed chunk > maxPendingBytes
	parser := NewFrameStreamParser(1024)
	oversized := make([]byte, 2048)
	_, err = parser.Feed(oversized)
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("expected ErrLimit for feed exceeding maxPendingBytes, got %v", err)
	}
}
