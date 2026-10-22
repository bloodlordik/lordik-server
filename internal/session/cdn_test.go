package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/telegramdesktop/tproxy-server/internal/config"
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

func TestPiggybackAndPollStaleCursorGraceful(t *testing.T) {
	configuration := testConfig("127.0.0.1:1")
	configuration.Profiles[0].CarrierMode = config.CarrierCDNAdaptive
	sess := newSession(sessionOptions{
		profile:  &configuration.Profiles[0],
		limits:   configuration.Limits,
		timeouts: configuration.Timeouts,
	})
	defer sess.Close()

	// Queue a downlink frame
	sess.mu.Lock()
	queued := sess.queueFrameLocked(frame.Data, 1, []byte("response 1"))
	sess.mu.Unlock()
	if !queued {
		t.Fatal("failed to queue test frame")
	}

	// 1. Initial PiggybackDown with cursor 0
	body, cursor, err := sess.PiggybackDown(0)
	if err != nil {
		t.Fatalf("initial PiggybackDown failed: %v", err)
	}
	if len(body) == 0 || cursor != 1 {
		t.Fatalf("expected batch at cursor 1, got len=%d cursor=%d", len(body), cursor)
	}

	// 2. Parallel in-flight request arrives with old cursor 0
	// MUST NOT fail protocol and MUST NOT kill the session!
	body2, cursor2, err := sess.PiggybackDown(0)
	if err != nil {
		t.Fatalf("parallel PiggybackDown(0) failed with error: %v", err)
	}
	if len(body2) != 0 || cursor2 != 1 {
		t.Fatalf("expected empty body and cursor 1 for stale parallel request, got len=%d cursor=%d", len(body2), cursor2)
	}

	// 3. Client acks cursor 1
	body3, cursor3, err := sess.PiggybackDown(1)
	if err != nil {
		t.Fatalf("PiggybackDown(1) ack failed: %v", err)
	}
	if len(body3) != 0 || cursor3 != 1 {
		t.Fatalf("expected empty body for empty queue ack, got len=%d cursor=%d", len(body3), cursor3)
	}

	// 4. Stale PollCDN with cursor 0 arrives after parallel request already advanced cursor
	pollBody, pollCursor, err := sess.PollCDN(context.Background(), 0, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("stale PollCDN(0) failed: %v", err)
	}
	if len(pollBody) != 0 || pollCursor != 1 {
		t.Fatalf("expected empty body and cursor 1 for stale PollCDN, got len=%d cursor=%d", len(pollBody), pollCursor)
	}

	// 5. Future cursor MUST fail protocol
	_, _, err = sess.PiggybackDown(99)
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("expected ErrProtocol on future cursor, got %v", err)
	}
}

func TestCDNPerIPLimitsBypass(t *testing.T) {
	configuration := testConfig("127.0.0.1:1")
	configuration.Profiles[0].CarrierMode = config.CarrierCDNAdaptive
	configuration.Limits.MaxBootstrapsPerIP = 1
	configuration.Limits.MaxSessionsPerIP = 1
	configuration.Limits.MaxBootstrapsGlobal = 10
	configuration.Limits.MaxSessionsGlobal = 10
	manager := NewManager(configuration, [32]byte{1})
	defer manager.Shutdown()

	clientIP := "198.51.100.42"
	// 1. Issue first bootstrap
	b1, err := manager.IssueBootstrap(&configuration.Profiles[0], clientIP)
	if err != nil {
		t.Fatalf("first IssueBootstrap failed: %v", err)
	}

	// 2. Issue second bootstrap from SAME IP - MUST succeed because carrier is CDN!
	b2, err := manager.IssueBootstrap(&configuration.Profiles[0], clientIP)
	if err != nil {
		t.Fatalf("second IssueBootstrap failed for CDN carrier: %v", err)
	}

	// 3. Create first session
	hello := frame.Encode(frame.Hello, 0, []byte{1})
	res1, err := manager.Create(b1, clientIP, hello)
	if err != nil {
		t.Fatalf("first Create failed: %v", err)
	}
	defer res1.Session.Close()

	// 4. Create second session from SAME IP - MUST succeed because carrier is CDN!
	res2, err := manager.Create(b2, clientIP, hello)
	if err != nil {
		t.Fatalf("second Create failed for CDN carrier: %v", err)
	}
	defer res2.Session.Close()
}

func TestStreamCDN_InitialHeartbeatAndPrefix(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteGLTFStreamPrefix(&buf); err != nil {
		t.Fatalf("WriteGLTFStreamPrefix failed: %v", err)
	}
	if buf.Len() != 12 {
		t.Fatalf("expected 12 bytes prefix, got %d", buf.Len())
	}
	if !bytes.Equal(buf.Bytes()[:4], []byte("glTF")) {
		t.Fatalf("expected glTF magic, got %q", buf.Bytes()[:4])
	}

	// Test empty envelope (heartbeat)
	buf.Reset()
	if err := WriteBatchEnvelope(&buf, 42, nil); err != nil {
		t.Fatalf("WriteBatchEnvelope heartbeat failed: %v", err)
	}
	if buf.Len() != 8 {
		t.Fatalf("expected 8 bytes heartbeat envelope, got %d", buf.Len())
	}

	configuration := testConfig("127.0.0.1:1")
	configuration.Profiles[0].CarrierMode = config.CarrierCDNAdaptive
	configuration.Limits.CDNStreamHeartbeatSecs = 1
	configuration.Limits.CDNStreamMaxDurationSecs = 10
	sess := newSession(sessionOptions{
		profile:  &configuration.Profiles[0],
		limits:   configuration.Limits,
		timeouts: configuration.Timeouts,
	})
	defer sess.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	received := make(chan []byte, 5)
	go func() {
		_ = sess.StreamCDN(ctx, 0, func(cur uint64, body []byte) error {
			if len(body) > 0 {
				received <- body
			}
			return nil
		})
	}()

	// Wait for stream to become active
	time.Sleep(20 * time.Millisecond)

	// Queue a downlink frame
	sess.mu.Lock()
	sess.queueFrameLocked(frame.Data, 10, []byte("streamed frame payload"))
	sess.mu.Unlock()

	select {
	case b := <-received:
		frames, err := frame.ParseAll(b, 1024*1024)
		if err != nil || len(frames) != 1 {
			t.Fatalf("invalid batch received: frames=%d err=%v", len(frames), err)
		}
		if frames[0].StreamID != 10 || string(frames[0].Payload) != "streamed frame payload" {
			t.Fatalf("unexpected frame content: %+v", frames[0])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for streamed batch")
	}
}

func TestStreamCDN_ZeroLossReplay(t *testing.T) {
	configuration := testConfig("127.0.0.1:1")
	configuration.Profiles[0].CarrierMode = config.CarrierCDNAdaptive
	sess := newSession(sessionOptions{
		profile:  &configuration.Profiles[0],
		limits:   configuration.Limits,
		timeouts: configuration.Timeouts,
	})
	defer sess.Close()

	// Send 2 batches via StreamCDN
	ctx1, cancel1 := context.WithCancel(context.Background())
	batches1 := make(chan uint64, 5)
	go func() {
		_ = sess.StreamCDN(ctx1, 0, func(cur uint64, body []byte) error {
			if len(body) > 0 {
				batches1 <- cur
			}
			return nil
		})
	}()

	time.Sleep(20 * time.Millisecond)
	sess.mu.Lock()
	sess.queueFrameLocked(frame.Data, 1, []byte("batch 1"))
	sess.mu.Unlock()

	select {
	case cur := <-batches1:
		if cur != 1 {
			t.Fatalf("expected cursor 1, got %d", cur)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for batch 1")
	}

	sess.mu.Lock()
	sess.queueFrameLocked(frame.Data, 2, []byte("batch 2"))
	sess.mu.Unlock()

	select {
	case cur := <-batches1:
		if cur != 2 {
			t.Fatalf("expected cursor 2, got %d", cur)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for batch 2")
	}

	// Disconnect client 1
	cancel1()
	time.Sleep(30 * time.Millisecond)

	// Client 2 reconnects asking for cursor 1 (missed batch 2)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	replayed := make(chan uint64, 5)
	go func() {
		_ = sess.StreamCDN(ctx2, 1, func(cur uint64, body []byte) error {
			if len(body) > 0 {
				replayed <- cur
			}
			return nil
		})
	}()

	select {
	case cur := <-replayed:
		if cur != 2 {
			t.Fatalf("expected replayed batch cursor 2, got %d", cur)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for replayed batch 2")
	}
}

func TestStreamCDN_UplinkAckPruning(t *testing.T) {
	configuration := testConfig("127.0.0.1:1")
	configuration.Profiles[0].CarrierMode = config.CarrierCDNAdaptive
	sess := newSession(sessionOptions{
		profile:  &configuration.Profiles[0],
		limits:   configuration.Limits,
		timeouts: configuration.Timeouts,
	})
	defer sess.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	batches := make(chan uint64, 5)
	go func() {
		_ = sess.StreamCDN(ctx, 0, func(cur uint64, body []byte) error {
			if len(body) > 0 {
				batches <- cur
			}
			return nil
		})
	}()

	time.Sleep(20 * time.Millisecond)
	sess.mu.Lock()
	sess.queueFrameLocked(frame.Data, 1, []byte("frame 1"))
	sess.mu.Unlock()

	<-batches

	sess.mu.Lock()
	if len(sess.unackedBatches) != 1 {
		t.Fatalf("expected 1 unacked batch, got %d", len(sess.unackedBatches))
	}
	sess.mu.Unlock()

	// Send PiggybackDown with cursor 1 (acknowledging batch 1)
	_, _, err := sess.PiggybackDown(1)
	if err != nil {
		t.Fatalf("PiggybackDown ack failed: %v", err)
	}

	sess.mu.Lock()
	if len(sess.unackedBatches) != 0 || sess.unackedCost != 0 {
		t.Fatalf("expected 0 unacked batches and 0 cost after ack, got %d batches, cost=%d",
			len(sess.unackedBatches), sess.unackedCost)
	}
	sess.mu.Unlock()
}

func TestStreamCDN_Superseded(t *testing.T) {
	configuration := testConfig("127.0.0.1:1")
	configuration.Profiles[0].CarrierMode = config.CarrierCDNAdaptive
	sess := newSession(sessionOptions{
		profile:  &configuration.Profiles[0],
		limits:   configuration.Limits,
		timeouts: configuration.Timeouts,
	})
	defer sess.Close()

	stream1Done := make(chan error, 1)
	go func() {
		err := sess.StreamCDN(context.Background(), 0, func(cur uint64, body []byte) error {
			return nil
		})
		stream1Done <- err
	}()

	time.Sleep(30 * time.Millisecond)

	// Start stream 2 (supersedes stream 1)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go func() {
		_ = sess.StreamCDN(ctx2, 0, func(cur uint64, body []byte) error {
			return nil
		})
	}()

	select {
	case err := <-stream1Done:
		if err != nil {
			t.Fatalf("stream 1 should exit cleanly with nil on superseded, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream 1 was not superseded in time")
	}
}
