package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"sync"
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

	// Since maxParallelCDNStreams = 4, streams 1..4 run concurrently in the worker pool.
	// Starting stream 5 exceeds the pool and evicts the oldest stream (stream 1) via FIFO rotation.
	cancels := make([]context.CancelFunc, 0, 4)
	defer func() {
		for _, cancel := range cancels {
			cancel()
		}
	}()

	// Launch streams 2..4 to fill up the pool to capacity
	for i := 2; i <= 4; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancels = append(cancels, cancel)
		go func() {
			_ = sess.StreamCDN(ctx, 0, func(cur uint64, body []byte) error {
				return nil
			})
		}()
	}

	// Wait until pool reaches maxParallelCDNStreams
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		sess.mu.Lock()
		wCount := len(sess.streamWorkers)
		sess.mu.Unlock()
		if wCount == maxParallelCDNStreams {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Stream 5: exceeds the pool, evicting the oldest stream (stream 1)
	ctx5, cancel5 := context.WithCancel(context.Background())
	cancels = append(cancels, cancel5)
	go func() {
		_ = sess.StreamCDN(ctx5, 0, func(cur uint64, body []byte) error {
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

func TestPiggybackAndPollSkipTinyWindow(t *testing.T) {
	configuration := testConfig("127.0.0.1:1")
	configuration.Profiles[0].CarrierMode = config.CarrierCDNAdaptive
	configuration.Profiles[0].BackendType = config.BackendDirect
	sess := newSession(sessionOptions{
		profile:  &configuration.Profiles[0],
		limits:   configuration.Limits,
		timeouts: configuration.Timeouts,
	})
	defer sess.Close()

	// 1. Queue tiny WINDOW frame (104 bytes credit)
	sess.mu.Lock()
	queued := sess.queueFrameLocked(frame.Window, 1, frame.WindowPayload(104))
	sess.mu.Unlock()
	if !queued {
		t.Fatal("failed to queue window frame")
	}

	// 2. PiggybackDownWait without coalesce: tiny WINDOW must NOT be returned standalone
	body, cursor, err := sess.PiggybackDownWait(0, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body) != 0 || cursor != 0 {
		t.Fatalf("expected tiny WINDOW to be skipped, got len=%d cursor=%d", len(body), cursor)
	}

	// 3. PiggybackDownWait with coalesce: should wait and still NOT return standalone tiny WINDOW
	start := time.Now()
	body, cursor, err = sess.PiggybackDownWait(0, true)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body) != 0 || cursor != 0 {
		t.Fatalf("expected tiny WINDOW to be skipped after coalesce timeout, got len=%d cursor=%d", len(body), cursor)
	}
	// Direct backend has 150ms coalesce wait
	if elapsed < 100*time.Millisecond {
		t.Fatalf("expected direct coalesce wait >= 100ms, got %v", elapsed)
	}

	// 4. Now queue DATA frame (simulate Telegram DC resPQ arriving)
	sess.mu.Lock()
	queued = sess.queueFrameLocked(frame.Data, 1, []byte("telegram res_pq_multi response"))
	sess.mu.Unlock()
	if !queued {
		t.Fatal("failed to queue data frame")
	}

	// 5. Now PiggybackDownWait should return both frames bundled
	body, cursor, err = sess.PiggybackDownWait(0, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body) == 0 || cursor != 1 {
		t.Fatalf("expected bundled batch at cursor 1, got len=%d cursor=%d", len(body), cursor)
	}

	// Verify both WINDOW and DATA frames are in the bundled batch
	parsed, err := frame.ParseAll(body, frame.MaxPayload)
	if err != nil {
		t.Fatalf("failed to parse bundled frames: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 frames (WINDOW + DATA), got %d", len(parsed))
	}
	if parsed[0].Type != frame.Window || parsed[1].Type != frame.Data {
		t.Fatalf("expected [Window, Data], got [%v, %v]", parsed[0].Type, parsed[1].Type)
	}
}

func TestPollCDNSkipsTinyWindowUntilData(t *testing.T) {
	configuration := testConfig("127.0.0.1:1")
	configuration.Profiles[0].CarrierMode = config.CarrierCDNAdaptive
	sess := newSession(sessionOptions{
		profile:  &configuration.Profiles[0],
		limits:   configuration.Limits,
		timeouts: configuration.Timeouts,
	})
	defer sess.Close()

	// Queue tiny WINDOW
	sess.mu.Lock()
	_ = sess.queueFrameLocked(frame.Window, 1, frame.WindowPayload(104))
	sess.mu.Unlock()

	resultCh := make(chan struct {
		body   []byte
		cursor uint64
		err    error
	}, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		b, c, e := sess.PollCDN(ctx, 0, 1*time.Second)
		resultCh <- struct {
			body   []byte
			cursor uint64
			err    error
		}{b, c, e}
	}()

	// PollCDN must NOT immediately return on tiny WINDOW
	select {
	case res := <-resultCh:
		t.Fatalf("PollCDN returned prematurely for tiny WINDOW: len=%d cursor=%d err=%v", len(res.body), res.cursor, res.err)
	case <-time.After(50 * time.Millisecond):
		// Expected: PollCDN is still waiting for worthwhile frames
	}

	// Now queue DATA frame
	sess.mu.Lock()
	_ = sess.queueFrameLocked(frame.Data, 1, []byte("delayed data"))
	sess.mu.Unlock()

	// PollCDN should now wake up and return bundled frames
	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("PollCDN returned error: %v", res.err)
		}
		if len(res.body) == 0 || res.cursor != 1 {
			t.Fatalf("expected bundled body and cursor 1, got len=%d cursor=%d", len(res.body), res.cursor)
		}
		parsed, err := frame.ParseAll(res.body, frame.MaxPayload)
		if err != nil || len(parsed) != 2 {
			t.Fatalf("expected 2 parsed frames, got len=%d err=%v", len(parsed), err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("PollCDN did not wake up after DATA frame queued")
	}
}

func TestPiggybackDownWaitSkipsCoalesceWhenBufferHasHoles(t *testing.T) {
	configuration := testConfig("127.0.0.1:1")
	configuration.Profiles[0].CarrierMode = config.CarrierCDNAdaptive
	configuration.Profiles[0].BackendType = config.BackendDirect
	sess := newSession(sessionOptions{
		profile:  &configuration.Profiles[0],
		limits:   configuration.Limits,
		timeouts: configuration.Timeouts,
	})
	defer sess.Close()

	// Send out-of-order chunk (seq 2 arrives when expected is 1)
	f2 := frame.Encode(frame.Data, 1, []byte("chunk-2"))
	_, err := sess.ProcessUpCDN(2, f2)
	if err != nil {
		t.Fatalf("unexpected error on out-of-order chunk: %v", err)
	}
	if !sess.cdnReassembly.HasHoles() {
		t.Fatal("expected ReassemblyBuffer to have holes")
	}

	// Coalesce request with holes in buffer must NOT wait 150ms
	start := time.Now()
	body, cursor, err := sess.PiggybackDownWait(0, true)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body) != 0 || cursor != 0 {
		t.Fatalf("expected empty body and cursor 0, got len=%d cursor=%d", len(body), cursor)
	}
	if elapsed >= 80*time.Millisecond {
		t.Fatalf("expected micro-wait to be skipped when buffer has holes, but took %v", elapsed)
	}
}

func TestProcessUpCDNErrLimitDoesNotCloseSession(t *testing.T) {
	configuration := testConfig("127.0.0.1:1")
	configuration.Profiles[0].CarrierMode = config.CarrierCDNAdaptive
	configuration.Limits.MaxFramePayload = 1024
	configuration.Limits.CDNUplinkWindowSize = 4
	sess := newSession(sessionOptions{
		profile:  &configuration.Profiles[0],
		limits:   configuration.Limits,
		timeouts: configuration.Timeouts,
	})
	defer sess.Close()

	// Feed oversized chunk > maxPendingBytes (1024 + 8) to trigger ErrLimit from parser
	oversized := make([]byte, 2048)
	_, err := sess.ProcessUpCDN(1, oversized)
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("expected ErrLimit, got %v", err)
	}

	// The session MUST NOT be marked closed on ErrLimit!
	sess.mu.Lock()
	isClosed := sess.closed
	sess.mu.Unlock()
	if isClosed {
		t.Fatal("session was closed on ErrLimit; expected session to stay open for retry")
	}
}

func TestSession_VIPPrioritization(t *testing.T) {
	configuration := testConfig("127.0.0.1:1")
	configuration.Profiles[0].CarrierMode = config.CarrierCDNAdaptive
	configuration.Limits.CDNMaxDownBatchBytes = 131072
	sess := newSession(sessionOptions{
		profile:  &configuration.Profiles[0],
		limits:   configuration.Limits,
		timeouts: configuration.Timeouts,
	})
	defer sess.Close()

	// Subtest 1: VIP frames (WINDOW, interactive DATA) advance ahead of bulk media DATA
	sess.mu.Lock()
	f1 := frame.Encode(frame.Data, 1, make([]byte, 64*1024))
	f2 := frame.Encode(frame.Window, 2, frame.WindowPayload(104))
	f3 := frame.Encode(frame.Data, 2, make([]byte, 500))
	sess.pendingFrames = []queuedFrame{
		{encoded: f1, typeCode: frame.Data, streamID: 1, cost: len(f1)},
		{encoded: f2, typeCode: frame.Window, streamID: 2, cost: len(f2)},
		{encoded: f3, typeCode: frame.Data, streamID: 2, cost: len(f3)},
	}
	batch := sess.takeDownBatchLimitLocked(131072)
	sess.mu.Unlock()

	frames, err := frame.ParseAll(batch.body, frame.MaxPayload)
	if err != nil {
		t.Fatalf("failed to parse batch: %v", err)
	}
	if len(frames) != 3 {
		t.Fatalf("expected 3 frames, got %d", len(frames))
	}
	// Frame 0: WINDOW (stream 2)
	if frames[0].Type != frame.Window || frames[0].StreamID != 2 {
		t.Fatalf("expected frame 0 to be WINDOW (stream 2), got type=%v stream=%d", frames[0].Type, frames[0].StreamID)
	}
	// Frame 1: DATA (stream 2, 500 B)
	if frames[1].Type != frame.Data || frames[1].StreamID != 2 || len(frames[1].Payload) != 500 {
		t.Fatalf("expected frame 1 to be DATA (stream 2, 500 B), got type=%v stream=%d len=%d", frames[1].Type, frames[1].StreamID, len(frames[1].Payload))
	}
	// Frame 2: DATA (stream 1, 64 KiB)
	if frames[2].Type != frame.Data || frames[2].StreamID != 1 || len(frames[2].Payload) != 64*1024 {
		t.Fatalf("expected frame 2 to be DATA (stream 1, 64 KiB), got type=%v stream=%d len=%d", frames[2].Type, frames[2].StreamID, len(frames[2].Payload))
	}

	// Subtest 2: Size limit scenario (maxBytes = 4000)
	// Bulk media frame does not fit in remaining budget; VIP frames are returned, bulk remains in queue.
	sess.mu.Lock()
	sess.pendingFrames = []queuedFrame{
		{encoded: f1, typeCode: frame.Data, streamID: 1, cost: len(f1)},
		{encoded: f2, typeCode: frame.Window, streamID: 2, cost: len(f2)},
		{encoded: f3, typeCode: frame.Data, streamID: 2, cost: len(f3)},
	}
	batch = sess.takeDownBatchLimitLocked(4000)
	remCount := len(sess.pendingFrames)
	sess.mu.Unlock()

	frames, err = frame.ParseAll(batch.body, frame.MaxPayload)
	if err != nil {
		t.Fatalf("failed to parse batch: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("expected 2 VIP frames in batch, got %d", len(frames))
	}
	if frames[0].Type != frame.Window || frames[0].StreamID != 2 {
		t.Fatalf("expected frame 0 to be WINDOW, got %v", frames[0])
	}
	if frames[1].Type != frame.Data || frames[1].StreamID != 2 || len(frames[1].Payload) != 500 {
		t.Fatalf("expected frame 1 to be interactive DATA, got %v", frames[1])
	}
	if remCount != 1 {
		t.Fatalf("expected 1 remaining frame in pendingFrames, got %d", remCount)
	}

	// Subtest 3: Relative ordering within a single stream is strictly preserved
	// Queue for stream 1: [DATA 64 KiB, DATA 500 B, CLOSE]
	// DATA 500 B and CLOSE must NOT bypass earlier DATA 64 KiB of stream 1!
	sess.mu.Lock()
	f1Small := frame.Encode(frame.Data, 1, make([]byte, 500))
	fc := frame.Encode(frame.Close, 1, nil)
	sess.pendingFrames = []queuedFrame{
		{encoded: f1, typeCode: frame.Data, streamID: 1, cost: len(f1)},
		{encoded: f1Small, typeCode: frame.Data, streamID: 1, cost: len(f1Small)},
		{encoded: fc, typeCode: frame.Close, streamID: 1, cost: len(fc)},
	}
	batch = sess.takeDownBatchLimitLocked(131072)
	sess.mu.Unlock()

	frames, err = frame.ParseAll(batch.body, frame.MaxPayload)
	if err != nil {
		t.Fatalf("failed to parse batch: %v", err)
	}
	if len(frames) != 3 {
		t.Fatalf("expected 3 frames, got %d", len(frames))
	}
	if frames[0].Type != frame.Data || frames[0].StreamID != 1 || len(frames[0].Payload) != 64*1024 {
		t.Fatalf("expected frame 0 to be DATA 64 KiB, got %v", frames[0])
	}
	if frames[1].Type != frame.Data || frames[1].StreamID != 1 || len(frames[1].Payload) != 500 {
		t.Fatalf("expected frame 1 to be DATA 500 B, got %v", frames[1])
	}
	if frames[2].Type != frame.Close || frames[2].StreamID != 1 {
		t.Fatalf("expected frame 2 to be CLOSE, got %v", frames[2])
	}
	// Subtest 4: When OPEN doesn't fit in budget (budget consumed by earlier frame),
	// subsequent CLOSE of that stream must NOT bypass OPEN
	sess.mu.Lock()
	fo3 := frame.Encode(frame.Open, 3, nil)
	fc3 := frame.Encode(frame.Close, 3, nil)
	sess.pendingFrames = []queuedFrame{
		{encoded: f2, typeCode: frame.Window, streamID: 2, cost: len(f2)}, // 104 bytes
		{encoded: fo3, typeCode: frame.Open, streamID: 3, cost: len(fo3)},   // 8 bytes
		{encoded: fc3, typeCode: frame.Close, streamID: 3, cost: len(fc3)},  // 8 bytes
	}
	// maxBytes = len(f2): f2 fills budget; fo3 doesn't fit; fc3 must not bypass fo3
	batch = sess.takeDownBatchLimitLocked(len(f2))
	remCount = len(sess.pendingFrames)
	sess.mu.Unlock()

	frames, err = frame.ParseAll(batch.body, frame.MaxPayload)
	if err != nil {
		t.Fatalf("failed to parse batch: %v", err)
	}
	if len(frames) != 1 || frames[0].Type != frame.Window || frames[0].StreamID != 2 {
		t.Fatalf("expected only stream 2 WINDOW in batch, got %v", frames)
	}
	if remCount != 2 {
		t.Fatalf("expected both OPEN and CLOSE of stream 3 to remain queued, got %d", remCount)
	}

	// Subtest 5: CLOSE of stream 1 is blocked behind heavy DATA 64K of stream 1,
	// while VIP frames of stream 2 ARE picked
	sess.mu.Lock()
	sess.pendingFrames = []queuedFrame{
		{encoded: f1, typeCode: frame.Data, streamID: 1, cost: len(f1)},
		{encoded: fc, typeCode: frame.Close, streamID: 1, cost: len(fc)},
		{encoded: f2, typeCode: frame.Window, streamID: 2, cost: len(f2)},
		{encoded: f3, typeCode: frame.Data, streamID: 2, cost: len(f3)},
	}
	// maxBytes = 4000: f1 (64K) doesn't fit; fc (stream 1) must be blocked; f2 and f3 (stream 2) must be picked
	batch = sess.takeDownBatchLimitLocked(4000)
	remCount = len(sess.pendingFrames)
	sess.mu.Unlock()

	frames, err = frame.ParseAll(batch.body, frame.MaxPayload)
	if err != nil {
		t.Fatalf("failed to parse batch: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames from stream 2, got %d", len(frames))
	}
	if frames[0].Type != frame.Window || frames[0].StreamID != 2 {
		t.Fatalf("expected frame 0 to be WINDOW (stream 2), got %v", frames[0])
	}
	if frames[1].Type != frame.Data || frames[1].StreamID != 2 {
		t.Fatalf("expected frame 1 to be DATA (stream 2), got %v", frames[1])
	}
	if remCount != 2 {
		t.Fatalf("expected stream 1's DATA and CLOSE to remain queued, got %d", remCount)
	}
}

func TestSession_ParallelStreamWorkers(t *testing.T) {
	configuration := testConfig("127.0.0.1:1")
	configuration.Profiles[0].CarrierMode = config.CarrierCDNAdaptive
	configuration.Limits.CDNMaxDownBatchBytes = 524288 // 512 KiB
	sess := newSession(sessionOptions{
		profile:  &configuration.Profiles[0],
		limits:   configuration.Limits,
		timeouts: configuration.Timeouts,
	})
	defer sess.Close()

	// 1. Single worker test: can consume batch > 128 KiB
	sess.mu.Lock()
	for i := 0; i < 4; i++ {
		f := frame.Encode(frame.Data, uint32(i+1), make([]byte, 64*1024))
		sess.pendingFrames = append(sess.pendingFrames, queuedFrame{
			encoded:  f,
			typeCode: frame.Data,
			streamID: uint32(i + 1),
			cost:     len(f),
		})
	}
	sess.mu.Unlock()

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	singleBatchReceived := make(chan int, 1)
	go func() {
		_ = sess.StreamCDN(ctx1, 0, func(cur uint64, body []byte) error {
			singleBatchReceived <- len(body)
			return nil
		})
	}()

	select {
	case size := <-singleBatchReceived:
		if size <= 131072 {
			t.Fatalf("expected single worker batch > 128 KiB, got %d", size)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for single worker batch")
	}
	cancel1()
	time.Sleep(30 * time.Millisecond)

	// 2. Multi-worker test: each batch MUST be capped at 131072 bytes (128 KiB)
	sess2 := newSession(sessionOptions{
		profile:  &configuration.Profiles[0],
		limits:   configuration.Limits,
		timeouts: configuration.Timeouts,
	})
	defer sess2.Close()

	ctxWorkers, cancelWorkers := context.WithCancel(context.Background())
	defer cancelWorkers()

	var maxObservedBatch int64
	var mu sync.Mutex
	recordBatch := func(size int) {
		mu.Lock()
		defer mu.Unlock()
		if int64(size) > maxObservedBatch {
			maxObservedBatch = int64(size)
		}
	}

	workerDone := make(chan struct{}, 2)
	for w := 0; w < 2; w++ {
		go func() {
			_ = sess2.StreamCDN(ctxWorkers, 0, func(cur uint64, body []byte) error {
				recordBatch(len(body))
				return nil
			})
			workerDone <- struct{}{}
		}()
	}

	// Wait until both workers are registered in s.streamWorkers
	regDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(regDeadline) {
		sess2.mu.Lock()
		wCount := len(sess2.streamWorkers)
		sess2.mu.Unlock()
		if wCount == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Queue 8 frames of 64 KiB each and wake up workers
	sess2.mu.Lock()
	for i := 0; i < 8; i++ {
		f := frame.Encode(frame.Data, uint32(i+1), make([]byte, 64*1024))
		sess2.pendingFrames = append(sess2.pendingFrames, queuedFrame{
			encoded:  f,
			typeCode: frame.Data,
			streamID: uint32(i + 1),
			cost:     len(f),
		})
	}
	signal(sess2.notify)
	sess2.mu.Unlock()

	time.Sleep(100 * time.Millisecond)
	cancelWorkers()

	for w := 0; w < 2; w++ {
		select {
		case <-workerDone:
		case <-time.After(2 * time.Second):
			t.Fatal("worker did not exit cleanly")
		}
	}

	mu.Lock()
	observed := maxObservedBatch
	mu.Unlock()

	if observed == 0 {
		t.Fatal("no batches observed by parallel workers")
	}
	if observed > 131072 {
		t.Fatalf("expected parallel worker batch <= 131072 bytes, got %d", observed)
	}

	sess2.mu.Lock()
	workersCount := len(sess2.streamWorkers)
	sess2.mu.Unlock()
	if workersCount != 0 {
		t.Fatalf("expected 0 active streamWorkers after cancellation, got %d", workersCount)
	}
}
