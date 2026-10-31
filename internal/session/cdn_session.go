package session

import (
	"context"
	"errors"
	"time"

	"github.com/telegramdesktop/tproxy-server/internal/config"
	"github.com/telegramdesktop/tproxy-server/internal/frame"
)

const (
	maxParallelCDNStreams = 4
	multiStreamBatchBytes = 131072 // 128 KiB per envelope when striping across multiple streams
	interactiveDataLimit  = 4096   // <= 4 KiB DATA frames get priority ahead of bulk video chunks
	staleUnackedReplayAge = 600 * time.Millisecond
)

type sentBatch struct {
	cursor uint64
	body   []byte
	cost   int
	items  int
	sentAt time.Time
}

// AckDownCDN acknowledges client received bytes up to cursor.
func (s *Session) AckDownCDN(cursor uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if uint64(cursor) > s.downCursor {
		s.protocolFailure()
		return ErrProtocol
	}
	s.lastActivity = time.Now()
	s.ackCursorLocked(uint64(cursor))
	return nil
}

// ProcessUpCDN processes a numbered uplink chunk for CDN carriers using ReassemblyBuffer.
// Returns readyFramesCount (number of complete frames applied), or an error.
func (s *Session) ProcessUpCDN(sequence uint64, chunk []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, ErrClosed
	}
	s.lastActivity = time.Now()

	var frames []frame.Frame
	// If there were deferred frames from a previous backpressure event, apply them first
	if len(s.cdnPendingFrames) != 0 {
		frames = s.cdnPendingFrames
	}

	if s.cdnReassembly == nil {
		windowSize := uint64(s.limits.CDNUplinkWindowSize)
		if windowSize == 0 {
			windowSize = 64
		}
		s.cdnReassembly = NewReassemblyBuffer(windowSize, s.limits.MaxFramePayload)
	}

	pushedFrames, _, err := s.cdnReassembly.Push(sequence, chunk)
	if err != nil {
		if !errors.Is(err, ErrLimit) {
			s.protocolFailure()
		}
		s.mu.Unlock()
		return 0, err
	}
	if len(pushedFrames) != 0 {
		frames = append(frames, pushedFrames...)
	}
	if len(frames) == 0 {
		s.mu.Unlock()
		return 0, nil
	}

	if !s.validateBatchLocked(frames) {
		s.mu.Unlock()
		s.protocolFailure()
		return 0, ErrProtocol
	}
	reservedCost, reservedItems := s.backendWriteReservationLocked(frames)
	if (reservedCost != 0 || reservedItems != 0) &&
		!s.reservePendingLocked(reservedCost, reservedItems, pendingUplink) {
		s.cdnPendingFrames = frames
		s.mu.Unlock()
		return 0, ErrBackpressure
	}
	s.cdnPendingFrames = nil
	opened, closed, unusedCost, unusedItems, applied := s.applyBatchLocked(
		frames,
		reservedCost,
		reservedItems)
	if unusedCost != 0 || unusedItems != 0 {
		s.releasePendingLocked(unusedCost, unusedItems)
	}
	s.backendWG.Add(len(opened))
	s.mu.Unlock()

	for _, value := range closed {
		value.close()
	}
	for _, value := range opened {
		go s.runBackend(value)
	}
	if !applied {
		s.Close()
		return 0, ErrClosed
	}
	if s.onUp != nil {
		s.onUp(len(chunk))
	}
	return len(frames), nil
}

// PiggybackDown attempts a non-blocking harvest of available downlink frames to bundle
// in an uplink response.
func (s *Session) PiggybackDown(cursor uint64) ([]byte, uint64, error) {
	return s.PiggybackDownWait(cursor, false)
}

func (s *Session) ackCursorLocked(ackCursor uint64) {
	if ackCursor > s.downCursor {
		return
	}
	freedCount := 0
	freedCost := 0
	freedItems := 0
	for i := 0; i < len(s.unackedBatches); i++ {
		if s.unackedBatches[i].cursor <= ackCursor {
			freedCost += s.unackedBatches[i].cost
			freedItems += s.unackedBatches[i].items
			s.unackedBatches[i] = sentBatch{} // Clear slice reference for GC
			freedCount++
		} else {
			break
		}
	}
	if freedCount > 0 {
		s.releasePendingLocked(freedCost, freedItems)
		s.unackedBatches = s.unackedBatches[freedCount:]
		if len(s.unackedBatches) == 0 {
			s.unackedBatches = nil
		}
		s.unackedCost -= freedCost
		s.unackedItems -= freedItems
		if s.unackedCost < 0 {
			s.unackedCost = 0
		}
		if s.unackedItems < 0 {
			s.unackedItems = 0
		}
		if len(s.pendingFrames) > 0 {
			signal(s.notify)
		}
	}
	if len(s.unackedBatches) > 0 {
		s.unacked = s.unackedBatches[0].body
		s.unackedBase = s.unackedBatches[0].cursor - 1
	} else {
		if len(s.unacked) != 0 && (ackCursor == s.downCursor || ackCursor == s.unackedBase+1) {
			s.releasePendingLocked(s.unackedCost, s.unackedItems)
			s.unacked = nil
			s.unackedCost = 0
			s.unackedItems = 0
			if len(s.pendingFrames) > 0 {
				signal(s.notify)
			}
		} else if len(s.unacked) == 0 {
			s.unackedCost = 0
			s.unackedItems = 0
		}
	}
}

// PiggybackDownWait attempts a harvest of downlink frames, optionally micro-waiting
// if coalesce is true, no poll/stream is active, and no frames are immediately available.
func (s *Session) PiggybackDownWait(cursor uint64, coalesce bool) ([]byte, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, cursor, ErrClosed
	}
	now := time.Now()
	s.lastActivity = now

	// 1. Future cursor is an invariant violation.
	if cursor > s.downCursor {
		s.closeLocked()
		return nil, cursor, ErrProtocol
	}

	// 2. Client acknowledges current unacked batch(es).
	s.ackCursorLocked(cursor)

	// 3. Stale cursor from a concurrent in-flight request, or unacked batch still in flight.
	// Do not duplicate traffic; client will receive via stream, long-poll or next request.
	if cursor < s.downCursor || len(s.unackedBatches) != 0 || len(s.unacked) != 0 {
		return nil, s.downCursor, nil
	}

	// 4. If PollCDN or StreamCDN is currently active, leave frames for the dedicated downlink poll/stream.
	if s.downActive || len(s.streamWorkers) > 0 {
		return nil, s.downCursor, nil
	}

	// 5. Adaptive micro-wait when requested by client and no poll is active:
	// wait for backend DATA/CLOSE frame to bundle with WINDOW ack.
	// For direct backend, TCP dial + MTProto resPQ takes ~30-100ms.
	if coalesce && !s.hasPendingDataOrCloseLocked() && (s.cdnReassembly == nil || !s.cdnReassembly.HasHoles()) {
		waitDur := 40 * time.Millisecond
		if s.profile != nil && s.profile.BackendType == config.BackendDirect {
			waitDur = 150 * time.Millisecond
		}
		deadline := time.Now().Add(waitDur)
		for !s.hasPendingDataOrCloseLocked() && !s.closed && !s.downActive && len(s.streamWorkers) == 0 {
			rem := time.Until(deadline)
			if rem <= 0 {
				break
			}
			notify := s.notify
			done := s.done
			s.mu.Unlock()
			select {
			case <-notify:
			case <-time.After(rem):
			case <-done:
			}
			s.mu.Lock()
		}
		if s.closed {
			return nil, cursor, ErrClosed
		}
		if cursor != s.downCursor || len(s.unackedBatches) != 0 || len(s.unacked) != 0 || s.downActive || len(s.streamWorkers) > 0 {
			return nil, s.downCursor, nil
		}
	}

	// Do not waste a downlink batch & cursor increment on a tiny standalone WINDOW frame
	// during piggybacking unless significant window credit (>64 KiB) is being returned.
	if !s.hasWorthwhilePiggybackLocked() {
		return nil, s.downCursor, nil
	}

	maxBatch := s.limits.CDNMaxDownBatchBytes
	if maxBatch <= 0 {
		maxBatch = 524288
	}
	batch := s.takeDownBatchLimitLocked(maxBatch)
	s.downCursor++
	s.unackedBase = cursor
	s.unacked = batch.body
	s.unackedCost += batch.cost
	s.unackedItems += batch.items
	s.unackedBatches = append(s.unackedBatches, sentBatch{
		cursor: s.downCursor,
		body:   batch.body,
		cost:   batch.cost,
		items:  batch.items,
		sentAt: time.Now(),
	})
	next := s.downCursor
	if s.onDown != nil {
		s.onDown(len(batch.body))
	}
	return batch.body, next, nil
}

// PollCDN waits for downlink frames up to timeout duration for CDN carriers.
func (s *Session) PollCDN(ctx context.Context, cursor uint64, timeout time.Duration) ([]byte, uint64, error) {
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, cursor, ErrClosed
	}
	s.lastActivity = time.Now()

	if cursor > s.downCursor {
		s.mu.Unlock()
		s.protocolFailure()
		return nil, cursor, ErrProtocol
	}

	s.ackCursorLocked(cursor)

	if cursor < s.downCursor {
		// If retry of an unacknowledged batch (or gap healing request from multi-stream client)
		for i := range s.unackedBatches {
			if s.unackedBatches[i].cursor > cursor {
				s.unackedBatches[i].sentAt = time.Now()
				result := s.unackedBatches[i].body
				next := s.unackedBatches[i].cursor
				s.mu.Unlock()
				return result, next, nil
			}
		}
		if len(s.unacked) != 0 && cursor == s.unackedBase {
			result := s.unacked
			next := s.downCursor
			s.mu.Unlock()
			return result, next, nil
		}
		// Otherwise this cursor was already acknowledged by a concurrent request.
		// Return empty with current downCursor.
		next := s.downCursor
		s.mu.Unlock()
		return nil, next, nil
	}

	// Evict any active PollCDN or StreamCDN workers when falling back to PollCDN
	if s.downActive && s.superseded != nil {
		close(s.superseded)
		s.superseded = nil
	}
	for _, ch := range s.streamWorkers {
		close(ch)
	}
	s.streamWorkers = nil

	mine := make(chan struct{})
	s.superseded = mine
	s.downActive = true

	maxBatch := s.limits.CDNMaxDownBatchBytes
	if maxBatch <= 0 {
		maxBatch = 524288
	}

	for {
		if s.superseded != mine {
			s.mu.Unlock()
			return nil, cursor, nil
		}
		if s.hasWorthwhilePiggybackLocked() {
			batch := s.takeDownBatchLimitLocked(maxBatch)
			s.downCursor++
			s.unackedBase = cursor
			s.unacked = batch.body
			s.unackedCost += batch.cost
			s.unackedItems += batch.items
			s.unackedBatches = append(s.unackedBatches, sentBatch{
				cursor: s.downCursor,
				body:   batch.body,
				cost:   batch.cost,
				items:  batch.items,
				sentAt: time.Now(),
			})
			s.downActive = false
			s.superseded = nil
			next := s.downCursor
			s.mu.Unlock()
			if s.onDown != nil {
				s.onDown(len(batch.body))
			}
			return batch.body, next, nil
		}
		if s.closed {
			s.downActive = false
			s.superseded = nil
			s.mu.Unlock()
			return nil, cursor, ErrClosed
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			s.mu.Lock()
			if s.superseded == mine {
				s.downActive = false
				s.superseded = nil
			}
			s.mu.Unlock()
			return nil, cursor, ctx.Err()
		case <-mine:
			s.mu.Lock()
			signal(s.notify)
			s.mu.Unlock()
			return nil, cursor, nil
		case <-deadline.C:
			s.mu.Lock()
			if s.superseded != mine {
				signal(s.notify)
				s.mu.Unlock()
				return nil, cursor, nil
			}
			if len(s.pendingFrames) != 0 {
				batch := s.takeDownBatchLimitLocked(maxBatch)
				s.downCursor++
				s.unackedBase = cursor
				s.unacked = batch.body
				s.unackedCost += batch.cost
				s.unackedItems += batch.items
				s.unackedBatches = append(s.unackedBatches, sentBatch{
					cursor: s.downCursor,
					body:   batch.body,
					cost:   batch.cost,
					items:  batch.items,
					sentAt: time.Now(),
				})
				s.downActive = false
				s.superseded = nil
				next := s.downCursor
				s.mu.Unlock()
				if s.onDown != nil {
					s.onDown(len(batch.body))
				}
				return batch.body, next, nil
			}
			s.downActive = false
			s.superseded = nil
			s.lastActivity = time.Now()
			s.mu.Unlock()
			return nil, cursor, nil
		case <-s.notify:
			s.mu.Lock()
			if s.superseded != mine {
				signal(s.notify)
			}
		}
	}
}

// removeStreamWorkerLocked removes a specific worker channel from s.streamWorkers.
func (s *Session) removeStreamWorkerLocked(mine chan struct{}) {
	for i, ch := range s.streamWorkers {
		if ch == mine {
			copy(s.streamWorkers[i:], s.streamWorkers[i+1:])
			s.streamWorkers[len(s.streamWorkers)-1] = nil
			s.streamWorkers = s.streamWorkers[:len(s.streamWorkers)-1]
			break
		}
	}
	if len(s.streamWorkers) == 0 && s.superseded == nil {
		s.downActive = false
	}
}

// StreamCDN streams downlink frames continuously using binary stream envelopes.
// Supports up to maxParallelCDNStreams concurrent stream workers per session
// for striped multi-stream throughput (especially effective for streaming video).
func (s *Session) StreamCDN(ctx context.Context, startCursor uint64, onBatch func(cursor uint64, body []byte) error) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	if startCursor > s.downCursor {
		s.mu.Unlock()
		s.protocolFailure()
		return ErrProtocol
	}
	now := time.Now()
	s.lastActivity = now

	s.ackCursorLocked(startCursor)

	// If a legacy single PollCDN was waiting, cancel it.
	if s.superseded != nil {
		close(s.superseded)
		s.superseded = nil
	}

	hadActiveWorkers := len(s.streamWorkers) > 0

	// If pool is full, evict the oldest stream worker (FIFO rotation / Make-Before-Break).
	if len(s.streamWorkers) >= maxParallelCDNStreams {
		oldest := s.streamWorkers[0]
		close(oldest)
		copy(s.streamWorkers[0:], s.streamWorkers[1:])
		s.streamWorkers[len(s.streamWorkers)-1] = nil
		s.streamWorkers = s.streamWorkers[:len(s.streamWorkers)-1]
	}

	mine := make(chan struct{})
	s.streamWorkers = append(s.streamWorkers, mine)
	s.downActive = true

	defer func() {
		s.mu.Lock()
		s.removeStreamWorkerLocked(mine)
		if len(s.pendingFrames) > 0 && len(s.streamWorkers) > 0 {
			signal(s.notify)
		}
		s.mu.Unlock()
	}()

	// 1. Zero-Loss Replay:
	// - If no other stream workers were active (!hadActiveWorkers), replay all unackedBatches > startCursor.
	// - If other stream workers ARE active, replay only stale unackedBatches (> 600ms old) so a dropped
	//   turbo-stream is automatically healed without duplicating fresh in-flight chunks on sibling streams.
	var toReplay []sentBatch
	if len(s.unackedBatches) > 0 {
		for i := range s.unackedBatches {
			b := &s.unackedBatches[i]
			if b.cursor > startCursor {
				if !hadActiveWorkers || b.sentAt.IsZero() || now.Sub(b.sentAt) >= staleUnackedReplayAge {
					b.sentAt = now
					toReplay = append(toReplay, *b)
				}
			}
		}
	}
	s.mu.Unlock()

	for _, b := range toReplay {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-mine:
			return nil
		default:
		}
		if err := onBatch(b.cursor, b.body); err != nil {
			return err
		}
		s.mu.Lock()
		s.lastActivity = time.Now()
		s.mu.Unlock()
	}

	s.mu.Lock()

	maxDuration := time.Duration(s.limits.CDNStreamMaxDurationSecs) * time.Second
	if maxDuration <= 0 {
		maxDuration = 45 * time.Second
	}
	heartbeatInterval := time.Duration(s.limits.CDNStreamHeartbeatSecs) * time.Second
	if heartbeatInterval <= 0 {
		heartbeatInterval = 10 * time.Second
	}
	maxUnacked := s.limits.CDNMaxUnackedBatches
	if maxUnacked <= 0 {
		maxUnacked = 32
	}
	maxBatch := s.limits.CDNMaxDownBatchBytes
	if maxBatch <= 0 {
		maxBatch = 524288
	}

	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()
	maxDur := time.NewTimer(maxDuration)
	defer maxDur.Stop()

	for {
		if s.closed {
			s.mu.Unlock()
			return ErrClosed
		}
		select {
		case <-mine:
			s.mu.Unlock()
			return nil
		default:
		}

		// Backpressure check: don't take new frames if unacked queue is full or unackedCost >= 4 MiB
		if len(s.pendingFrames) > 0 && len(s.unackedBatches) < maxUnacked && s.unackedCost < 4*1024*1024 {
			// Adaptive batch striping: when multiple stream workers are active in parallel,
			// cap each batch at 128 KiB so chunks are striped evenly across all parallel CDN streams.
			effectiveMaxBatch := maxBatch
			if len(s.streamWorkers) > 1 && effectiveMaxBatch > multiStreamBatchBytes {
				effectiveMaxBatch = multiStreamBatchBytes
			}

			batch := s.takeDownBatchLimitLocked(effectiveMaxBatch)
			sentTime := time.Now()
			s.downCursor++
			s.unackedBase = s.downCursor - 1
			s.unacked = batch.body
			s.unackedCost += batch.cost
			s.unackedItems += batch.items
			sb := sentBatch{
				cursor: s.downCursor,
				body:   batch.body,
				cost:   batch.cost,
				items:  batch.items,
				sentAt: sentTime,
			}
			s.unackedBatches = append(s.unackedBatches, sb)
			cur := s.downCursor
			body := batch.body
			s.lastActivity = sentTime
			if s.onDown != nil {
				s.onDown(len(body))
			}

			// Cascade wake-up: if more frames remain and sibling stream workers are open,
			// immediately wake the next worker so it flushes the next video chunk in parallel!
			if len(s.pendingFrames) > 0 && len(s.streamWorkers) > 1 {
				signal(s.notify)
			}
			s.mu.Unlock()

			if err := onBatch(cur, body); err != nil {
				return err
			}

			s.mu.Lock()
			continue
		}

		notify := s.notify
		done := s.done
		s.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-mine:
			return nil
		case <-done:
			return ErrClosed
		case <-maxDur.C:
			return nil
		case <-heartbeat.C:
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				return ErrClosed
			}
			select {
			case <-mine:
				s.mu.Unlock()
				return nil
			default:
			}
			cur := s.downCursor
			s.lastActivity = time.Now()
			s.mu.Unlock()

			if err := onBatch(cur, nil); err != nil {
				return err
			}
			s.mu.Lock()
		case <-notify:
			s.mu.Lock()
			// If woken up and even more frames exist for another worker, keep the signal alive
			if len(s.pendingFrames) > 0 && len(s.streamWorkers) > 1 {
				signal(s.notify)
			}
		}
	}
}

func (s *Session) hasPendingDataLocked() bool {
	for i := range s.pendingFrames {
		if s.pendingFrames[i].typeCode == frame.Data {
			return true
		}
	}
	return false
}

func (s *Session) hasPendingDataOrCloseLocked() bool {
	for i := range s.pendingFrames {
		if s.pendingFrames[i].typeCode == frame.Data || s.pendingFrames[i].typeCode == frame.Close {
			return true
		}
	}
	return false
}

func (s *Session) hasWorthwhilePiggybackLocked() bool {
	if len(s.pendingFrames) == 0 {
		return false
	}
	for i := range s.pendingFrames {
		if s.pendingFrames[i].typeCode != frame.Window {
			return true
		}
		if len(s.pendingFrames[i].encoded) >= frame.HeaderSize+4 {
			if amount, err := frame.WindowAmount(s.pendingFrames[i].encoded[frame.HeaderSize : frame.HeaderSize+4]); err == nil && amount >= 65536 {
				return true
			}
		}
	}
	return false
}

// takeDownBatchLimitLocked extracts up to maxBytes of frames.
// When bulk media DATA frames are queued, it prioritizes control frames (OPEN, WINDOW, CLOSE)
// and small interactive DATA frames (<= 4 KiB) from other streams so chat/UI traffic
// never suffers Head-of-Line blocking behind heavy video chunks, while strictly preserving
// per-stream frame ordering.
func (s *Session) takeDownBatchLimitLocked(maxBytes int) downBatch {
	n := len(s.pendingFrames)
	if n == 0 {
		return downBatch{}
	}

	// Fast path: check if all pending frames fit in maxBytes and frame.MaxBatchFrames
	totalSize := 0
	totalCost := 0
	allFit := n <= frame.MaxBatchFrames
	if allFit {
		for i := 0; i < n; i++ {
			totalSize += len(s.pendingFrames[i].encoded)
			totalCost += s.pendingFrames[i].cost
			if i != 0 && totalSize > maxBytes {
				allFit = false
				break
			}
		}
	}
	if allFit {
		result := make([]byte, 0, totalSize)
		for i := 0; i < n; i++ {
			result = append(result, s.pendingFrames[i].encoded...)
			s.pendingFrames[i] = queuedFrame{}
		}
		s.pendingFrames = nil
		clear(s.pendingWindows)
		return downBatch{body: result, cost: totalCost, items: n}
	}

	// Priority-aware selection preserving per-stream FIFO ordering:
	// Pass 1 picks control frames (WINDOW, OPEN) and small interactive frames from streams
	// that haven't had a frame skipped yet.
	// Pass 2 fills the remaining budget in normal FIFO order.
	picked := make([]bool, n)
	blockedStream := make(map[uint32]bool)
	size := 0
	cost := 0
	count := 0

	// Pass 1: VIP Control & Interactive frames
	for i := 0; i < n && count < frame.MaxBatchFrames; i++ {
		f := &s.pendingFrames[i]
		isVIP := f.typeCode == frame.Window || f.typeCode == frame.Open ||
			(f.typeCode == frame.Close && !blockedStream[f.streamID]) ||
			(f.typeCode == frame.Data && len(f.encoded) <= frame.HeaderSize+interactiveDataLimit && !blockedStream[f.streamID])

		if isVIP {
			fLen := len(f.encoded)
			if count == 0 || size+fLen <= maxBytes {
				picked[i] = true
				size += fLen
				cost += f.cost
				count++
				continue
			}
		}
		if f.typeCode == frame.Data || f.typeCode == frame.Close {
			blockedStream[f.streamID] = true
		}
	}

	// Pass 2: Bulk Media & Remaining frames in FIFO order
	for i := 0; i < n && count < frame.MaxBatchFrames; i++ {
		if picked[i] {
			continue
		}
		f := &s.pendingFrames[i]
		fLen := len(f.encoded)
		if count != 0 && size+fLen > maxBytes {
			break
		}
		picked[i] = true
		size += fLen
		cost += f.cost
		count++
	}

	result := make([]byte, 0, size)
	writeIdx := 0
	clear(s.pendingWindows)

	for i := 0; i < n; i++ {
		if picked[i] {
			result = append(result, s.pendingFrames[i].encoded...)
		} else {
			s.pendingFrames[writeIdx] = s.pendingFrames[i]
			if s.pendingFrames[writeIdx].typeCode == frame.Window {
				s.pendingWindows[s.pendingFrames[writeIdx].streamID] = writeIdx
			}
			writeIdx++
		}
	}
	for i := writeIdx; i < n; i++ {
		s.pendingFrames[i] = queuedFrame{}
	}
	s.pendingFrames = s.pendingFrames[:writeIdx]
	if len(s.pendingFrames) == 0 {
		s.pendingFrames = nil
	}

	return downBatch{body: result, cost: cost, items: count}
}
