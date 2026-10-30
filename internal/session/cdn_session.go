package session

import (
	"context"
	"errors"
	"time"

	"github.com/telegramdesktop/tproxy-server/internal/config"
	"github.com/telegramdesktop/tproxy-server/internal/frame"
)

type sentBatch struct {
	cursor uint64
	body   []byte
	cost   int
	items  int
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
	s.lastActivity = time.Now()

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

	// 4. If PollCDN or StreamCDN is currently active, leave frames for the dedicated downlink poll.
	if s.downActive {
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
		for !s.hasPendingDataOrCloseLocked() && !s.closed && !s.downActive {
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
		if cursor != s.downCursor || len(s.unackedBatches) != 0 || len(s.unacked) != 0 || s.downActive {
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
		// If retry of an unacknowledged batch
		for _, b := range s.unackedBatches {
			if b.cursor > cursor {
				result := b.body
				next := b.cursor
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

	if s.downActive && s.superseded != nil {
		close(s.superseded)
	}
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

// StreamCDN streams downlink frames continuously using binary stream envelopes.
// It performs zero-loss replay for unacknowledged batches, handles periodic heartbeats,
// and bounds unacknowledged memory via sliding window backpressure.
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
	s.lastActivity = time.Now()

	s.ackCursorLocked(startCursor)

	if s.downActive && s.superseded != nil {
		close(s.superseded)
	}
	mine := make(chan struct{})
	s.superseded = mine
	s.downActive = true

	defer func() {
		s.mu.Lock()
		if s.superseded == mine {
			s.downActive = false
			s.superseded = nil
		}
		s.mu.Unlock()
	}()

	// 1. Zero-Loss Replay for any remaining unacknowledged batches with cursor > startCursor
	var toReplay []sentBatch
	for _, b := range s.unackedBatches {
		if b.cursor > startCursor {
			toReplay = append(toReplay, b)
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
		if s.superseded != mine {
			s.mu.Unlock()
			return nil
		}

		// Backpressure check: don't take new frames if unacked queue is full or unackedCost >= 4 MiB
		if len(s.pendingFrames) > 0 && len(s.unackedBatches) < maxUnacked && s.unackedCost < 4*1024*1024 {
			batch := s.takeDownBatchLimitLocked(maxBatch)
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
			}
			s.unackedBatches = append(s.unackedBatches, sb)
			cur := s.downCursor
			body := batch.body
			s.lastActivity = time.Now()
			if s.onDown != nil {
				s.onDown(len(body))
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
			if s.superseded != mine {
				s.mu.Unlock()
				return nil
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

func (s *Session) takeDownBatchLimitLocked(maxBytes int) downBatch {
	size := 0
	cost := 0
	count := 0
	for count < len(s.pendingFrames) && count < frame.MaxBatchFrames {
		next := len(s.pendingFrames[count].encoded)
		if count != 0 && size+next > maxBytes {
			break
		}
		size += next
		cost += s.pendingFrames[count].cost
		count++
	}
	result := make([]byte, 0, size)
	for index := 0; index != count; index++ {
		if s.pendingFrames[index].typeCode == frame.Window &&
			s.pendingWindows[s.pendingFrames[index].streamID] == index {
			delete(s.pendingWindows, s.pendingFrames[index].streamID)
		}
		result = append(result, s.pendingFrames[index].encoded...)
		s.pendingFrames[index] = queuedFrame{}
	}
	s.pendingFrames = s.pendingFrames[count:]
	for id, index := range s.pendingWindows {
		s.pendingWindows[id] = index - count
	}
	if len(s.pendingFrames) == 0 {
		s.pendingFrames = nil
	}
	return downBatch{body: result, cost: cost, items: count}
}
