package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"time"

	"github.com/telegramdesktop/tproxy-server/internal/config"
	"github.com/telegramdesktop/tproxy-server/internal/frame"
)

func (s *Session) ReleaseWebSocket() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.websocketActive = false
	s.lastActivity = time.Now()
}

func (s *Session) AcquireWebSocketTakeover() (chan struct{}, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.carrier != config.CarrierWebSocket {
		return nil, false
	}
	if s.websocketActive && s.wsSuperseded != nil {
		select {
		case <-s.wsSuperseded:
		default:
			close(s.wsSuperseded)
		}
	}
	s.wsSuperseded = make(chan struct{})
	s.websocketActive = true
	s.lastActivity = time.Now()
	return s.wsSuperseded, true
}

func (s *Session) AcquireWebSocket() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.carrier != config.CarrierWebSocket || s.websocketActive {
		return false
	}
	s.websocketActive = true
	return true
}

func (s *Session) Resume(upSeq, downCursor uint64) (serverUpSeq, serverDownCursor uint64, replay []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, 0, nil, ErrClosed
	}
	s.lastActivity = time.Now()
	if len(s.unackedBatches) != 0 {
		s.ackCursorLocked(downCursor)
		if len(s.unackedBatches) != 0 {
			replay = s.unackedBatches[0].body
		}
		serverDownCursor = s.downCursor
	} else if len(s.unacked) != 0 {
		if downCursor == s.unackedBase {
			replay = s.unacked
			serverDownCursor = s.downCursor
		} else if downCursor == s.downCursor {
			s.releasePendingLocked(s.unackedCost, s.unackedItems)
			s.unacked = nil
			s.unackedCost = 0
			s.unackedItems = 0
			serverDownCursor = s.downCursor
		} else if downCursor == 0 {
			if s.unackedBase == 0 {
				replay = s.unacked
			}
			serverDownCursor = s.downCursor
		} else {
			return 0, 0, nil, ErrProtocol
		}
	} else {
		if downCursor == s.downCursor || downCursor == 0 {
			serverDownCursor = s.downCursor
		} else {
			return 0, 0, nil, ErrProtocol
		}
	}
	serverUpSeq = s.lastUpSequence + 1
	return serverUpSeq, serverDownCursor, replay, nil
}

func (s *Session) ProcessUp(sequence uint64, body []byte) (uint64, error) {
	if s.usesCarrierLanes() {
		return 0, ErrProtocol
	}
	digest := sha256.Sum256(body)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, ErrClosed
	}
	s.lastActivity = time.Now()
	if sequence == s.lastUpSequence && sequence != 0 {
		match := bytes.Equal(digest[:], s.lastUpDigest[:])
		s.mu.Unlock()
		if !match {
			s.protocolFailure()
			return 0, ErrProtocol
		}
		return sequence, nil
	}
	if sequence != s.lastUpSequence+1 || sequence == 0 {
		s.mu.Unlock()
		s.protocolFailure()
		return 0, ErrProtocol
	}
	if s.upActive {
		s.mu.Unlock()
		return 0, ErrConcurrent
	}
	s.upActive = true
	s.mu.Unlock()

	frames, err := frame.ParseAll(body, s.limits.MaxFramePayload)
	if err == nil {
		for _, value := range frames {
			if shapeErr := frame.ValidateClientShape(value); shapeErr != nil {
				err = shapeErr
				break
			}
		}
	}

	s.mu.Lock()
	s.upActive = false
	if s.closed {
		s.mu.Unlock()
		return 0, ErrClosed
	}
	if err != nil || !s.validateBatchLocked(frames) {
		s.mu.Unlock()
		s.protocolFailure()
		return 0, ErrProtocol
	}
	reservedCost, reservedItems := s.backendWriteReservationLocked(frames)
	if (reservedCost != 0 || reservedItems != 0) &&
		!s.reservePendingLocked(reservedCost, reservedItems, pendingUplink) {
		s.mu.Unlock()
		return 0, ErrBackpressure
	}
	opened, closed, unusedCost, unusedItems, applied := s.applyBatchLocked(
		frames,
		reservedCost,
		reservedItems)
	if unusedCost != 0 || unusedItems != 0 {
		s.releasePendingLocked(unusedCost, unusedItems)
	}
	s.backendWG.Add(len(opened))
	if applied {
		s.lastUpSequence = sequence
		s.lastUpDigest = digest
	}
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
		s.onUp(len(body))
	}
	return sequence, nil
}

func (s *Session) Poll(ctx context.Context, cursor uint64) ([]byte, uint64, error) {
	if s.usesCarrierLanes() {
		return nil, cursor, ErrProtocol
	}
	deadline := time.NewTimer(s.timeouts.LongPoll.Value())
	defer deadline.Stop()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, cursor, ErrClosed
	}
	s.lastActivity = time.Now()
	if len(s.unacked) != 0 {
		if cursor == s.unackedBase {
			result := s.unacked
			next := s.downCursor
			s.mu.Unlock()
			return result, next, nil
		}
		if cursor != s.downCursor {
			s.mu.Unlock()
			s.protocolFailure()
			return nil, cursor, ErrProtocol
		}
		s.releasePendingLocked(s.unackedCost, s.unackedItems)
		s.unacked = nil
		s.unackedCost = 0
		s.unackedItems = 0
	} else if cursor != s.downCursor {
		s.mu.Unlock()
		s.protocolFailure()
		return nil, cursor, ErrProtocol
	}
	if s.downActive && s.superseded != nil {
		close(s.superseded)
	}
	mine := make(chan struct{})
	s.superseded = mine
	s.downActive = true
	for {
		if s.superseded != mine {
			s.mu.Unlock()
			return nil, cursor, nil
		}
		if len(s.pendingFrames) != 0 {
			batch := s.takeDownBatchLocked()
			s.downCursor++
			s.unackedBase = cursor
			s.unacked = batch.body
			s.unackedCost = batch.cost
			s.unackedItems = batch.items
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
				continue
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

func (s *Session) takeDownBatchLocked() downBatch {
	size := 0
	cost := 0
	count := 0
	for count < len(s.pendingFrames) && count < frame.MaxBatchFrames {
		next := len(s.pendingFrames[count].encoded)
		if count != 0 && size+next > s.limits.CarrierBatchBytes {
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
