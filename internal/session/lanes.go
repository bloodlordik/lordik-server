package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"time"

	"github.com/telegramdesktop/tproxy-server/internal/config"
	"github.com/telegramdesktop/tproxy-server/internal/frame"
)

type carrierLane struct {
	lastUpSequence  uint64
	lastUpDigest    [sha256.Size]byte
	upActive        bool
	websocketActive bool
	pendingFrames   []queuedFrame
	pendingWindows  map[uint32]int
	unacked         []byte
	unackedCost     int
	unackedItems    int
	unackedBase     uint64
	downCursor      uint64
	downActive      bool
	superseded      chan struct{}
	wsSuperseded    chan struct{}
	notify          chan struct{}
}

func newCarrierLane() *carrierLane {
	return &carrierLane{
		pendingWindows: make(map[uint32]int),
		notify:         make(chan struct{}, 1),
	}
}

func (s *Session) usesCarrierLanes() bool {
	return s.carrier == config.CarrierHTTPSLanes ||
		s.carrier == config.CarrierWebSocketLanes
}

func (s *Session) ReleaseWebSocketLaneGraceful(laneID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.carrier != config.CarrierWebSocketLanes {
		return
	}
	lane := s.carrierLanes[laneID]
	if lane == nil {
		return
	}
	lane.websocketActive = false
	s.lastActivity = time.Now()
}

func (s *Session) AcquireWebSocketLaneTakeover(laneID uint32) (chan struct{}, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed ||
		s.carrier != config.CarrierWebSocketLanes ||
		laneID == 0 ||
		laneID > frame.MaxStreamID {
		return nil, false
	}
	if _, closed := s.closedStreams[laneID]; closed {
		return nil, false
	}
	lane := s.carrierLanes[laneID]
	if lane == nil {
		if len(s.carrierLanes) >= s.limits.MaxStreamsPerSession {
			return nil, false
		}
		lane = newCarrierLane()
		s.carrierLanes[laneID] = lane
	}
	if lane.websocketActive && lane.wsSuperseded != nil {
		select {
		case <-lane.wsSuperseded:
		default:
			close(lane.wsSuperseded)
		}
	}
	lane.wsSuperseded = make(chan struct{})
	lane.websocketActive = true
	s.lastActivity = time.Now()
	return lane.wsSuperseded, true
}

func (s *Session) AcquireWebSocketLane(laneID uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed ||
		s.carrier != config.CarrierWebSocketLanes ||
		laneID == 0 ||
		laneID > frame.MaxStreamID {
		return false
	}
	if _, closed := s.closedStreams[laneID]; closed {
		return false
	}
	lane := s.carrierLanes[laneID]
	if lane == nil {
		if len(s.carrierLanes) >= s.limits.MaxStreamsPerSession {
			return false
		}
		lane = newCarrierLane()
		s.carrierLanes[laneID] = lane
	}
	if lane.websocketActive {
		return false
	}
	lane.websocketActive = true
	s.lastActivity = time.Now()
	return true
}

func (s *Session) ReleaseWebSocketLane(laneID uint32) {
	var backend *backendStream
	s.mu.Lock()
	if s.carrier != config.CarrierWebSocketLanes {
		s.mu.Unlock()
		return
	}
	lane := s.carrierLanes[laneID]
	if lane == nil {
		s.mu.Unlock()
		return
	}
	lane.websocketActive = false
	if state := s.streams[laneID]; state != nil {
		s.releaseStreamWritesLocked(state)
		delete(s.streams, laneID)
		s.rememberClosedLocked(laneID)
		backend = state.backend
	}
	s.releaseLaneLocked(lane)
	delete(s.carrierLanes, laneID)
	s.lastActivity = time.Now()
	s.mu.Unlock()
	if backend != nil {
		backend.close()
	}
}

func (s *Session) laneProtocolFailure(laneID uint32) {
	if s.carrier == config.CarrierWebSocketLanes {
		s.ReleaseWebSocketLane(laneID)
	} else {
		s.protocolFailure()
	}
}

func (s *Session) releaseLaneLocked(lane *carrierLane) {
	cost := lane.unackedCost
	items := lane.unackedItems
	for i := range lane.pendingFrames {
		cost += lane.pendingFrames[i].cost
		items++
	}
	if cost != 0 || items != 0 {
		s.releasePendingLocked(cost, items)
	}
	lane.pendingFrames = nil
	lane.pendingWindows = nil
	lane.unacked = nil
	lane.unackedCost = 0
	lane.unackedItems = 0
	signal(lane.notify)
}

func (s *Session) ResumeLane(laneID uint32, upSeq, downCursor uint64) (serverUpSeq, serverDownCursor uint64, replay []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, 0, nil, ErrClosed
	}
	lane := s.carrierLanes[laneID]
	if lane == nil {
		return 0, 0, nil, ErrProtocol
	}
	s.lastActivity = time.Now()
	if len(lane.unacked) != 0 {
		if downCursor == lane.unackedBase {
			replay = lane.unacked
			serverDownCursor = lane.downCursor
		} else if downCursor == lane.downCursor {
			s.releasePendingLocked(lane.unackedCost, lane.unackedItems)
			lane.unacked = nil
			lane.unackedCost = 0
			lane.unackedItems = 0
			serverDownCursor = lane.downCursor
		} else if downCursor == 0 {
			if lane.unackedBase == 0 {
				replay = lane.unacked
			}
			serverDownCursor = lane.downCursor
		} else {
			return 0, 0, nil, ErrProtocol
		}
	} else {
		if downCursor == lane.downCursor || downCursor == 0 {
			serverDownCursor = lane.downCursor
		} else {
			return 0, 0, nil, ErrProtocol
		}
	}
	serverUpSeq = lane.lastUpSequence + 1
	return serverUpSeq, serverDownCursor, replay, nil
}

func (s *Session) ProcessUpLane(laneID uint32, sequence uint64, body []byte) (uint64, error) {
	if !s.usesCarrierLanes() || laneID > frame.MaxStreamID {
		return 0, ErrProtocol
	}
	digest := sha256.Sum256(body)
	frames, err := frame.ParseAll(body, s.limits.MaxFramePayload)
	if err == nil {
		for _, value := range frames {
			if shapeErr := frame.ValidateClientShape(value); shapeErr != nil || value.StreamID != laneID {
				err = ErrProtocol
				break
			}
		}
	}
	if err != nil {
		s.laneProtocolFailure(laneID)
		return 0, ErrProtocol
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, ErrClosed
	}
	lane := s.carrierLanes[laneID]
	if lane == nil {
		if laneID != 0 && len(frames) != 0 && frames[0].Type != frame.Open &&
			s.onlyLateFrames(frames) {
			s.lastActivity = time.Now()
			s.mu.Unlock()
			return sequence, nil
		}
		if laneID == 0 || len(frames) == 0 || frames[0].Type != frame.Open {
			s.mu.Unlock()
			s.laneProtocolFailure(laneID)
			return 0, ErrProtocol
		}
		lane = newCarrierLane()
		s.carrierLanes[laneID] = lane
	}
	s.lastActivity = time.Now()
	if sequence == lane.lastUpSequence && sequence != 0 {
		match := bytes.Equal(digest[:], lane.lastUpDigest[:])
		s.mu.Unlock()
		if !match {
			s.laneProtocolFailure(laneID)
			return 0, ErrProtocol
		}
		return sequence, nil
	}
	if sequence != lane.lastUpSequence+1 || sequence == 0 {
		s.mu.Unlock()
		s.laneProtocolFailure(laneID)
		return 0, ErrProtocol
	}
	if lane.upActive {
		s.mu.Unlock()
		return 0, ErrConcurrent
	}
	lane.upActive = true
	if !s.validateBatchLocked(frames) {
		lane.upActive = false
		s.mu.Unlock()
		s.laneProtocolFailure(laneID)
		return 0, ErrProtocol
	}
	reservedCost, reservedItems := s.backendWriteReservationLocked(frames)
	if (reservedCost != 0 || reservedItems != 0) &&
		!s.reservePendingLocked(reservedCost, reservedItems, pendingUplink) {
		lane.upActive = false
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
	lane.upActive = false
	if applied {
		lane.lastUpSequence = sequence
		lane.lastUpDigest = digest
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

func (s *Session) PollLane(ctx context.Context, laneID uint32, cursor uint64) ([]byte, uint64, bool, error) {
	if !s.usesCarrierLanes() || laneID > frame.MaxStreamID {
		return nil, cursor, false, ErrProtocol
	}
	deadline := time.NewTimer(s.timeouts.LongPoll.Value())
	defer deadline.Stop()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, cursor, false, ErrClosed
	}
	lane := s.carrierLanes[laneID]
	if lane == nil {
		s.mu.Unlock()
		return nil, cursor, false, ErrProtocol
	}
	s.lastActivity = time.Now()
	if len(lane.unacked) != 0 {
		if cursor == lane.unackedBase {
			result := lane.unacked
			next := lane.downCursor
			s.mu.Unlock()
			return result, next, false, nil
		}
		if cursor != lane.downCursor {
			s.mu.Unlock()
			s.laneProtocolFailure(laneID)
			return nil, cursor, false, ErrProtocol
		}
		s.releasePendingLocked(lane.unackedCost, lane.unackedItems)
		lane.unacked = nil
		lane.unackedCost = 0
		lane.unackedItems = 0
	} else if cursor != lane.downCursor {
		s.mu.Unlock()
		s.laneProtocolFailure(laneID)
		return nil, cursor, false, ErrProtocol
	}
	if lane.downActive && lane.superseded != nil {
		close(lane.superseded)
	}
	mine := make(chan struct{})
	lane.superseded = mine
	lane.downActive = true
	for {
		if lane.superseded != mine {
			s.mu.Unlock()
			return nil, cursor, false, nil
		}
		if len(lane.pendingFrames) != 0 {
			batch := s.takeLaneDownBatchLocked(lane)
			lane.downCursor++
			lane.unackedBase = cursor
			lane.unacked = batch.body
			lane.unackedCost = batch.cost
			lane.unackedItems = batch.items
			lane.downActive = false
			lane.superseded = nil
			next := lane.downCursor
			s.mu.Unlock()
			if s.onDown != nil {
				s.onDown(len(batch.body))
			}
			return batch.body, next, false, nil
		}
		if s.closed {
			lane.downActive = false
			lane.superseded = nil
			s.mu.Unlock()
			return nil, cursor, false, ErrClosed
		}
		if laneID != 0 {
			_, live := s.streams[laneID]
			_, closed := s.closedStreams[laneID]
			if !live && closed {
				lane.downActive = false
				lane.superseded = nil
				s.mu.Unlock()
				return nil, cursor, true, nil
			}
		}
		if s.carrierLanes[laneID] != lane {
			lane.downActive = false
			lane.superseded = nil
			s.mu.Unlock()
			return nil, cursor, true, nil
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			s.mu.Lock()
			if lane.superseded == mine {
				lane.downActive = false
				lane.superseded = nil
			}
			s.mu.Unlock()
			return nil, cursor, false, ctx.Err()
		case <-mine:
			s.mu.Lock()
			signal(lane.notify)
			s.mu.Unlock()
			return nil, cursor, false, nil
		case <-s.done:
			s.mu.Lock()
			if lane.superseded == mine {
				lane.downActive = false
				lane.superseded = nil
			}
			s.mu.Unlock()
			return nil, cursor, false, ErrClosed
		case <-deadline.C:
			s.mu.Lock()
			if lane.superseded != mine {
				signal(lane.notify)
				s.mu.Unlock()
				return nil, cursor, false, nil
			}
			if len(lane.pendingFrames) != 0 {
				continue
			}
			lane.downActive = false
			lane.superseded = nil
			s.lastActivity = time.Now()
			s.mu.Unlock()
			return nil, cursor, false, nil
		case <-lane.notify:
			s.mu.Lock()
			if lane.superseded != mine {
				signal(lane.notify)
			}
		}
	}
}

func (s *Session) queueLaneFrameLocked(t frame.Type, id uint32, payload []byte) bool {
	lane := s.carrierLanes[id]
	if lane == nil {
		return false
	}
	if t == frame.Window {
		if index, exists := lane.pendingWindows[id]; exists {
			queued := &lane.pendingFrames[index]
			previous, _ := frame.WindowAmount(
				queued.encoded[frame.HeaderSize:])
			amount, _ := frame.WindowAmount(payload)
			total := uint64(previous) + uint64(amount)
			if total <= math.MaxUint32 {
				binary.BigEndian.PutUint32(
					queued.encoded[frame.HeaderSize:],
					uint32(total))
				signal(lane.notify)
				return true
			}
		}
	}
	if len(lane.pendingFrames) != 0 {
		last := &lane.pendingFrames[len(lane.pendingFrames)-1]
		if last.typeCode == frame.Data && t == frame.Data && last.streamID == id && len(last.encoded)-frame.HeaderSize+len(payload) <= s.limits.MaxFramePayload {
			if !s.reservePendingLocked(
				len(payload),
				0,
				pendingDownlink) {
				return false
			}
			last.encoded = append(last.encoded, payload...)
			last.cost += len(payload)
			binary.BigEndian.PutUint32(last.encoded[4:8], uint32(len(last.encoded)-frame.HeaderSize))
			signal(lane.notify)
			return true
		}
	}
	encoded := frame.Encode(t, id, payload)
	cost := len(encoded) + queueItemCost
	class := pendingControl
	if t == frame.Data {
		class = pendingDownlink
	}
	if !s.reservePendingLocked(cost, 1, class) {
		return false
	}
	lane.pendingFrames = append(lane.pendingFrames, queuedFrame{
		encoded:  encoded,
		typeCode: t,
		streamID: id,
		cost:     cost,
	})
	if t == frame.Window {
		lane.pendingWindows[id] = len(lane.pendingFrames) - 1
	}
	signal(lane.notify)
	return true
}

func (s *Session) takeLaneDownBatchLocked(lane *carrierLane) downBatch {
	size := 0
	cost := 0
	count := 0
	for count < len(lane.pendingFrames) && count < frame.MaxBatchFrames {
		next := len(lane.pendingFrames[count].encoded)
		if count != 0 && size+next > s.limits.CarrierBatchBytes {
			break
		}
		size += next
		cost += lane.pendingFrames[count].cost
		count++
	}
	result := make([]byte, 0, size)
	for index := 0; index != count; index++ {
		if lane.pendingFrames[index].typeCode == frame.Window &&
			lane.pendingWindows[lane.pendingFrames[index].streamID] == index {
			delete(lane.pendingWindows, lane.pendingFrames[index].streamID)
		}
		result = append(result, lane.pendingFrames[index].encoded...)
		lane.pendingFrames[index] = queuedFrame{}
	}
	lane.pendingFrames = lane.pendingFrames[count:]
	for id, index := range lane.pendingWindows {
		lane.pendingWindows[id] = index - count
	}
	if len(lane.pendingFrames) == 0 {
		lane.pendingFrames = nil
	}
	return downBatch{body: result, cost: cost, items: count}
}
