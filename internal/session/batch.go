package session

import (
	"encoding/binary"
	"math"

	"github.com/telegramdesktop/tproxy-server/internal/frame"
)

type queuedFrame struct {
	encoded  []byte
	typeCode frame.Type
	streamID uint32
	cost     int
}

type downBatch struct {
	body  []byte
	cost  int
	items int
}

func (s *Session) queueFrameLocked(t frame.Type, id uint32, payload []byte) bool {
	if s.usesCarrierLanes() {
		return s.queueLaneFrameLocked(t, id, payload)
	}
	if t == frame.Window {
		if index, exists := s.pendingWindows[id]; exists {
			queued := &s.pendingFrames[index]
			previous, _ := frame.WindowAmount(
				queued.encoded[frame.HeaderSize:])
			amount, _ := frame.WindowAmount(payload)
			total := uint64(previous) + uint64(amount)
			if total <= math.MaxUint32 {
				binary.BigEndian.PutUint32(
					queued.encoded[frame.HeaderSize:],
					uint32(total))
				signal(s.notify)
				return true
			}
		}
	}
	if len(s.pendingFrames) != 0 {
		last := &s.pendingFrames[len(s.pendingFrames)-1]
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
			signal(s.notify)
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
	s.pendingFrames = append(s.pendingFrames, queuedFrame{
		encoded:  encoded,
		typeCode: t,
		streamID: id,
		cost:     cost,
	})
	if t == frame.Window {
		s.pendingWindows[id] = len(s.pendingFrames) - 1
	}
	signal(s.notify)
	return true
}

func (s *Session) validateBatchLocked(values []frame.Frame) bool {
	live := make(map[uint32]streamSnapshot, len(s.streams))
	for id, value := range s.streams {
		live[id] = streamSnapshot{
			receiveWindow: value.receiveWindow,
			sendCredit:    value.sendCredit,
		}
	}
	closed := make(map[uint32]struct{})
	for _, value := range values {
		if value.StreamID == 0 {
			if value.Type != frame.Pong {
				return false
			}
			continue
		}
		state, exists := live[value.StreamID]
		_, wasClosedBefore := s.closedStreams[value.StreamID]
		_, closedInBatch := closed[value.StreamID]
		wasClosed := wasClosedBefore || closedInBatch
		switch value.Type {
		case frame.Open:
			if exists || wasClosed {
				return false
			}
			live[value.StreamID] = streamSnapshot{
				receiveWindow: frame.InitialStreamWindow,
				sendCredit:    frame.InitialStreamWindow,
			}
		case frame.Data:
			if wasClosed {
				continue
			}
			if !exists || uint32(len(value.Payload)) > state.receiveWindow {
				return false
			}
			state.receiveWindow -= uint32(len(value.Payload))
			live[value.StreamID] = state
		case frame.Window:
			if wasClosed {
				continue
			}
			if !exists {
				return false
			}
			amount, _ := frame.WindowAmount(value.Payload)
			state.sendCredit += uint64(amount)
			if state.sendCredit > math.MaxUint32 {
				state.sendCredit = math.MaxUint32
			}
			live[value.StreamID] = state
		case frame.Close:
			if wasClosed {
				continue
			}
			if !exists {
				return false
			}
			delete(live, value.StreamID)
			closed[value.StreamID] = struct{}{}
		default:
			return false
		}
	}
	return true
}

func (s *Session) applyBatchLocked(
	values []frame.Frame,
	reservedCost int,
	reservedItems int) (
	[]*backendStream,
	[]*backendStream,
	int,
	int,
	bool) {
	opened := make([]*backendStream, 0)
	closed := make([]*backendStream, 0)
	for _, value := range values {
		if value.StreamID == 0 {
			continue
		}
		state := s.streams[value.StreamID]
		_, wasClosed := s.closedStreams[value.StreamID]
		switch value.Type {
		case frame.Open:
			if len(s.streams) >= s.limits.MaxStreamsPerSession ||
				(s.acquireStream != nil && !s.acquireStream()) {
				s.rememberClosedLocked(value.StreamID)
				if s.onStreamRejected != nil {
					s.onStreamRejected()
				}
				if !s.queueFrameLocked(frame.Close, value.StreamID, nil) {
					return opened, closed, reservedCost, reservedItems, false
				}
				continue
			}
			backend := newBackendStream(s, value.StreamID, s.profile.Backend)
			state = &streamState{
				backend:       backend,
				receiveWindow: frame.InitialStreamWindow,
				sendCredit:    frame.InitialStreamWindow,
				creditNotify:  make(chan struct{}, 1),
				writeNotify:   make(chan struct{}, 1),
			}
			s.streams[value.StreamID] = state
			opened = append(opened, backend)
		case frame.Data:
			if wasClosed {
				continue
			}
			cost, items := s.appendBackendWriteLocked(state, value.Payload)
			reservedCost -= cost
			reservedItems -= items
			state.receiveWindow -= uint32(len(value.Payload))
			signal(state.writeNotify)
		case frame.Window:
			if wasClosed {
				continue
			}
			amount, _ := frame.WindowAmount(value.Payload)
			state.sendCredit += uint64(amount)
			if state.sendCredit > math.MaxUint32 {
				state.sendCredit = math.MaxUint32
			}
			signal(state.creditNotify)
		case frame.Close:
			if wasClosed {
				continue
			}
			s.releaseStreamWritesLocked(state)
			delete(s.streams, value.StreamID)
			s.rememberClosedLocked(value.StreamID)
			closed = append(closed, state.backend)
		}
	}
	return opened, closed, reservedCost, reservedItems, true
}

func (s *Session) onlyLateFrames(values []frame.Frame) bool {
	for _, value := range values {
		switch value.Type {
		case frame.Data, frame.Window, frame.Close:
		default:
			return false
		}
	}
	return len(values) != 0
}

func signal(channel chan struct{}) {
	select {
	case channel <- struct{}{}:
	default:
	}
}
