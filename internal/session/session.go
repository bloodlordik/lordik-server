package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/telegramdesktop/tproxy-server/internal/config"
	"github.com/telegramdesktop/tproxy-server/internal/frame"
	"github.com/telegramdesktop/tproxy-server/internal/logger"
)

const (
	queueItemCost                = 256
	controlReserveExtraItems     = 16
	controlReserveItemsPerStream = 3
)

type pendingClass byte

const (
	pendingUplink pendingClass = iota
	pendingDownlink
	pendingControl
)

type sessionOptions struct {
	profile               *config.Profile
	clientIP              string
	limits                config.Limits
	timeouts              config.Timeouts
	budget                func(int, int, pendingClass) bool
	onFinished            func(*Session)
	acquireStream         func() bool
	onBackendDialFinished func(bool)
	onStreamFinished      func()
	onStreamRejected      func()
	onUp                  func(int)
	onDown                func(int)
}

type streamState struct {
	backend           *backendStream
	receiveWindow     uint32
	sendCredit        uint64
	pendingWriteBytes int
	pendingWriteCost  int
	pendingWriteItems int
	creditNotify      chan struct{}
	writes            [][]byte
	writeNotify       chan struct{}
}

type streamSnapshot struct {
	receiveWindow uint32
	sendCredit    uint64
}

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

type sentBatch struct {
	cursor uint64
	body   []byte
	cost   int
	items  int
}

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

type Session struct {
	profile  *config.Profile
	clientIP string
	limits   config.Limits
	timeouts config.Timeouts
	budget   func(int, int, pendingClass) bool
	carrier  config.CarrierMode

	mu                    sync.Mutex
	streams               map[uint32]*streamState
	closedStreams         map[uint32]struct{}
	closedOrder           []uint32
	closedStart           int
	pendingFrames         []queuedFrame
	pendingWindows        map[uint32]int
	pendingCost           int
	pendingItems          int
	unacked               []byte
	unackedCost           int
	unackedItems          int
	unackedBase           uint64
	unackedBatches        []sentBatch
	downCursor            uint64
	lastUpSequence        uint64
	lastUpDigest          [sha256.Size]byte
	upActive              bool
	downActive            bool
	superseded            chan struct{}
	websocketActive       bool
	wsSuperseded          chan struct{}
	resumeToken           string
	resumeHash            [sha256.Size]byte
	closed                bool
	lastActivity          time.Time
	notify                chan struct{}
	budgetNotify          chan struct{}
	done                  chan struct{}
	carrierLanes          map[uint32]*carrierLane
	cdnReassembly         *ReassemblyBuffer
	cdnPendingFrames      []frame.Frame
	tokenHash             [sha256.Size]byte
	bootstrapHash         [sha256.Size]byte
	shortID               string
	rawSecret             []byte
	ycConnID              string
	finishOnce            sync.Once
	backendWG             sync.WaitGroup
	onFinished            func(*Session)
	acquireStream         func() bool
	onBackendDialFinished func(bool)
	onStreamFinished      func()
	onStreamRejected      func()
	onUp                  func(int)
	onDown                func(int)
}

func newSession(options sessionOptions) *Session {
	carrier := options.profile.CarrierMode.WithDefault()
	var rawSecret []byte
	if options.profile != nil && options.profile.Secret != "" {
		rawSecret, _ = config.DecodeSecret(options.profile.Secret)
	}
	result := &Session{
		profile:               options.profile,
		rawSecret:             rawSecret,
		clientIP:              options.clientIP,
		limits:                options.limits,
		timeouts:              options.timeouts,
		budget:                options.budget,
		carrier:               carrier,
		streams:               make(map[uint32]*streamState),
		closedStreams:         make(map[uint32]struct{}),
		pendingWindows:        make(map[uint32]int),
		lastActivity:          time.Now(),
		notify:                make(chan struct{}, 1),
		budgetNotify:          make(chan struct{}),
		done:                  make(chan struct{}),
		carrierLanes:          make(map[uint32]*carrierLane),
		onFinished:            options.onFinished,
		acquireStream:         options.acquireStream,
		onBackendDialFinished: options.onBackendDialFinished,
		onStreamFinished:      options.onStreamFinished,
		onStreamRejected:      options.onStreamRejected,
		onUp:                  options.onUp,
		onDown:                options.onDown,
	}
	if carrier == config.CarrierHTTPSLanes {
		result.carrierLanes[0] = newCarrierLane()
	}
	if carrier.IsCDN() || carrier.IsYC() {
		windowSize := uint64(options.limits.CDNUplinkWindowSize)
		if windowSize == 0 {
			windowSize = 64
		}
		result.cdnReassembly = NewReassemblyBuffer(windowSize, options.limits.MaxFramePayload)
	}
	return result
}

func (s *Session) Profile() *config.Profile {
	return s.profile
}

func (s *Session) CarrierMode() config.CarrierMode {
	return s.carrier
}

func (s *Session) ShortID() string {
	return s.shortID
}

func (s *Session) RawSecret() []byte {
	return s.rawSecret
}

func (s *Session) ResumeToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resumeToken
}

func (s *Session) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Session) LastUpSequence() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastUpSequence
}

func (s *Session) DownCursor() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.downCursor
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

// NextUpSeq returns the next expected uplink sequence number.
func (s *Session) NextUpSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cdnReassembly != nil {
		return s.cdnReassembly.ExpectedUpSeq()
	}
	return s.lastUpSequence + 1
}

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

func (s *Session) AcquireWebSocket() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.carrier != config.CarrierWebSocket || s.websocketActive {
		return false
	}
	s.websocketActive = true
	return true
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
			s.unackedBatches[i] = sentBatch{} // Явно очищаем ссылку на слайс body для GC
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

func (s *Session) LastActivity() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastActivity
}

func (s *Session) Close() {
	s.mu.Lock()
	s.closeLocked()
	s.mu.Unlock()
}

func (s *Session) wait() {
	s.backendWG.Wait()
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

func (s *Session) backendWriteReservationLocked(
	values []frame.Frame) (int, int) {
	live := make(map[uint32]bool, len(s.streams))
	for id := range s.streams {
		live[id] = true
	}
	cost := 0
	items := 0
	for _, value := range values {
		if value.StreamID == 0 {
			continue
		}
		switch value.Type {
		case frame.Open:
			live[value.StreamID] = true
		case frame.Data:
			if live[value.StreamID] {
				cost += len(value.Payload) + queueItemCost
				items++
			}
		case frame.Close:
			delete(live, value.StreamID)
		}
	}
	return cost, items
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

func (s *Session) appendBackendWriteLocked(
	state *streamState,
	payload []byte) (int, int) {
	cost := len(payload) + queueItemCost
	items := 1
	coalesce := len(state.writes) != 0 && len(state.writes[len(state.writes)-1])+len(payload) <= frame.DataChunk
	if coalesce {
		cost = len(payload)
		items = 0
	}
	if coalesce {
		last := len(state.writes) - 1
		state.writes[last] = append(state.writes[last], payload...)
	} else {
		state.writes = append(state.writes, append([]byte(nil), payload...))
	}
	state.pendingWriteBytes += len(payload)
	state.pendingWriteCost += cost
	state.pendingWriteItems += items
	return cost, items
}

func (s *Session) nextWrite(id uint32, done <-chan struct{}) ([]byte, bool) {
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil, false
		}
		state := s.streams[id]
		if state == nil {
			s.mu.Unlock()
			return nil, false
		}
		if len(state.writes) != 0 {
			result := state.writes[0]
			state.writes[0] = nil
			state.writes = state.writes[1:]
			s.mu.Unlock()
			return result, true
		}
		notify := state.writeNotify
		s.mu.Unlock()
		select {
		case <-notify:
		case <-s.done:
			return nil, false
		case <-done:
			return nil, false
		}
	}
}

func (s *Session) nextWrites(id uint32, done <-chan struct{}) ([][]byte, bool) {
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil, false
		}
		state := s.streams[id]
		if state == nil {
			s.mu.Unlock()
			return nil, false
		}
		if len(state.writes) != 0 {
			result := state.writes
			state.writes = nil
			s.mu.Unlock()
			return result, true
		}
		notify := state.writeNotify
		s.mu.Unlock()
		select {
		case <-notify:
		case <-s.done:
			return nil, false
		case <-done:
			return nil, false
		}
	}
}

func (s *Session) backendDrained(id uint32, amount int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.streams[id]
	if s.closed || state == nil || amount <= 0 || amount > state.pendingWriteBytes || amount > state.pendingWriteCost || uint64(state.receiveWindow)+uint64(amount) > frame.InitialStreamWindow {
		return false
	}
	state.pendingWriteBytes -= amount
	state.pendingWriteCost -= amount
	s.releasePendingLocked(amount, 0)
	state.receiveWindow += uint32(amount)
	if !s.queueFrameLocked(frame.Window, id, frame.WindowPayload(uint32(amount))) {
		return false
	}
	return true
}

func (s *Session) backendWriteFinished(id uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.streams[id]
	if s.closed || state == nil || state.pendingWriteItems == 0 || state.pendingWriteCost < queueItemCost {
		return false
	}
	state.pendingWriteItems--
	state.pendingWriteCost -= queueItemCost
	s.releasePendingLocked(queueItemCost, 1)
	return true
}

func (s *Session) nextReadAllowance(id uint32, done <-chan struct{}) (int, bool) {
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return 0, false
		}
		state := s.streams[id]
		if state == nil {
			s.mu.Unlock()
			return 0, false
		}
		if state.sendCredit != 0 {
			result := int(state.sendCredit)
			if result > frame.DataChunk {
				result = frame.DataChunk
			}
			result = s.dataFrameAllowanceLocked(result)
			if result != 0 {
				s.mu.Unlock()
				return result, true
			}
		}
		notify := state.creditNotify
		budgetNotify := s.budgetNotify
		s.mu.Unlock()
		select {
		case <-notify:
		case <-budgetNotify:
		case <-s.done:
			return 0, false
		case <-done:
			return 0, false
		}
	}
}

func (s *Session) backendData(id uint32, data []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.streams[id]
	if s.closed || state == nil || len(data) == 0 || uint64(len(data)) > state.sendCredit {
		return false
	}
	state.sendCredit -= uint64(len(data))
	if !s.queueFrameLocked(frame.Data, id, data) {
		return false
	}
	return true
}

func (s *Session) backendClosed(id uint32, backend *backendStream) {
	s.mu.Lock()
	state := s.streams[id]
	if !s.closed && state != nil && state.backend == backend {
		s.releaseStreamWritesLocked(state)
		delete(s.streams, id)
		s.rememberClosedLocked(id)
		if !s.queueFrameLocked(frame.Close, id, nil) {
			s.closeLocked()
		}
	}
	s.mu.Unlock()
	backend.close()
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

func (s *Session) usesCarrierLanes() bool {
	return s.carrier == config.CarrierHTTPSLanes ||
		s.carrier == config.CarrierWebSocketLanes
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

func ValidateBudget(cfg config.Config) error {
	reserveCost, reserveItems := pendingControlReserve(cfg.Limits)
	sessions := cfg.Limits.MaxSessionsGlobal
	if reserveCost > cfg.Limits.MaxPendingGlobal/sessions {
		return errors.New("per-session control reserve times max_sessions_global exhausts max_pending_global")
	}
	if reserveItems > cfg.Limits.MaxPendingItemsGlobal/sessions {
		return errors.New("per-session control reserve times max_sessions_global exhausts max_pending_items_global")
	}
	return nil
}

func pendingControlReserve(limits config.Limits) (int, int) {
	items := controlReserveExtraItems
	if limits.MaxStreamsPerSession > (math.MaxInt-items)/controlReserveItemsPerStream {
		return limits.MaxPendingPerSession, limits.MaxPendingItemsPerSession
	}
	items += limits.MaxStreamsPerSession * controlReserveItemsPerStream
	costPerItem := queueItemCost + frame.HeaderSize + 4
	if items > math.MaxInt/costPerItem {
		return limits.MaxPendingPerSession, limits.MaxPendingItemsPerSession
	}
	return items * costPerItem, items
}

func pendingUplinkReserve(limits config.Limits) (int, int) {
	items := limits.MaxBodyBytes / frame.HeaderSize
	if items > frame.MaxBatchFrames {
		items = frame.MaxBatchFrames
	}
	if items > (math.MaxInt-limits.MaxBodyBytes)/queueItemCost {
		return limits.MaxPendingPerSession, limits.MaxPendingItemsPerSession
	}
	return limits.MaxBodyBytes + items*queueItemCost, items
}

func subtractPendingReserve(
	cost, items int,
	reserveCost, reserveItems int) (int, int) {
	if reserveCost >= cost {
		cost = 0
	} else {
		cost -= reserveCost
	}
	if reserveItems >= items {
		items = 0
	} else {
		items -= reserveItems
	}
	return cost, items
}

func (s *Session) uplinkPendingLimits() (int, int) {
	reserveCost, reserveItems := pendingControlReserve(s.limits)
	return subtractPendingReserve(
		s.limits.MaxPendingPerSession,
		s.limits.MaxPendingItemsPerSession,
		reserveCost,
		reserveItems)
}

func (s *Session) downlinkPendingLimits() (int, int) {
	cost, items := s.uplinkPendingLimits()
	reserveCost, reserveItems := pendingUplinkReserve(s.limits)
	return subtractPendingReserve(
		cost,
		items,
		reserveCost,
		reserveItems)
}

func (s *Session) dataFrameAllowanceLocked(limit int) int {
	costLimit, itemLimit := s.downlinkPendingLimits()
	if s.pendingItems >= itemLimit {
		return 0
	}
	available := costLimit - s.pendingCost - queueItemCost - frame.HeaderSize
	if available <= 0 {
		return 0
	}
	if limit > available {
		limit = available
	}
	return limit
}

func (s *Session) reservePendingLocked(
	cost, items int,
	class pendingClass) bool {
	costLimit := s.limits.MaxPendingPerSession
	itemLimit := s.limits.MaxPendingItemsPerSession
	if class == pendingUplink {
		costLimit, itemLimit = s.uplinkPendingLimits()
	} else if class == pendingDownlink {
		costLimit, itemLimit = s.downlinkPendingLimits()
	}
	if cost <= 0 || items < 0 || cost > costLimit || items > itemLimit || s.pendingCost > costLimit-cost || s.pendingItems > itemLimit-items {
		return false
	}
	if s.budget != nil && !s.budget(cost, items, class) {
		return false
	}
	s.pendingCost += cost
	s.pendingItems += items
	return true
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

func (s *Session) rememberClosedLocked(id uint32) {
	if _, exists := s.closedStreams[id]; exists {
		return
	}
	s.closedStreams[id] = struct{}{}
	if s.limits.MaxClosedStreamIDs > 0 {
		if len(s.closedOrder) < s.limits.MaxClosedStreamIDs {
			s.closedOrder = append(s.closedOrder, id)
		} else if len(s.closedOrder) > 0 {
			old := s.closedOrder[s.closedStart]
			delete(s.closedStreams, old)
			if lane := s.carrierLanes[old]; lane != nil {
				s.releaseLaneLocked(lane)
				delete(s.carrierLanes, old)
			}
			s.closedOrder[s.closedStart] = id
			s.closedStart = (s.closedStart + 1) % len(s.closedOrder)
		}
	}
	if lane := s.carrierLanes[id]; lane != nil {
		signal(lane.notify)
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

func (s *Session) releaseStreamWritesLocked(state *streamState) {
	if state.pendingWriteCost != 0 || state.pendingWriteItems != 0 {
		s.releasePendingLocked(state.pendingWriteCost, state.pendingWriteItems)
	}
	state.pendingWriteBytes = 0
	state.pendingWriteCost = 0
	state.pendingWriteItems = 0
	state.writes = nil
}

func (s *Session) releasePendingLocked(cost, items int) {
	if cost == 0 && items == 0 {
		return
	}
	if cost < 0 || items < 0 || cost > s.pendingCost || items > s.pendingItems {
		panic("invalid session pending budget release")
	}
	s.pendingCost -= cost
	s.pendingItems -= items
	if s.budget != nil {
		s.budget(-cost, -items, pendingUplink)
	}
	close(s.budgetNotify)
	s.budgetNotify = make(chan struct{})
}

func (s *Session) protocolFailure() {
	s.mu.Lock()
	s.closeLocked()
	s.mu.Unlock()
}

func (s *Session) laneProtocolFailure(laneID uint32) {
	if s.carrier == config.CarrierWebSocketLanes {
		s.ReleaseWebSocketLane(laneID)
	} else {
		s.protocolFailure()
	}
}

func (s *Session) closeLocked() {
	if s.closed {
		return
	}
	s.closed = true
	close(s.done)
	for _, lane := range s.carrierLanes {
		lane.pendingFrames = nil
		lane.pendingWindows = nil
		lane.unacked = nil
		lane.unackedCost = 0
		lane.unackedItems = 0
		signal(lane.notify)
	}
	for _, value := range s.streams {
		value.backend.close()
	}
	s.streams = nil
	if s.pendingCost != 0 || s.pendingItems != 0 {
		if s.budget != nil {
			s.budget(-s.pendingCost, -s.pendingItems, pendingUplink)
		}
		s.pendingCost = 0
		s.pendingItems = 0
	}
	s.pendingFrames = nil
	s.pendingWindows = nil
	s.unacked = nil
	s.unackedCost = 0
	s.unackedItems = 0
	s.unackedBatches = nil
	s.cdnReassembly = nil
	s.cdnPendingFrames = nil
	signal(s.notify)
	s.finishOnce.Do(func() {
		if s.onFinished != nil {
			go s.onFinished(s)
		}
	})
}

func (s *Session) runBackend(value *backendStream) {
	defer s.backendWG.Done()
	if s.onStreamFinished != nil {
		defer s.onStreamFinished()
	}
	value.run()
}

func (s *Session) backendDialFinished(failed bool) {
	if s.onBackendDialFinished != nil {
		s.onBackendDialFinished(failed)
	}
}

func signal(channel chan struct{}) {
	select {
	case channel <- struct{}{}:
	default:
	}
}

type backendStream struct {
	session   *Session
	id        uint32
	address   string
	ctx       context.Context
	cancel    context.CancelFunc
	connMu    sync.Mutex
	conn      net.Conn
	closeOnce sync.Once
	finished  chan struct{}
}

func newBackendStream(session *Session, id uint32, address string) *backendStream {
	ctx, cancel := context.WithCancel(context.Background())
	return &backendStream{
		session:  session,
		id:       id,
		address:  address,
		ctx:      ctx,
		cancel:   cancel,
		finished: make(chan struct{}),
	}
}

func (s *backendStream) run() {
	defer close(s.finished)
	defer s.session.backendClosed(s.id, s)

	if s.session.profile != nil && s.session.profile.BackendType == config.BackendDirect {
		s.runDirect()
		return
	}
	network := "tcp"
	target := s.address
	if s.session.profile != nil {
		network, target = s.session.profile.BackendNetworkAndAddress()
	} else if strings.HasPrefix(s.address, "unix://") {
		network = "unix"
		target = strings.TrimPrefix(s.address, "unix://")
	} else if strings.HasPrefix(s.address, "unix:") {
		network = "unix"
		target = strings.TrimPrefix(s.address, "unix:")
	} else if strings.HasPrefix(s.address, "/") {
		network = "unix"
		target = s.address
	}

	dialer := net.Dialer{
		Timeout:   s.session.timeouts.BackendDial.Value(),
		KeepAlive: 30 * time.Second,
	}
	connection, err := dialer.DialContext(s.ctx, network, target)
	s.session.backendDialFinished(err != nil && s.ctx.Err() == nil)
	if err != nil {
		if s.ctx.Err() == nil {
			logger.Warn("backend dial failed", "network", network, "target", target, "stream_id", s.id, "err", err)
		}
		return
	}
	if tcpConn, ok := connection.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}
	logger.Debug("backend connected", "network", network, "target", target, "stream_id", s.id)
	s.connMu.Lock()
	if s.ctx.Err() != nil {
		s.connMu.Unlock()
		_ = connection.Close()
		return
	}
	s.conn = connection
	s.connMu.Unlock()
	if s.session.profile != nil && s.session.profile.BackendProxyProtocol != config.BackendProxyNone {
		header := buildProxyHeader(s.session.profile.BackendProxyProtocol, s.session.clientIP, s.address)
		if len(header) > 0 {
			_ = connection.SetWriteDeadline(time.Now().Add(s.session.timeouts.BackendDial.Value()))
			if _, err := connection.Write(header); err != nil {
				s.close()
				return
			}
			_ = connection.SetWriteDeadline(time.Time{})
		}
	}
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		s.writeLoop(connection)
		s.close()
	}()
	s.readLoop(connection)
	s.close()
	<-writeDone
}

var readBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, frame.DataChunk)
		return &b
	},
}

func (s *backendStream) writeLoop(connection net.Conn) {
	for {
		chunks, ok := s.session.nextWrites(s.id, s.ctx.Done())
		if !ok {
			return
		}
		if len(chunks) == 1 {
			data := chunks[0]
			for len(data) != 0 {
				written, err := connection.Write(data)
				if written > 0 {
					if !s.session.backendDrained(s.id, written) {
						return
					}
					data = data[written:]
				}
				if err != nil || written == 0 {
					return
				}
			}
			if !s.session.backendWriteFinished(s.id) {
				return
			}
		} else {
			buffers := net.Buffers(chunks)
			totalLen := 0
			for _, c := range chunks {
				totalLen += len(c)
			}
			numItems := len(chunks)
			for totalLen > 0 {
				n, err := buffers.WriteTo(connection)
				if n > 0 {
					if !s.session.backendDrained(s.id, int(n)) {
						return
					}
					totalLen -= int(n)
				}
				if err != nil || n == 0 {
					return
				}
			}
			for i := 0; i < numItems; i++ {
				if !s.session.backendWriteFinished(s.id) {
					return
				}
			}
		}
	}
}

func (s *backendStream) readLoop(connection net.Conn) {
	bufPtr := readBufferPool.Get().(*[]byte)
	defer readBufferPool.Put(bufPtr)
	buffer := *bufPtr
	for {
		allowance, ok := s.session.nextReadAllowance(s.id, s.ctx.Done())
		if !ok {
			return
		}
		read, err := connection.Read(buffer[:allowance])
		if read > 0 && !s.session.backendData(s.id, buffer[:read]) {
			return
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && s.ctx.Err() == nil {
				return
			}
			return
		}
		if read == 0 {
			return
		}
	}
}

func (s *backendStream) close() {
	s.closeOnce.Do(func() {
		s.cancel()
		s.connMu.Lock()
		if s.conn != nil {
			_ = s.conn.Close()
			s.conn = nil
		}
		s.connMu.Unlock()
	})
}

// SetUpActiveForTest forces the single-uplink-in-flight flag so tests can
// exercise the concurrent-uplink path without a real race.
func (s *Session) SetUpActiveForTest(active bool) {
	s.mu.Lock()
	s.upActive = active
	s.mu.Unlock()
}
