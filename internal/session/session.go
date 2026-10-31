package session

import (
	"crypto/sha256"
	"sync"
	"time"

	"github.com/telegramdesktop/tproxy-server/internal/config"
	"github.com/telegramdesktop/tproxy-server/internal/frame"
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
	warmDCPool            *WarmDCPool
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
	streamWorkers         []chan struct{} // пул параллельных StreamCDN воркеров
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
	warmDCPool            *WarmDCPool
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
		warmDCPool:            options.warmDCPool,
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

func (s *Session) WarmDCPool() *WarmDCPool {
	return s.warmDCPool
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

// NextUpSeq returns the next expected uplink sequence number.
func (s *Session) NextUpSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cdnReassembly != nil {
		return s.cdnReassembly.ExpectedUpSeq()
	}
	return s.lastUpSequence + 1
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

func (s *Session) protocolFailure() {
	s.mu.Lock()
	s.closeLocked()
	s.mu.Unlock()
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
	if s.superseded != nil {
		close(s.superseded)
		s.superseded = nil
	}
	for _, ch := range s.streamWorkers {
		close(ch)
	}
	s.streamWorkers = nil
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

// SetUpActiveForTest forces the single-uplink-in-flight flag so tests can
// exercise the concurrent-uplink path without a real race.
func (s *Session) SetUpActiveForTest(active bool) {
	s.mu.Lock()
	s.upActive = active
	s.mu.Unlock()
}
