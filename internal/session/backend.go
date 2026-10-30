package session

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/telegramdesktop/tproxy-server/internal/config"
	"github.com/telegramdesktop/tproxy-server/internal/frame"
	"github.com/telegramdesktop/tproxy-server/internal/logger"
)

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

func (s *Session) releaseStreamWritesLocked(state *streamState) {
	if state.pendingWriteCost != 0 || state.pendingWriteItems != 0 {
		s.releasePendingLocked(state.pendingWriteCost, state.pendingWriteItems)
	}
	state.pendingWriteBytes = 0
	state.pendingWriteCost = 0
	state.pendingWriteItems = 0
	state.writes = nil
}
