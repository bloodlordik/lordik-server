package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/http/pprof"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/telegramdesktop/tproxy-server/internal/bridge"
	"github.com/telegramdesktop/tproxy-server/internal/config"
	"github.com/telegramdesktop/tproxy-server/internal/frame"
	"github.com/telegramdesktop/tproxy-server/internal/session"
	"github.com/telegramdesktop/tproxy-server/internal/logger"
)

const (
	webSocketProtocolPrefix         = "tproxy-v1."
	webSocketLaneProtocolPrefix     = "tproxy-lane-v1."
	webSocketResumeProtocolPrefix     = "tproxy-resume-v1."
	webSocketLaneResumeProtocolPrefix = "tproxy-lane-resume-v1."
)

// A create body is a single HELLO frame (8-byte header + 1-byte payload), so a
// tiny cap is plenty and keeps an unauthenticated POST /session from streaming
// megabytes before Create rejects it.
const maxCreateBodyBytes = 64

// A request body must not be able to hold a relay goroutine and a
// Caddy->relay connection open indefinitely — neither while a handler reads
// it nor while net/http discards an unread body before answering. Long polls
// carry no body. Public requests use the ordinary gateway timeout policy.
const bodyReadDeadline = 30 * time.Second

type Server struct {
	config           config.Config
	base             string
	manager          *session.Manager
	site             *staticSite
	publicUpstream   http.Handler
	publicTransport  *http.Transport
	bodyReadDeadline time.Duration
	buildID          string
}

func New(value config.Config) (*Server, error) {
	tokenKey, err := config.ReadTokenKey(value.TokenKeyFile)
	if err != nil {
		return nil, err
	}
	if err := session.ValidateBudget(value); err != nil {
		return nil, err
	}
	var site *staticSite
	var publicUpstream http.Handler
	var publicTransport *http.Transport
	if value.PublicDir != "" {
		var err error
		site, err = loadStaticSite(value.PublicDir)
		if err != nil {
			return nil, err
		}
	} else {
		target, err := url.Parse(value.PublicUpstream)
		if err != nil {
			return nil, err
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DisableCompression = true
		publicTransport = transport
		proxy := &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(request *httputil.ProxyRequest) {
				request.Out.URL.Scheme = target.Scheme
				request.Out.URL.Host = target.Host
				request.Out.Host = request.In.Host
				request.Out.URL.RawQuery = request.In.URL.RawQuery
				request.Out.Trailer = request.In.Trailer
				for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
					if values, ok := request.In.Header[name]; ok {
						request.Out.Header[name] = append([]string(nil), values...)
					}
				}
			},
		}
		proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		}
		publicUpstream = proxy
	}
	return &Server{
		config:           value,
		base:             value.Base(),
		manager:          session.NewManager(value, tokenKey),
		site:             site,
		publicUpstream:   publicUpstream,
		publicTransport:  publicTransport,
		bodyReadDeadline: bodyReadDeadline,
		buildID:          generateBuildID(),
	}, nil
}

func (s *Server) BuildID() string {
	return s.buildID
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serveHTTP)
}

func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/readyz", s.serveReady)
	mux.HandleFunc("/metrics", s.serveMetrics)
	if s.config.EnablePprof {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}
	return mux
}

func (s *Server) Shutdown() {
	s.manager.Shutdown()
	if s.publicTransport != nil {
		s.publicTransport.CloseIdleConnections()
	}
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.hasInternalSecret(r) {
		s.servePublic(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.ContentLength != 0 {
		s.setReadDeadline(w)
	}
	if r.Host != s.config.PublicHostname && r.Host != s.config.PublicHostname+":443" {
		s.serveNotFound(w, r)
		return
	}
	if suffix, ok := s.transportSuffix(r.URL.Path); ok && r.URL.EscapedPath() == r.URL.Path {
		if strings.HasPrefix(suffix, "_next/data/") || strings.HasPrefix(suffix, "assets/") {
			s.serveCDN(w, r, suffix)
			return
		}
		s.serveAPI(w, r, suffix)
		return
	}
	if profile := s.bridgeProfile(r); profile != nil {
		s.serveBridge(w, r, profile)
		return
	}
	s.serveNotFound(w, r)
}

func (s *Server) serveBridge(w http.ResponseWriter, r *http.Request, profile *config.Profile) {
	clientIP, err := s.clientIP(r)
	if err != nil {
		logger.Debug("bridge request rejected: invalid client IP", "err", err)
		s.serveNotFound(w, r)
		return
	}
	token, err := s.manager.IssueBootstrap(profile, clientIP)
	if err != nil {
		logger.Warn("bridge bootstrap issuance failed", "client_ip", clientIP, "profile", profile.Name, "err", err)
		s.serveNotFound(w, r)
		return
	}
	page, err := bridge.RenderWithOptions(bridge.Options{
		Hostname:       s.config.PublicHostname,
		BasePath:       s.config.BasePath,
		BootstrapToken: token,
		CarrierMode:    string(profile.CarrierMode.WithDefault()),
		BatchBytes:     s.config.Limits.CarrierBatchBytes,
		BuildID:        s.buildID,
	})
	if err != nil {
		logger.Error("bridge render failed", "client_ip", clientIP, "profile", profile.Name, "err", err)
		s.serveNotFound(w, r)
		return
	}
	logger.Debug("bridge page served", "client_ip", clientIP, "profile", profile.Name, "carrier", profile.CarrierMode)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", page.CSP)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-DNS-Prefetch-Control", "off")
	w.Header().Set("Permissions-Policy", bridge.PermissionsPolicy)
	w.Header().Set("Content-Length", strconv.Itoa(len(page.Body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(page.Body)
}

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request, suffix string) {
	if (r.URL.RawQuery != "" || r.URL.ForceQuery) && suffix != "api/v1/ws" {
		s.serveNotFound(w, r)
		return
	}
	if len(r.Header.Values("Authorization")) > 1 ||
		len(r.Header.Values("Sec-WebSocket-Protocol")) > 1 ||
		(r.Header.Get("Cookie") != "" && suffix != "api/v1/ws") {
		s.serveNotFound(w, r)
		return
	}
	clientIP, err := s.clientIP(r)
	if err != nil {
		s.serveNotFound(w, r)
		return
	}
	if suffix == "api/v1/ws" {
		s.serveWebSocket(w, r)
		return
	}
	if suffix == "api/v1/resume" {
		s.serveResume(w, r, clientIP)
		return
	}
	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		s.serveNotFound(w, r)
		return
	}
	switch suffix {
	case "api/v1/session":
		s.serveSession(w, r, token, clientIP)
	case "api/v1/up":
		s.serveUp(w, r, token)
	case "api/v1/down":
		s.serveDown(w, r, token)
	default:
		s.serveNotFound(w, r)
	}
}

func (s *Server) serveSession(
	w http.ResponseWriter,
	r *http.Request,
	token string,
	clientIP string,
) {
	if r.Method == http.MethodDelete {
		if !emptyBody(r) || r.Header.Get("Content-Type") != "" {
			s.serveNotFound(w, r)
			return
		}
		if err := s.manager.CloseToken(token); err != nil {
			logger.Debug("session delete failed", "err", err)
			s.serveNotFound(w, r)
			return
		}
		logger.Info("session closed via delete request")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost || !binaryContentType(r.Header.Get("Content-Type")) {
		s.serveNotFound(w, r)
		return
	}
	if !s.manager.HasBootstrap(token) {
		s.serveNotFound(w, r)
		return
	}
	body, err := readBody(w, r, maxCreateBodyBytes)
	if err != nil {
		s.serveNotFound(w, r)
		return
	}
	result, err := s.manager.Create(token, clientIP, body)
	if err != nil {
		if errors.Is(err, session.ErrLimit) {
			logger.Warn("session create limit reached", "client_ip", clientIP)
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		logger.Warn("session create failed", "client_ip", clientIP, "err", err)
		s.serveNotFound(w, r)
		return
	}
	logger.Info("session created", "client_ip", clientIP, "carrier", result.Session.CarrierMode())
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Session-Token", result.Token)
	w.Header().Set("X-Resume-Token", result.ResumeToken)
	w.Header().Set("X-Carrier-Mode", string(result.Session.CarrierMode()))
	w.Header().Set("X-Down-Cursor", "0")
	w.Header().Set("Content-Length", strconv.Itoa(len(result.Welcome)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result.Welcome)
}
func (s *Server) serveResume(w http.ResponseWriter, r *http.Request, clientIP string) {
	if r.Method != http.MethodPost || !emptyBody(r) || r.Header.Get("Content-Type") != "" {
		s.serveNotFound(w, r)
		return
	}
	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		token = r.Header.Get("X-Resume-Token")
		if token == "" {
			token = r.Header.Get("X-Session-Token")
		}
	}
	if token == "" {
		s.serveNotFound(w, r)
		return
	}
	sess, err := s.manager.Resume(token, clientIP)
	if err != nil {
		logger.Warn("session resume failed", "client_ip", clientIP, "err", err)
		s.serveNotFound(w, r)
		return
	}
	upSeq := uint64(1)
	if upSeqHeader := r.Header.Get("X-Up-Seq"); upSeqHeader != "" {
		if val, ok := canonicalUint(upSeqHeader); ok {
			upSeq = val
		}
	}
	downCursor := uint64(0)
	if downCursorHeader := r.Header.Get("X-Down-Cursor"); downCursorHeader != "" {
		if val, ok := canonicalUint(downCursorHeader); ok {
			downCursor = val
		}
	}
	serverUp, serverDown, replay, err := sess.Resume(upSeq, downCursor)
	if err != nil {
		logger.Warn("session resume alignment failed", "client_ip", clientIP, "err", err)
		s.serveNotFound(w, r)
		return
	}
	logger.Info("session resumed", "client_ip", clientIP, "carrier", sess.CarrierMode(), "up_seq", serverUp, "down_cursor", serverDown)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Resume-Token", sess.ResumeToken())
	w.Header().Set("X-Carrier-Mode", string(sess.CarrierMode()))
	w.Header().Set("X-Up-Seq", strconv.FormatUint(serverUp, 10))
	w.Header().Set("X-Down-Cursor", strconv.FormatUint(serverDown, 10))
	if len(replay) > 0 {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(replay)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(replay)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}


func (s *Server) serveUp(w http.ResponseWriter, r *http.Request, token string) {
	if r.Method != http.MethodPost || !binaryContentType(r.Header.Get("Content-Type")) {
		s.serveNotFound(w, r)
		return
	}
	sequence, ok := canonicalUint(r.Header.Get("X-Up-Seq"))
	if !ok || sequence == 0 {
		s.serveNotFound(w, r)
		return
	}
	value, err := s.manager.Get(token)
	if err != nil {
		s.serveNotFound(w, r)
		return
	}
	body, err := readBody(w, r, s.config.Limits.MaxBodyBytes)
	if err != nil {
		s.serveNotFound(w, r)
		return
	}
	var ack uint64
	switch value.CarrierMode() {
	case config.CarrierHTTPS:
		if r.Header.Get("X-Lane-ID") != "" {
			s.serveNotFound(w, r)
			return
		}
		ack, err = value.ProcessUp(sequence, body)
	case config.CarrierHTTPSLanes:
		lane, ok := canonicalUint(r.Header.Get("X-Lane-ID"))
		if !ok || lane > frame.MaxStreamID {
			s.serveNotFound(w, r)
			return
		}
		ack, err = value.ProcessUpLane(uint32(lane), sequence, body)
	default:
		s.serveNotFound(w, r)
		return
	}
	if err != nil {
		if errors.Is(err, session.ErrBackpressure) ||
			errors.Is(err, session.ErrConcurrent) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		s.serveNotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Up-Ack", strconv.FormatUint(ack, 10))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) serveDown(w http.ResponseWriter, r *http.Request, token string) {
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "" {
		s.serveNotFound(w, r)
		return
	}
	cursor, ok := canonicalUint(r.Header.Get("X-Down-Cursor"))
	if !ok {
		s.serveNotFound(w, r)
		return
	}
	value, err := s.manager.Get(token)
	if err != nil {
		s.serveNotFound(w, r)
		return
	}
	if !emptyBody(r) {
		s.serveNotFound(w, r)
		return
	}
	var body []byte
	var next uint64
	var laneClosed bool
	switch value.CarrierMode() {
	case config.CarrierHTTPS:
		if r.Header.Get("X-Lane-ID") != "" {
			s.serveNotFound(w, r)
			return
		}
		body, next, err = value.Poll(r.Context(), cursor)
	case config.CarrierHTTPSLanes:
		lane, ok := canonicalUint(r.Header.Get("X-Lane-ID"))
		if !ok || lane > frame.MaxStreamID {
			s.serveNotFound(w, r)
			return
		}
		body, next, laneClosed, err = value.PollLane(
			r.Context(),
			uint32(lane),
			cursor)
	default:
		s.serveNotFound(w, r)
		return
	}
	if err != nil {
		if r.Context().Err() != nil {
			return
		}
		if errors.Is(err, session.ErrConcurrent) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		s.serveNotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Down-Cursor", strconv.FormatUint(next, 10))
	if laneClosed {
		w.Header().Set("X-Lane-Closed", "1")
	}
	if len(body) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

type wsAuthInfo struct {
	token      string
	laneID     uint32
	lanes      bool
	isResume   bool
	upSeq      uint64
	downCursor uint64
	ok         bool
}

func (s *Server) serveWebSocket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" {
		s.serveNotFound(w, r)
		return
	}
	protocols := websocket.Subprotocols(r)
	var proto string
	if len(protocols) == 1 {
		proto = protocols[0]
	}
	auth := webSocketAuth(r, proto)
	if !auth.ok {
		s.serveNotFound(w, r)
		return
	}
	if _, ok := bearerToken("Bearer " + auth.token); !ok {
		s.serveNotFound(w, r)
		return
	}
	clientIP, err := s.clientIP(r)
	if err != nil {
		s.serveNotFound(w, r)
		return
	}
	var value *session.Session
	if auth.isResume {
		value, err = s.manager.Resume(auth.token, clientIP)
	} else {
		value, err = s.manager.Get(auth.token)
	}
	if err != nil ||
		(auth.lanes && value.CarrierMode() != config.CarrierWebSocketLanes) ||
		(!auth.lanes && value.CarrierMode() != config.CarrierWebSocket) {
		s.serveNotFound(w, r)
		return
	}
	if !emptyBody(r) {
		s.serveNotFound(w, r)
		return
	}
	var wsSuperseded chan struct{}
	acquired := false
	if auth.lanes {
		wsSuperseded, acquired = value.AcquireWebSocketLaneTakeover(auth.laneID)
	} else {
		wsSuperseded, acquired = value.AcquireWebSocketTakeover()
	}
	if !acquired {
		s.serveNotFound(w, r)
		return
	}
	upgrader := websocket.Upgrader{
		ReadBufferSize:  64 * 1024,
		WriteBufferSize: 64 * 1024,
		Subprotocols:    protocols,
		CheckOrigin: func(*http.Request) bool {
			return true
		},
	}
	connection, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Warn("websocket upgrade failed", "err", err)
		if auth.lanes {
			value.ReleaseWebSocketLaneGraceful(auth.laneID)
		} else {
			value.ReleaseWebSocket()
		}
		return
	}
	logger.Info("websocket session connected", "carrier", value.CarrierMode(), "lanes", auth.lanes, "resume", auth.isResume)
	if auth.lanes {
		defer value.ReleaseWebSocketLaneGraceful(auth.laneID)
	} else {
		defer value.ReleaseWebSocket()
	}
	defer connection.Close()

	startSeq := auth.upSeq
	startCursor := auth.downCursor
	if auth.isResume {
		var serverUp, serverDown uint64
		var replay []byte
		if auth.lanes {
			serverUp, serverDown, replay, err = value.ResumeLane(auth.laneID, auth.upSeq, auth.downCursor)
		} else {
			serverUp, serverDown, replay, err = value.Resume(auth.upSeq, auth.downCursor)
		}
		if err != nil {
			logger.Warn("websocket resume alignment failed", "client_ip", clientIP, "err", err)
			return
		}
		startSeq = serverUp
		startCursor = serverDown
		if len(replay) > 0 {
			_ = connection.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if err := connection.WriteMessage(websocket.BinaryMessage, replay); err != nil {
				return
			}
		}
	}

	connection.SetReadLimit(int64(s.config.Limits.MaxBodyBytes))
	idle := 2 * s.config.Timeouts.LongPoll.Value()
	_ = connection.SetReadDeadline(time.Now().Add(idle))
	connection.SetPongHandler(func(string) error {
		return connection.SetReadDeadline(time.Now().Add(idle))
	})
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	if wsSuperseded != nil {
		go func() {
			select {
			case <-wsSuperseded:
				_ = connection.Close()
				cancel()
			case <-ctx.Done():
			}
		}()
	}
	finished := make(chan error, 2)
	go s.readWebSocket(ctx, connection, value, auth.laneID, auth.lanes, idle, startSeq, finished)
	go s.writeWebSocket(ctx, connection, value, auth.laneID, auth.lanes, startCursor, finished)
	<-finished
}

func webSocketAuth(r *http.Request, protocol string) wsAuthInfo {
	if strings.HasPrefix(protocol, webSocketResumeProtocolPrefix) {
		trimmed := strings.TrimPrefix(protocol, webSocketResumeProtocolPrefix)
		parts := strings.Split(trimmed, ".")
		if len(parts) >= 1 && parts[0] != "" {
			upSeq := uint64(1)
			downCursor := uint64(0)
			if len(parts) >= 2 {
				if val, ok := canonicalUint(parts[1]); ok {
					upSeq = val
				}
			}
			if len(parts) >= 3 {
				if val, ok := canonicalUint(parts[2]); ok {
					downCursor = val
				}
			}
			return wsAuthInfo{
				token:      parts[0],
				laneID:     0,
				lanes:      false,
				isResume:   true,
				upSeq:      upSeq,
				downCursor: downCursor,
				ok:         true,
			}
		}
	}
	if strings.HasPrefix(protocol, webSocketLaneResumeProtocolPrefix) {
		trimmed := strings.TrimPrefix(protocol, webSocketLaneResumeProtocolPrefix)
		parts := strings.Split(trimmed, ".")
		if len(parts) >= 2 && parts[0] != "" {
			lane, ok := canonicalUint(parts[1])
			if ok && lane > 0 && lane <= frame.MaxStreamID {
				upSeq := uint64(1)
				downCursor := uint64(0)
				if len(parts) >= 3 {
					if val, ok := canonicalUint(parts[2]); ok {
						upSeq = val
					}
				}
				if len(parts) >= 4 {
					if val, ok := canonicalUint(parts[3]); ok {
						downCursor = val
					}
				}
				return wsAuthInfo{
					token:      parts[0],
					laneID:     uint32(lane),
					lanes:      true,
					isResume:   true,
					upSeq:      upSeq,
					downCursor: downCursor,
					ok:         true,
				}
			}
		}
	}
	if strings.HasPrefix(protocol, webSocketProtocolPrefix) {
		token := strings.TrimPrefix(protocol, webSocketProtocolPrefix)
		if token != "" {
			return wsAuthInfo{
				token:      token,
				laneID:     0,
				lanes:      false,
				isResume:   false,
				upSeq:      1,
				downCursor: 0,
				ok:         true,
			}
		}
	}
	if strings.HasPrefix(protocol, webSocketLaneProtocolPrefix) {
		tokenAndLane := strings.TrimPrefix(protocol, webSocketLaneProtocolPrefix)
		token, laneText, ok := strings.Cut(tokenAndLane, ".")
		if ok && token != "" {
			lane, ok := canonicalUint(laneText)
			if ok && lane > 0 && lane <= frame.MaxStreamID {
				return wsAuthInfo{
					token:      token,
					laneID:     uint32(lane),
					lanes:      true,
					isResume:   false,
					upSeq:      1,
					downCursor: 0,
					ok:         true,
				}
			}
		}
	}
	if r != nil {
		q := r.URL.Query()
		resumeToken := q.Get("resume")
		if resumeToken != "" {
			upSeq := uint64(1)
			if u, ok := canonicalUint(q.Get("up")); ok {
				upSeq = u
			}
			downCursor := uint64(0)
			if d, ok := canonicalUint(q.Get("down")); ok {
				downCursor = d
			}
			laneID := uint32(0)
			lanes := false
			if laneStr := q.Get("lane"); laneStr != "" {
				if l, ok := canonicalUint(laneStr); ok && l > 0 && l <= frame.MaxStreamID {
					laneID = uint32(l)
					lanes = true
				}
			}
			return wsAuthInfo{
				token:      resumeToken,
				laneID:     laneID,
				lanes:      lanes,
				isResume:   true,
				upSeq:      upSeq,
				downCursor: downCursor,
				ok:         true,
			}
		}
	}
	return wsAuthInfo{}
}

func webSocketCredentials(protocol string) (string, uint32, bool, bool) {
	auth := webSocketAuth(nil, protocol)
	return auth.token, auth.laneID, auth.lanes, auth.ok
}

func (s *Server) readWebSocket(
	ctx context.Context,
	connection *websocket.Conn,
	value *session.Session,
	laneID uint32,
	lanes bool,
	idle time.Duration,
	startSeq uint64,
	finished chan<- error) {
	sequence := startSeq
	for {
		messageType, body, err := connection.ReadMessage()
		if err != nil {
			finished <- err
			return
		}
		_ = connection.SetReadDeadline(time.Now().Add(idle))
		if messageType != websocket.BinaryMessage || len(body) == 0 {
			finished <- session.ErrProtocol
			return
		}
		deadline := time.NewTimer(30 * time.Second)
		for {
			var ack uint64
			var processErr error
			if lanes {
				ack, processErr = value.ProcessUpLane(laneID, sequence, body)
			} else {
				ack, processErr = value.ProcessUp(sequence, body)
			}
			if processErr == nil && ack == sequence {
				if !deadline.Stop() {
					<-deadline.C
				}
				sequence++
				break
			}
			if !errors.Is(processErr, session.ErrBackpressure) {
				deadline.Stop()
				finished <- processErr
				return
			}
			select {
			case <-ctx.Done():
				deadline.Stop()
				finished <- ctx.Err()
				return
			case <-deadline.C:
				finished <- session.ErrBackpressure
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
}

func (s *Server) writeWebSocket(
	ctx context.Context,
	connection *websocket.Conn,
	value *session.Session,
	laneID uint32,
	lanes bool,
	startCursor uint64,
	finished chan<- error) {
	cursor := startCursor
	for {
		var body []byte
		var next uint64
		var laneClosed bool
		var err error
		if lanes {
			body, next, laneClosed, err = value.PollLane(
				ctx,
				laneID,
				cursor)
		} else {
			body, next, err = value.Poll(ctx, cursor)
		}
		if err != nil {
			finished <- err
			return
		}
		if laneClosed {
			finished <- nil
			return
		}
		if err := connection.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
			finished <- err
			return
		}
		if len(body) == 0 {
			if err := connection.WriteMessage(websocket.PingMessage, nil); err != nil {
				finished <- err
				return
			}
			continue
		}
		if err := connection.WriteMessage(websocket.BinaryMessage, body); err != nil {
			finished <- err
			return
		}
		cursor = next
	}
}


func (s *Server) clientIP(r *http.Request) (string, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", err
	}
	peer := net.ParseIP(host)
	if peer == nil || !peer.IsLoopback() {
		return "", errors.New("request did not arrive through loopback proxy")
	}
	// Prioritize CDN and reverse proxy client IP headers
	for _, headerName := range []string{"CF-Connecting-IP", "True-Client-IP", "X-Real-IP"} {
		if val := strings.TrimSpace(r.Header.Get(headerName)); val != "" {
			if parsed := net.ParseIP(val); parsed != nil {
				return parsed.String(), nil
			}
		}
	}
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		return peer.String(), nil
	}
	// Support comma-separated X-Forwarded-For (take the first client IP)
	target := forwarded
	if idx := strings.IndexByte(forwarded, ','); idx != -1 {
		target = forwarded[:idx]
	}
	target = strings.TrimSpace(target)
	parsed := net.ParseIP(target)
	if parsed == nil {
		return "", errors.New("invalid forwarding address")
	}
	return parsed.String(), nil
}

// The request reaches the site with its original path, base prefix included. A
// stripped prefix would expose the whole site a second time under it, which is a
// far louder signature than the 404 it would replace.
func (s *Server) servePublic(w http.ResponseWriter, r *http.Request) {
	logger.Debug("serving public site", "method", r.Method, "host", r.Host, "path", r.URL.Path)
	if s.publicUpstream != nil {
		s.publicUpstream.ServeHTTP(w, r)
		return
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if r.URL.Path == "/" {
			s.serveEntry(w, r, s.site.index, http.StatusOK)
			return
		}
		if entry := s.site.resolve(r.URL.Path, s.config.StaticRoutes == "legacy"); entry != nil {
			s.serveEntry(w, r, entry, http.StatusOK)
			return
		}
	}
	s.serveEntry(w, r, s.site.notFound, http.StatusNotFound)
}

func (s *Server) serveNotFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	http.NotFound(w, r)
}

// transportSuffix names the carrier endpoint a request path selects, relative to
// the configured base. A path outside the base, or one naming anything else, is
// not carrier traffic and stays with the bridge or public handlers.
func (s *Server) transportSuffix(requestPath string) (string, bool) {
	if !strings.HasPrefix(requestPath, s.base) {
		return "", false
	}
	suffix := requestPath[len(s.base):]
	switch suffix {
	case "api/v1/session", "api/v1/up", "api/v1/down", "api/v1/ws", "api/v1/resume":
		return suffix, true
	}
	if strings.HasPrefix(suffix, "_next/data/") || strings.HasPrefix(suffix, "assets/") {
		return suffix, true
	}
	return "", false
}

func (s *Server) serveReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	for _, profile := range s.config.Profiles {
		network, address := profile.BackendNetworkAndAddress()
		connection, err := net.DialTimeout(network, address, s.config.Timeouts.BackendDial.Value())
		if err != nil {
			http.Error(w, "backend unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = connection.Close()
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ready\n")
}

func (s *Server) serveMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	metrics := s.manager.Metrics()
	capacity := s.manager.Capacity()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(w,
		"tproxy_sessions_live %d\n"+
			"tproxy_streams_live %d\n"+
			"tproxy_backend_dials_in_flight %d\n"+
			"tproxy_pending_bytes %d\n"+
			"tproxy_pending_items %d\n"+
			"tproxy_sessions_created_total %d\n"+
			"tproxy_sessions_closed_total %d\n"+
			"tproxy_streams_opened_total %d\n"+
			"tproxy_streams_rejected_total %d\n"+
			"tproxy_backend_dial_failures_total %d\n"+
			"tproxy_bytes_up_total %d\n"+
			"tproxy_bytes_down_total %d\n"+
			"tproxy_limit_hits_total %d\n",
		capacity.Sessions, capacity.Streams, capacity.BackendDialsInFlight,
		capacity.PendingBytes, capacity.PendingItems,
		metrics.SessionsCreated, metrics.SessionsClosed,
		metrics.StreamsOpened, metrics.StreamsRejected,
		metrics.BackendDialFailures, metrics.BytesUp, metrics.BytesDown,
		metrics.LimitHits)
}

func (s *Server) setReadDeadline(w http.ResponseWriter) {
	if controller := http.NewResponseController(w); controller != nil {
		_ = controller.SetReadDeadline(time.Now().Add(s.bodyReadDeadline))
	}
}

func readBody(w http.ResponseWriter, r *http.Request, limit int) ([]byte, error) {
	reader := http.MaxBytesReader(w, r.Body, int64(limit))
	defer reader.Close()
	result, err := io.ReadAll(reader)
	if err != nil || len(result) == 0 {
		return nil, errors.New("invalid body")
	}
	return result, nil
}

func emptyBody(r *http.Request) bool {
	if r.ContentLength > 0 {
		return false
	}
	if r.Body == nil {
		return true
	}
	var single [1]byte
	read, _ := r.Body.Read(single[:])
	return read == 0
}

func binaryContentType(value string) bool {
	mediaType, parameters, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/octet-stream" && len(parameters) == 0
}

func bearerToken(value string) (string, bool) {
	if !strings.HasPrefix(value, "Bearer ") || strings.Count(value, " ") != 1 {
		return "", false
	}
	token := strings.TrimPrefix(value, "Bearer ")
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	return token, err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == token
}

func canonicalUint(value string) (uint64, bool) {
	if value == "" || (len(value) > 1 && value[0] == '0') || strings.HasPrefix(value, "+") {
		return 0, false
	}
	result, err := strconv.ParseUint(value, 10, 64)
	return result, err == nil && strconv.FormatUint(result, 10) == value
}
