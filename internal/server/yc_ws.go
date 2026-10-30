package server

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/telegramdesktop/tproxy-server/internal/session"
)

// serveYCWS routes requests under the `_yc/` prefix for Yandex Cloud API Gateway.
func (s *Server) serveYCWS(w http.ResponseWriter, r *http.Request, vhost *VHost, suffix string) {
	if vhost == nil {
		s.servePublic(w, r)
		return
	}
	// Anti-probing: client IP must be resolvable
	if _, err := s.clientIPForVHost(r, vhost); err != nil {
		vhost.servePublic(w, r)
		return
	}

	parts := strings.Split(suffix, "/")
	if len(parts) < 2 || parts[0] != "_yc" {
		vhost.servePublic(w, r)
		return
	}

	// Route 1: POST _yc/session
	if len(parts) == 2 && parts[1] == "session" {
		if r.Method != http.MethodPost {
			vhost.servePublic(w, r)
			return
		}
		s.serveYCWSSession(w, r, vhost)
		return
	}

	// Route 2: GET _yc/init/{bootstrap_token}/{hello_b64}.json
	if len(parts) == 4 && parts[1] == "init" {
		if r.Method != http.MethodGet {
			vhost.servePublic(w, r)
			return
		}
		s.serveYCWSInit(w, r, vhost, parts[2], strings.TrimSuffix(parts[3], ".json"))
		return
	}

	// Route 3: GET or POST _yc/unload/{short_id}.json
	if len(parts) == 3 && parts[1] == "unload" {
		s.serveYCWSUnload(w, r, vhost, strings.TrimSuffix(parts[2], ".json"))
		return
	}

	// Route 4: POST _yc/ws/connect
	if len(parts) == 3 && parts[1] == "ws" && parts[2] == "connect" {
		if r.Method != http.MethodPost {
			vhost.servePublic(w, r)
			return
		}
		s.serveYCWSConnect(w, r, vhost)
		return
	}

	// Route 5: POST _yc/ws/message
	if len(parts) == 3 && parts[1] == "ws" && parts[2] == "message" {
		if r.Method != http.MethodPost {
			vhost.servePublic(w, r)
			return
		}
		s.serveYCWSMessage(w, r, vhost)
		return
	}

	// Route 6: POST _yc/ws/disconnect
	if len(parts) == 3 && parts[1] == "ws" && parts[2] == "disconnect" {
		if r.Method != http.MethodPost {
			vhost.servePublic(w, r)
			return
		}
		s.serveYCWSDisconnect(w, r, vhost)
		return
	}

	// Route 7: POST _yc/up/{short_id}/{seq}.bin
	if len(parts) == 4 && parts[1] == "up" {
		if r.Method != http.MethodPost {
			vhost.servePublic(w, r)
			return
		}
		s.serveYCWSUpPost(w, r, vhost, parts[2], strings.TrimSuffix(parts[3], ".bin"))
		return
	}

	// Route 8: GET _yc/stream/{short_id}/{file}
	if len(parts) == 4 && parts[1] == "stream" {
		if r.Method != http.MethodGet {
			vhost.servePublic(w, r)
			return
		}
		s.serveCDNStreamDown(w, r, vhost, parts[2], parts[3])
		return
	}

	// Route 9: GET _yc/poll/{short_id}/{file}
	if len(parts) == 4 && parts[1] == "poll" {
		if r.Method != http.MethodGet {
			vhost.servePublic(w, r)
			return
		}
		s.serveCDNMediaPoll(w, r, vhost, parts[2], parts[3])
		return
	}

	vhost.servePublic(w, r)
}

func (s *Server) serveYCWSSession(w http.ResponseWriter, r *http.Request, vhost *VHost) {
	token := r.Header.Get("X-Client-Key")
	if token == "" {
		token = r.URL.Query().Get("k")
	}
	if token == "" || !s.manager.HasBootstrapForHost(token, vhost.Hostname) {
		vhost.servePublic(w, r)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxCreateBodyBytes+1))
	if err != nil || len(body) > maxCreateBodyBytes {
		vhost.servePublic(w, r)
		return
	}
	clientIP, err := s.clientIPForVHost(r, vhost)
	if err != nil {
		vhost.servePublic(w, r)
		return
	}
	res, err := s.manager.Create(token, clientIP, body)
	if err != nil {
		vhost.servePublic(w, r)
		return
	}

	shortID := res.Token
	if len(res.Token) >= 12 {
		shortID = res.Token[:12]
	}
	welcomeB64 := base64.RawURLEncoding.EncodeToString(res.Welcome)
	resp := map[string]interface{}{
		"token":        res.Token,
		"resume_token": res.ResumeToken,
		"short_id":     shortID,
		"welcome":      welcomeB64,
		"cursor":       0,
	}
	respJSON, _ := json.Marshal(resp)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store, no-cache, max-age=0, must-revalidate")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Length", strconv.Itoa(len(respJSON)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respJSON)
}

func (s *Server) serveYCWSInit(w http.ResponseWriter, r *http.Request, vhost *VHost, bootstrapToken, helloFile string) {
	if !s.manager.HasBootstrapForHost(bootstrapToken, vhost.Hostname) {
		vhost.servePublic(w, r)
		return
	}

	helloBytes, err := base64.RawURLEncoding.DecodeString(helloFile)
	if err != nil || len(helloBytes) > maxCreateBodyBytes {
		vhost.servePublic(w, r)
		return
	}

	clientIP, err := s.clientIPForVHost(r, vhost)
	if err != nil {
		vhost.servePublic(w, r)
		return
	}
	res, err := s.manager.Create(bootstrapToken, clientIP, helloBytes)
	if err != nil {
		vhost.servePublic(w, r)
		return
	}

	shortID := res.Token
	if len(res.Token) >= 12 {
		shortID = res.Token[:12]
	}
	welcomeB64 := base64.RawURLEncoding.EncodeToString(res.Welcome)
	resp := map[string]interface{}{
		"token":        res.Token,
		"resume_token": res.ResumeToken,
		"short_id":     shortID,
		"welcome":      welcomeB64,
		"cursor":       0,
	}
	respJSON, _ := json.Marshal(resp)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store, no-cache, max-age=0, must-revalidate")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Length", strconv.Itoa(len(respJSON)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respJSON)
}

func (s *Server) serveYCWSUnload(w http.ResponseWriter, r *http.Request, vhost *VHost, sessionShortID string) {
	if key := r.Header.Get("X-Client-Key"); key != "" {
		_ = s.manager.CloseToken(key)
	} else if tok, ok := bearerToken(r.Header.Get("Authorization")); ok {
		_ = s.manager.CloseToken(tok)
	} else if k := r.URL.Query().Get("k"); k != "" {
		_ = s.manager.CloseToken(k)
	} else if sess, err := s.manager.GetByShortID(sessionShortID); err == nil && sess != nil {
		if sess.Profile() == nil || strings.EqualFold(sess.Profile().Hostname, vhost.Hostname) {
			sess.Close()
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store, no-cache, max-age=0, must-revalidate")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"s":1}`))
}

func (s *Server) serveYCWSConnect(w http.ResponseWriter, r *http.Request, vhost *VHost) {
	connID := r.Header.Get("X-Yc-Apigateway-Websocket-Connection-Id")
	token := r.URL.Query().Get("k")
	if token == "" {
		token = r.Header.Get("X-Client-Key")
	}
	if token == "" {
		if tok, ok := bearerToken(r.Header.Get("Authorization")); ok {
			token = tok
		}
	}
	if connID == "" || token == "" {
		vhost.servePublic(w, r)
		return
	}

	var sess *session.Session
	if sFound, err := s.manager.Get(token); err == nil && sFound != nil {
		sess = sFound
	} else if sFound, err := s.manager.Resume(token, ""); err == nil && sFound != nil {
		sess = sFound
	}
	if sess == nil || sess.IsClosed() {
		vhost.servePublic(w, r)
		return
	}
	if sess.Profile() != nil && !strings.EqualFold(sess.Profile().Hostname, vhost.Hostname) {
		vhost.servePublic(w, r)
		return
	}

	s.manager.BindYCWSConn(connID, sess)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store, no-cache, max-age=0, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"s":1}`))
}

func decodeYCPayload(body []byte) []byte {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) < 8 {
		return body
	}
	isB64 := true
	for _, b := range trimmed {
		if !((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' || b == '_' || b == '+' || b == '/' || b == '=') {
			isB64 = false
			break
		}
	}
	if !isB64 {
		return body
	}

	trimmedNoPad := bytes.TrimRight(trimmed, "=")
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(trimmedNoPad)))
	n, err := base64.RawURLEncoding.Decode(decoded, trimmedNoPad)
	if err == nil && n >= 8 {
		return decoded[:n]
	}

	decodedStd := make([]byte, base64.StdEncoding.DecodedLen(len(trimmed)))
	n, err = base64.StdEncoding.Decode(decodedStd, trimmed)
	if err == nil && n >= 8 {
		return decodedStd[:n]
	}

	return body
}

func (s *Server) serveYCWSMessage(w http.ResponseWriter, r *http.Request, vhost *VHost) {
	connID := r.Header.Get("X-Yc-Apigateway-Websocket-Connection-Id")
	var sess *session.Session
	if connID != "" {
		sess = s.manager.GetYCWSConn(connID)
	}
	if sess == nil {
		sess = s.resolveSession(r, "", vhost)
	}
	if sess == nil || sess.IsClosed() {
		vhost.servePublic(w, r)
		return
	}
	if sess.Profile() != nil && !strings.EqualFold(sess.Profile().Hostname, vhost.Hostname) {
		vhost.servePublic(w, r)
		return
	}

	maxBodyBytes := 2 * 1024 * 1024
	if s.config.Limits.MaxFramePayload > 0 {
		maxBodyBytes = s.config.Limits.MaxFramePayload * 4
		if maxBodyBytes < 65536 {
			maxBodyBytes = 65536
		}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(maxBodyBytes+1)))
	if err != nil || len(body) == 0 || len(body) > maxBodyBytes {
		vhost.servePublic(w, r)
		return
	}

	payload := decodeYCPayload(body)
	if len(payload) < 8 {
		s.handleCDNSessionError(w, r, vhost, session.ErrProtocol)
		return
	}

	seq := binary.BigEndian.Uint32(payload[0:4])
	clientCursor := binary.BigEndian.Uint32(payload[4:8])

	if err := sess.AckDownCDN(clientCursor); err != nil {
		s.handleCDNSessionError(w, r, vhost, err)
		return
	}

	if seq == 0 && len(payload) == 8 {
		// Pure ACK
		resp := fmt.Sprintf(`{"s":1,"c":%d,"u":%d}`, sess.DownCursor(), sess.NextUpSeq())
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, no-store, no-cache, max-age=0, must-revalidate")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, resp)
		return
	}

	if seq > 0 {
		_, err := sess.ProcessUpCDN(uint64(seq), payload[8:])
		if err != nil {
			s.handleCDNSessionError(w, r, vhost, err)
			return
		}
	}

	resp := fmt.Sprintf(`{"s":1,"c":%d,"u":%d}`, sess.DownCursor(), sess.NextUpSeq())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store, no-cache, max-age=0, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, resp)
}

func (s *Server) serveYCWSDisconnect(w http.ResponseWriter, r *http.Request, vhost *VHost) {
	connID := r.Header.Get("X-Yc-Apigateway-Websocket-Connection-Id")
	if connID != "" {
		s.manager.UnbindYCWSConn(connID)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store, no-cache, max-age=0, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"s":1}`))
}

func (s *Server) serveYCWSUpPost(w http.ResponseWriter, r *http.Request, vhost *VHost, sessionShortID, seqStr string) {
	seq, err := strconv.ParseUint(seqStr, 10, 64)
	if err != nil {
		vhost.servePublic(w, r)
		return
	}

	sess := s.resolveSession(r, sessionShortID, vhost)
	if sess == nil {
		vhost.servePublic(w, r)
		return
	}

	cursor := parseCursorFromRequest(r)
	if cursor == 0 {
		if cStr := r.URL.Query().Get("c"); cStr != "" {
			if c, err := strconv.ParseUint(cStr, 10, 64); err == nil {
				cursor = c
			}
		}
	}

	if err := sess.AckDownCDN(uint32(cursor)); err != nil {
		s.handleCDNSessionError(w, r, vhost, err)
		return
	}

	maxBodyBytes := 2 * 1024 * 1024
	if s.config.Limits.MaxFramePayload > 0 {
		maxBodyBytes = s.config.Limits.MaxFramePayload * 4
		if maxBodyBytes < 65536 {
			maxBodyBytes = 65536
		}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(maxBodyBytes+1)))
	if err != nil || len(body) > maxBodyBytes {
		vhost.servePublic(w, r)
		return
	}

	if len(body) > 0 {
		_, err := sess.ProcessUpCDN(seq, body)
		if err != nil {
			s.handleCDNSessionError(w, r, vhost, err)
			return
		}
	}

	resp := fmt.Sprintf(`{"s":1,"c":%d,"u":%d}`, sess.DownCursor(), sess.NextUpSeq())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store, no-cache, max-age=0, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, resp)
}
