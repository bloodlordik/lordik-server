package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/telegramdesktop/tproxy-server/internal/session"
)

const buildIDChars = "abcdefghijklmnopqrstuvwxyz0123456789"

func generateBuildID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "k9x2m4p1"
	}
	for i := range b {
		b[i] = buildIDChars[int(b[i])%len(buildIDChars)]
	}
	return string(b)
}

func parseCursorFromRequest(r *http.Request) uint64 {
	if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
		parts := strings.Split(reqID, ".")
		if len(parts) >= 2 {
			if c, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
				return c
			}
		}
	}
	if curStr := r.Header.Get("X-Down-Cursor"); curStr != "" {
		if c, err := strconv.ParseUint(curStr, 10, 64); err == nil {
			return c
		}
	}
	return 0
}

func (s *Server) resolveSession(r *http.Request, sessionShortID string, vhost *VHost) *session.Session {
	var sess *session.Session
	if key := r.Header.Get("X-Client-Key"); key != "" {
		if found, err := s.manager.Get(key); err == nil && found != nil {
			sess = found
		} else if found, err := s.manager.Resume(key, ""); err == nil && found != nil {
			sess = found
		}
	} else if tok, ok := bearerToken(r.Header.Get("Authorization")); ok {
		if found, err := s.manager.Get(tok); err == nil && found != nil {
			sess = found
		} else if found, err := s.manager.Resume(tok, ""); err == nil && found != nil {
			sess = found
		}
	} else if k := r.URL.Query().Get("k"); k != "" {
		if found, err := s.manager.Get(k); err == nil && found != nil {
			sess = found
		} else if found, err := s.manager.Resume(k, ""); err == nil && found != nil {
			sess = found
		}
	}
	if sess == nil {
		return nil
	}
	if vhost != nil && sess.Profile() != nil && !strings.EqualFold(sess.Profile().Hostname, vhost.Hostname) {
		return nil
	}
	if sessionShortID != "" && sess.ShortID() != "" && sess.ShortID() != sessionShortID {
		return nil
	}
	return sess
}

func (s *Server) serveCDN(w http.ResponseWriter, r *http.Request, vhost *VHost, suffix string) {
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

	// Route 1: POST _next/data/{build_id}/collect.json?k={prefix}
	// [0]: "_next", [1]: "data", [2]: build_id, [3]: "collect.json"
	if len(parts) == 4 && parts[0] == "_next" && parts[1] == "data" && parts[3] == "collect.json" {
		if r.Method != http.MethodPost || parts[2] != vhost.BuildID {
			vhost.servePublic(w, r)
			return
		}
		s.serveCDNCollect(w, r, vhost)
		return
	}

	// Route 2: GET _next/data/{build_id}/init/{bootstrap_token}/{hello_b64}.json
	// [0]: "_next", [1]: "data", [2]: build_id, [3]: "init", [4]: bootstrap_token, [5]: hello_b64.json
	if len(parts) == 6 && parts[0] == "_next" && parts[1] == "data" && parts[3] == "init" {
		if r.Method != http.MethodGet || parts[2] != vhost.BuildID {
			vhost.servePublic(w, r)
			return
		}
		s.serveCDNInit(w, r, vhost, parts[4], strings.TrimSuffix(parts[5], ".json"))
		return
	}

	// Route 3: GET assets/chunks/{session_short_id}/{seq}_{url_payload_b64}.bin
	// [0]: "assets", [1]: "chunks", [2]: session_short_id, [3]: {seq}_{url_payload_b64}.bin
	if len(parts) == 4 && parts[0] == "assets" && parts[1] == "chunks" {
		if r.Method != http.MethodGet {
			vhost.servePublic(w, r)
			return
		}
		s.serveCDNChunkGet(w, r, vhost, parts[2], parts[3])
		return
	}

	// Route 4: POST _next/data/{build_id}/sync/{session_short_id}/{seq}.bin
	// [0]: "_next", [1]: "data", [2]: build_id, [3]: "sync", [4]: session_short_id, [5]: seq.bin
	if len(parts) == 6 && parts[0] == "_next" && parts[1] == "data" && parts[3] == "sync" {
		if r.Method != http.MethodPost || parts[2] != vhost.BuildID {
			vhost.servePublic(w, r)
			return
		}
		s.serveCDNSyncPost(w, r, vhost, parts[4], strings.TrimSuffix(parts[5], ".bin"))
		return
	}

	// Route 5: GET assets/media/{session_short_id}/{seg|stream}_{cursor}_{rand}.m4s
	// [0]: "assets", [1]: "media", [2]: session_short_id, [3]: {seg|stream}_{cursor}_{rand}.m4s
	if len(parts) == 4 && parts[0] == "assets" && parts[1] == "media" {
		if r.Method != http.MethodGet {
			vhost.servePublic(w, r)
			return
		}
		cleanFile := strings.TrimSuffix(parts[3], ".m4s")
		if strings.HasPrefix(cleanFile, "stream_") || (strings.HasPrefix(cleanFile, "seg_") && r.Header.Get("X-Stream-Poll") == "1") {
			s.serveCDNStreamDown(w, r, vhost, parts[2], parts[3])
			return
		}
		s.serveCDNMediaPoll(w, r, vhost, parts[2], parts[3])
		return
	}

	// Route 6: GET _next/data/{build_id}/unload/{session_short_id}.json
	// [0]: "_next", [1]: "data", [2]: build_id, [3]: "unload", [4]: session_short_id.json
	if len(parts) == 5 && parts[0] == "_next" && parts[1] == "data" && parts[3] == "unload" {
		if r.Method != http.MethodGet || parts[2] != vhost.BuildID {
			vhost.servePublic(w, r)
			return
		}
		s.serveCDNUnload(w, r, vhost, strings.TrimSuffix(parts[4], ".json"))
		return
	}

	// Fallback to public site for unrecognized endpoints
	vhost.servePublic(w, r)
}

func (s *Server) serveCDNCollect(w http.ResponseWriter, r *http.Request, vhost *VHost) {
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

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Session-Token", res.Token)
	w.Header().Set("X-Resume-Token", res.ResumeToken)
	w.Header().Set("X-Carrier-Mode", "cdn-body")
	w.Header().Set("X-Down-Cursor", "0")
	w.Header().Set("Cache-Control", "private, no-store, no-cache, max-age=0, must-revalidate")
	w.Header().Set("CDN-Cache-Control", "no-store")
	w.Header().Set("Cloudflare-CDN-Cache-Control", "no-store")
	w.Header().Set("Surrogate-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Length", strconv.Itoa(len(res.Welcome)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(res.Welcome)
}

func (s *Server) serveCDNInit(w http.ResponseWriter, r *http.Request, vhost *VHost, bootstrapToken, helloFile string) {
	if !s.manager.HasBootstrapForHost(bootstrapToken, vhost.Hostname) {
		vhost.servePublic(w, r)
		return
	}

	helloBytes, err := base64.RawURLEncoding.DecodeString(helloFile)
	if err != nil {
		if pad := len(helloFile) % 4; pad != 0 {
			helloBytes, err = base64.URLEncoding.DecodeString(helloFile + strings.Repeat("=", 4-pad))
		}
	}
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
	resp := map[string]string{
		"token":        res.Token,
		"resume_token": res.ResumeToken,
		"short_id":     shortID,
		"welcome":      welcomeB64,
		"mode":         "cdn-get",
	}
	respJSON, _ := json.Marshal(resp)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Resume-Token", res.ResumeToken)
	w.Header().Set("Cache-Control", "private, no-store, no-cache, max-age=0, must-revalidate")
	w.Header().Set("CDN-Cache-Control", "no-store")
	w.Header().Set("Cloudflare-CDN-Cache-Control", "no-store")
	w.Header().Set("Surrogate-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Length", strconv.Itoa(len(respJSON)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respJSON)
}

func (s *Server) serveCDNChunkGet(w http.ResponseWriter, r *http.Request, vhost *VHost, sessionShortID, file string) {
	cleanFile := strings.TrimSuffix(file, ".bin")
	var seqStr, urlPayloadB64 string
	idx := strings.Index(cleanFile, "_")
	if idx > 0 {
		seqStr = cleanFile[:idx]
		urlPayloadB64 = cleanFile[idx+1:]
	} else {
		seqStr = cleanFile
	}
	if qp := r.URL.Query().Get("p"); qp != "" {
		urlPayloadB64 = qp
	}
	if seqStr == "" {
		vhost.servePublic(w, r)
		return
	}
	seq, err := strconv.ParseUint(seqStr, 10, 64)
	if err != nil {
		vhost.servePublic(w, r)
		return
	}

	var headerParts []string
	for i := 0; i < 8; i++ {
		val := r.Header.Get(fmt.Sprintf("X-Client-Data-%d", i))
		if val != "" {
			headerParts = append(headerParts, val)
		}
	}

	chunk, err := session.DecodeCDNPayload(urlPayloadB64, headerParts)
	if err != nil {
		vhost.servePublic(w, r)
		return
	}

	sess := s.resolveSession(r, sessionShortID, vhost)
	if sess == nil {
		vhost.servePublic(w, r)
		return
	}

	_, err = sess.ProcessUpCDN(seq, chunk)
	if err != nil {
		s.handleCDNSessionError(w, r, vhost, err)
		return
	}

	cursor := parseCursorFromRequest(r)
	coalesce := r.Header.Get("X-Coalesce") == "1" || r.URL.Query().Get("coalesce") == "1"
	downBytes, nextCursor, err := sess.PiggybackDownWait(cursor, coalesce)
	if err != nil {
		s.handleCDNSessionError(w, r, vhost, err)
		return
	}

	s.writeCDNDownlinkResponse(w, downBytes, nextCursor)
}

func (s *Server) serveCDNSyncPost(w http.ResponseWriter, r *http.Request, vhost *VHost, sessionShortID, seqStr string) {
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

	body, err := io.ReadAll(io.LimitReader(r.Body, int64(s.config.Limits.MaxBodyBytes+1)))
	if err != nil || len(body) > s.config.Limits.MaxBodyBytes {
		vhost.servePublic(w, r)
		return
	}

	_, err = sess.ProcessUpCDN(seq, body)
	if err != nil {
		s.handleCDNSessionError(w, r, vhost, err)
		return
	}

	cursor := parseCursorFromRequest(r)
	coalesce := r.Header.Get("X-Coalesce") == "1" || r.URL.Query().Get("coalesce") == "1"
	downBytes, nextCursor, err := sess.PiggybackDownWait(cursor, coalesce)
	if err != nil {
		s.handleCDNSessionError(w, r, vhost, err)
		return
	}

	s.writeCDNDownlinkResponse(w, downBytes, nextCursor)
}

func (s *Server) serveCDNMediaPoll(w http.ResponseWriter, r *http.Request, vhost *VHost, sessionShortID, file string) {
	cleanFile := strings.TrimSuffix(file, ".m4s")
	if !strings.HasPrefix(cleanFile, "seg_") {
		vhost.servePublic(w, r)
		return
	}
	parts := strings.Split(strings.TrimPrefix(cleanFile, "seg_"), "_")
	if len(parts) == 0 {
		vhost.servePublic(w, r)
		return
	}
	cursor, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		vhost.servePublic(w, r)
		return
	}

	sess := s.resolveSession(r, sessionShortID, vhost)
	if sess == nil {
		vhost.servePublic(w, r)
		return
	}

	pollTimeout := time.Duration(s.config.Limits.CDNPollTimeoutSecs) * time.Second
	if pollTimeout <= 0 {
		pollTimeout = 12 * time.Second
	}

	batch, nextCursor, err := sess.PollCDN(r.Context(), cursor, pollTimeout)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		s.handleCDNSessionError(w, r, vhost, err)
		return
	}

	s.writeCDNDownlinkResponse(w, batch, nextCursor)
}

func (s *Server) serveCDNUnload(w http.ResponseWriter, r *http.Request, vhost *VHost, sessionShortID string) {
	if key := r.Header.Get("X-Client-Key"); key != "" {
		if sess, err := s.manager.Get(key); err == nil && sess != nil {
			if sess.Profile() == nil || strings.EqualFold(sess.Profile().Hostname, vhost.Hostname) {
				_ = s.manager.CloseToken(key)
			}
		}
	} else if k := r.URL.Query().Get("k"); k != "" {
		if sess, err := s.manager.Get(k); err == nil && sess != nil {
			if sess.Profile() == nil || strings.EqualFold(sess.Profile().Hostname, vhost.Hostname) {
				_ = s.manager.CloseToken(k)
			}
		}
	} else if sess, err := s.manager.GetByShortID(sessionShortID); err == nil && sess != nil {
		if sess.Profile() == nil || strings.EqualFold(sess.Profile().Hostname, vhost.Hostname) {
			sess.Close()
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store, no-cache, max-age=0, must-revalidate")
	w.Header().Set("CDN-Cache-Control", "no-store")
	w.Header().Set("Cloudflare-CDN-Cache-Control", "no-store")
	w.Header().Set("Surrogate-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{\"s\":1}"))
}
func (s *Server) writeCDNDownlinkResponse(w http.ResponseWriter, batch []byte, cursor uint64) {
	w.Header().Set("Cache-Control", "private, no-store, no-cache, max-age=0, must-revalidate")
	w.Header().Set("CDN-Cache-Control", "no-store")
	w.Header().Set("Cloudflare-CDN-Cache-Control", "no-store")
	w.Header().Set("Surrogate-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Pragma", "no-cache")
	if len(batch) > 0 {
		gltf := session.WrapGLTF(batch, cursor)
		etag := fmt.Sprintf("\"W/%x-%x\"", cursor, len(batch))
		w.Header().Set("Content-Type", "model/gltf-binary")
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Length", strconv.Itoa(len(gltf)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gltf)
		return
	}
	resp := fmt.Sprintf("{\"s\":1,\"c\":%d}", cursor)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(resp)))
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, resp)
}


func (s *Server) handleCDNSessionError(w http.ResponseWriter, r *http.Request, vhost *VHost, err error) {
	if errors.Is(err, session.ErrBackpressure) || errors.Is(err, session.ErrConcurrent) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if vhost != nil {
		vhost.servePublic(w, r)
		return
	}
	s.servePublic(w, r)
}

func (s *Server) serveCDNLegacy(w http.ResponseWriter, r *http.Request, suffix string) {
	vhost := s.resolveVHost(r)
	if vhost == nil {
		vhost = s.defaultVHost
	}
	s.serveCDN(w, r, vhost, suffix)
}
