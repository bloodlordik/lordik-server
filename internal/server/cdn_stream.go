package server

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"github.com/telegramdesktop/tproxy-server/internal/session"
)

func (s *Server) serveCDNStreamDown(w http.ResponseWriter, r *http.Request, vhost *VHost, sessionShortID, file string) {
	cleanFile := strings.TrimSuffix(file, ".m4s")
	var prefix string
	if strings.HasPrefix(cleanFile, "stream_") {
		prefix = "stream_"
	} else if strings.HasPrefix(cleanFile, "seg_") {
		prefix = "seg_"
	} else {
		vhost.servePublic(w, r)
		return
	}
	parts := strings.Split(strings.TrimPrefix(cleanFile, prefix), "_")
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

	if cursor > sess.DownCursor() {
		s.handleCDNSessionError(w, r, vhost, session.ErrProtocol)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		s.serveCDNMediaPoll(w, r, vhost, sessionShortID, file)
		return
	}

	isSSE := r.Header.Get("X-SSE-Stream") == "1" || strings.Contains(r.Header.Get("Accept"), "text/event-stream")
	if isSSE {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("Cache-Control", "private, no-store, no-cache, no-transform, max-age=0, must-revalidate")
		w.Header().Set("CDN-Cache-Control", "no-store")
		w.Header().Set("Cloudflare-CDN-Cache-Control", "no-store")
		w.Header().Set("Surrogate-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusOK)

		rc := http.NewResponseController(w)
		_ = rc.SetWriteDeadline(time.Now().Add(15 * time.Second))

		if _, err := io.WriteString(w, ": ok\n\n"); err != nil {
			return
		}
		flusher.Flush()

		bw := bufio.NewWriterSize(w, 64*1024)
		onBatch := func(cur uint64, body []byte) error {
			_ = rc.SetWriteDeadline(time.Now().Add(15 * time.Second))
			if len(body) == 0 {
				if _, err := fmt.Fprintf(bw, ": hb %d\n\n", cur); err != nil {
					return err
				}
			} else {
				env := make([]byte, 4+len(body))
				binary.BigEndian.PutUint32(env[:4], uint32(cur))
				copy(env[4:], body)
				enc := base64.RawURLEncoding.EncodeToString(env)
				if _, err := fmt.Fprintf(bw, "data: %s\n\n", enc); err != nil {
					return err
				}
			}
			if err := bw.Flush(); err != nil {
				return err
			}
			flusher.Flush()
			return nil
		}

		_ = sess.StreamCDN(r.Context(), cursor, onBatch)
		return
	}

	w.Header().Set("Content-Type", "model/gltf-binary")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "private, no-store, no-cache, max-age=0, must-revalidate")
	w.Header().Set("CDN-Cache-Control", "no-store")
	w.Header().Set("Cloudflare-CDN-Cache-Control", "no-store")
	w.Header().Set("Surrogate-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)

	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(15 * time.Second))

	// Объединяем 12 байт GLTFStreamHeader и 8 байт первого пустого конверта (length = 0)
	// в единый 20-байтовый буфер на стеке и делаем ровно один Flush!
	var initPkt [20]byte
	copy(initPkt[0:12], session.GLTFStreamHeader[:])
	binary.BigEndian.PutUint32(initPkt[12:16], uint32(cursor))
	binary.BigEndian.PutUint32(initPkt[16:20], 0)
	if _, err := w.Write(initPkt[:]); err != nil {
		return
	}
	flusher.Flush()

	bw := bufio.NewWriterSize(w, 64*1024)

	onBatch := func(cur uint64, body []byte) error {
		_ = rc.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if err := session.WriteBatchEnvelope(bw, cur, body); err != nil {
			return err
		}
		if err := bw.Flush(); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}

	_ = sess.StreamCDN(r.Context(), cursor, onBatch)
}
