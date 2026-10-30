package server

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/telegramdesktop/tproxy-server/internal/config"
	"github.com/telegramdesktop/tproxy-server/internal/frame"
	"github.com/telegramdesktop/tproxy-server/internal/session"
)

func newTestEchoBackend(t *testing.T) (string, func()) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on tcp: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						_, _ = c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return l.Addr().String(), func() {
		_ = l.Close()
		wg.Wait()
	}
}

func setupYCWSServer(t *testing.T, backendAddr string) (*Server, *session.Manager, string, func()) {
	secret, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f10")
	cfg := config.Defaults()
	cfg.TokenKeyFile = filepath.Join(t.TempDir(), "token.key")
	if err := os.WriteFile(cfg.TokenKeyFile, bytes.Repeat([]byte{1}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("site"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "404.html"), []byte("not found"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.PublicDir = dir
	cfg.PublicHostname = "yc.example.com"
	cfg.Profiles = []config.Profile{
		{
			Name:        "yc-profile",
			CarrierMode: config.CarrierYCWS,
			Backend:     backendAddr,
			BackendType: config.BackendMTProxy,
			Hostname:    "yc.example.com",
			Capability:  config.DeriveCapability("yc.example.com", "", secret),
		},
	}
	cfg.Limits.MaxSessionsGlobal = 100
	cfg.Limits.MaxSessionsPerIP = 10
	cfg.Limits.MaxBootstrapsGlobal = 100
	cfg.Limits.MaxBootstrapsPerIP = 10
	cfg.Limits.MaxFramePayload = 1024 * 1024
	cfg.Limits.CDNUplinkWindowSize = 64
	cfg.Timeouts.LongPoll = config.Duration(500 * time.Millisecond)
	cfg.Timeouts.BackendDial = config.Duration(time.Second)
	cfg.Timeouts.BootstrapLifetime = config.Duration(5 * time.Minute)

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	return srv, srv.manager, "yc.example.com", func() {
		srv.Shutdown()
	}
}

func newReq(method, urlStr string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, urlStr, body)
	req.RemoteAddr = "127.0.0.1:12345"
	return req
}

func TestYCWSActiveProbingResistance(t *testing.T) {
	backendAddr, cleanupBackend := newTestEchoBackend(t)
	defer cleanupBackend()
	srv, _, _, cleanupMgr := setupYCWSServer(t, backendAddr)
	defer cleanupMgr()

	paths := []struct {
		method string
		url    string
		header map[string]string
	}{
		{"POST", "/_yc/session", nil},
		{"GET", "/_yc/init/invalid-token/hello.json", nil},
		{"POST", "/_yc/ws/connect", map[string]string{"X-Yc-Apigateway-Websocket-Connection-Id": "c1"}},
		{"POST", "/_yc/ws/message", map[string]string{"X-Yc-Apigateway-Websocket-Connection-Id": "c1"}},
		{"POST", "/_yc/up/random-id/1.bin", nil},
		{"GET", "/_yc/stream/random-id/stream_0_123.m4s", nil},
		{"GET", "/_yc/poll/random-id/seg_0_123.m4s", nil},
		{"POST", "/_yc/session", map[string]string{"Host": "attacker.com"}},
	}

	for _, tc := range paths {
		req := newReq(tc.method, tc.url, nil)
		if tc.header != nil {
			for k, v := range tc.header {
				req.Header.Set(k, v)
			}
		}
		if req.Header.Get("Host") == "" {
			req.Host = "yc.example.com"
		}
		w := httptest.NewRecorder()
		srv.serveHTTP(w, req)
		resp := w.Result()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404 for unauthenticated probe %s %s, got %d", tc.method, tc.url, resp.StatusCode)
		}
	}
}

func TestYCWSEndToEndCycle(t *testing.T) {
	backendAddr, cleanupBackend := newTestEchoBackend(t)
	defer cleanupBackend()
	srv, mgr, host, cleanupMgr := setupYCWSServer(t, backendAddr)
	defer cleanupMgr()

	// 1. Issue bootstrap token
	prof := &srv.config.Profiles[0]
	bootstrapToken, err := mgr.IssueBootstrap(prof, "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to issue bootstrap: %v", err)
	}

	// 2. POST /_yc/session with 9-byte HELLO frame
	hello := frame.Encode(frame.Hello, 0, []byte{1})
	sessReq := newReq("POST", "/_yc/session", bytes.NewReader(hello))
	sessReq.Host = host
	sessReq.Header.Set("X-Client-Key", bootstrapToken)
	sessReq.Header.Set("Content-Type", "application/octet-stream")
	sessW := httptest.NewRecorder()
	srv.serveHTTP(sessW, sessReq)
	sessResp := sessW.Result()
	if sessResp.StatusCode != http.StatusOK {
		t.Fatalf("session creation failed: %d", sessResp.StatusCode)
	}
	var sessJSON struct {
		Token       string `json:"token"`
		ResumeToken string `json:"resume_token"`
		ShortID     string `json:"short_id"`
		Welcome     string `json:"welcome"`
		Cursor      uint64 `json:"cursor"`
	}
	if err := json.NewDecoder(sessResp.Body).Decode(&sessJSON); err != nil {
		t.Fatalf("failed to decode session JSON: %v", err)
	}
	if sessJSON.Token == "" || sessJSON.ShortID == "" {
		t.Fatalf("empty token or short_id: %+v", sessJSON)
	}

	// 3. POST /_yc/ws/connect with YC connection ID header
	connID := "yc-conn-abc-123"
	connReq := newReq("POST", "/_yc/ws/connect?k="+sessJSON.Token, nil)
	connReq.Host = host
	connReq.Header.Set("X-Yc-Apigateway-Websocket-Connection-Id", connID)
	connW := httptest.NewRecorder()
	srv.serveHTTP(connW, connReq)
	if connW.Result().StatusCode != http.StatusOK {
		t.Fatalf("ws connect failed: %d", connW.Result().StatusCode)
	}

	// Verify manager connection binding
	boundSess := mgr.GetYCWSConn(connID)
	if boundSess == nil {
		t.Fatal("session not bound to connection ID in manager")
	}

	// 4. Send frames via POST /_yc/ws/message:
	// Out-of-order chunks: seq 2 (DATA frame) then seq 1 (OPEN frame)
	openFrame := frame.Encode(frame.Open, 1, nil)
	dataFrame := frame.Encode(frame.Data, 1, []byte("hello-yc-world"))

	// Chunk 2: seq=2, cursor=0, payload=dataFrame
	chunk2Env := make([]byte, 8+len(dataFrame))
	binary.BigEndian.PutUint32(chunk2Env[0:4], 2)
	binary.BigEndian.PutUint32(chunk2Env[4:8], 0)
	copy(chunk2Env[8:], dataFrame)
	chunk2B64 := base64.RawURLEncoding.EncodeToString(chunk2Env)

	msg2Req := newReq("POST", "/_yc/ws/message", strings.NewReader(chunk2B64))
	msg2Req.Host = host
	msg2Req.Header.Set("X-Yc-Apigateway-Websocket-Connection-Id", connID)
	msg2W := httptest.NewRecorder()
	srv.serveHTTP(msg2W, msg2Req)
	if msg2W.Result().StatusCode != http.StatusOK {
		t.Fatalf("msg2 failed: %d", msg2W.Result().StatusCode)
	}

	// Chunk 1: seq=1, cursor=0, payload=openFrame
	chunk1Env := make([]byte, 8+len(openFrame))
	binary.BigEndian.PutUint32(chunk1Env[0:4], 1)
	binary.BigEndian.PutUint32(chunk1Env[4:8], 0)
	copy(chunk1Env[8:], openFrame)
	chunk1B64 := base64.RawURLEncoding.EncodeToString(chunk1Env)

	msg1Req := newReq("POST", "/_yc/ws/message", strings.NewReader(chunk1B64))
	msg1Req.Host = host
	msg1Req.Header.Set("X-Yc-Apigateway-Websocket-Connection-Id", connID)
	msg1W := httptest.NewRecorder()
	srv.serveHTTP(msg1W, msg1Req)
	if msg1W.Result().StatusCode != http.StatusOK {
		t.Fatalf("msg1 failed: %d", msg1W.Result().StatusCode)
	}

	// 5. Downlink poll or stream should receive the echoed data
	time.Sleep(50 * time.Millisecond)

	pollReq := newReq("GET", "/_yc/poll/"+sessJSON.ShortID+"/seg_0_abcd.m4s", nil)
	pollReq.Host = host
	pollReq.Header.Set("X-Client-Key", sessJSON.Token)
	pollW := httptest.NewRecorder()
	srv.serveHTTP(pollW, pollReq)
	pollResp := pollW.Result()
	if pollResp.StatusCode != http.StatusOK {
		t.Fatalf("poll failed: %d", pollResp.StatusCode)
	}
	pollBody, _ := io.ReadAll(pollResp.Body)
	if len(pollBody) == 0 {
		t.Fatal("empty poll response")
	}
	cursor, gltfPayload, err := session.UnwrapGLTF(pollBody)
	if err != nil {
		t.Fatalf("failed to unwrap glTF: %v", err)
	}
	if cursor == 0 || !bytes.Contains(gltfPayload, []byte("hello-yc-world")) {
		t.Fatalf("expected echo in gltf payload, got cursor=%d payload=%s", cursor, hex.EncodeToString(gltfPayload))
	}

	// 6. POST /_yc/ws/message with pure ACK (seq=0, cursor)
	ackEnv := make([]byte, 8)
	binary.BigEndian.PutUint32(ackEnv[0:4], 0)
	binary.BigEndian.PutUint32(ackEnv[4:8], uint32(cursor))
	ackReq := newReq("POST", "/_yc/ws/message", strings.NewReader(base64.RawURLEncoding.EncodeToString(ackEnv)))
	ackReq.Host = host
	ackReq.Header.Set("X-Yc-Apigateway-Websocket-Connection-Id", connID)
	ackW := httptest.NewRecorder()
	srv.serveHTTP(ackW, ackReq)
	if ackW.Result().StatusCode != http.StatusOK {
		t.Fatalf("ack failed: %d", ackW.Result().StatusCode)
	}

	// 7. POST /_yc/ws/disconnect
	discReq := newReq("POST", "/_yc/ws/disconnect", nil)
	discReq.Host = host
	discReq.Header.Set("X-Yc-Apigateway-Websocket-Connection-Id", connID)
	discW := httptest.NewRecorder()
	srv.serveHTTP(discW, discReq)
	if discW.Result().StatusCode != http.StatusOK {
		t.Fatalf("disconnect failed: %d", discW.Result().StatusCode)
	}
	if mgr.GetYCWSConn(connID) != nil {
		t.Fatal("connection ID still mapped after disconnect")
	}

	// 8. Session unload
	unloadReq := newReq("POST", "/_yc/unload/"+sessJSON.ShortID+".json", nil)
	unloadReq.Host = host
	unloadReq.Header.Set("X-Client-Key", sessJSON.Token)
	unloadW := httptest.NewRecorder()
	srv.serveHTTP(unloadW, unloadReq)
	if unloadW.Result().StatusCode != http.StatusOK {
		t.Fatalf("unload failed: %d", unloadW.Result().StatusCode)
	}
	if boundSess.IsClosed() == false {
		t.Fatal("session was not closed on unload")
	}
}

func TestYCWSBackupHTTPOperation(t *testing.T) {
	backendAddr, cleanupBackend := newTestEchoBackend(t)
	defer cleanupBackend()
	srv, mgr, host, cleanupMgr := setupYCWSServer(t, backendAddr)
	defer cleanupMgr()

	prof := &srv.config.Profiles[0]
	bootstrapToken, err := mgr.IssueBootstrap(prof, "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to issue bootstrap: %v", err)
	}

	hello := frame.Encode(frame.Hello, 0, []byte{1})
	sessReq := newReq("POST", "/_yc/session", bytes.NewReader(hello))
	sessReq.Host = host
	sessReq.Header.Set("X-Client-Key", bootstrapToken)
	sessW := httptest.NewRecorder()
	srv.serveHTTP(sessW, sessReq)
	var sessJSON struct {
		Token   string `json:"token"`
		ShortID string `json:"short_id"`
	}
	_ = json.NewDecoder(sessW.Result().Body).Decode(&sessJSON)

	// Send chunk via HTTP fallback: POST /_yc/up/{short_id}/{seq}.bin
	openFrame := frame.Encode(frame.Open, 2, nil)
	upReq := newReq("POST", "/_yc/up/"+sessJSON.ShortID+"/1.bin", bytes.NewReader(openFrame))
	upReq.Host = host
	upReq.Header.Set("X-Client-Key", sessJSON.Token)
	upReq.Header.Set("X-Down-Cursor", "0")
	upW := httptest.NewRecorder()
	srv.serveHTTP(upW, upReq)
	if upW.Result().StatusCode != http.StatusOK {
		t.Fatalf("http up post failed: %d", upW.Result().StatusCode)
	}
}

func TestDecodeYCPayload(t *testing.T) {
	raw := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0xde, 0xad, 0xbe, 0xef}
	b64url := base64.RawURLEncoding.EncodeToString(raw)
	b64std := base64.StdEncoding.EncodeToString(raw)

	// 1. Base64url
	got1 := decodeYCPayload([]byte(b64url))
	if !bytes.Equal(got1, raw) {
		t.Fatalf("decodeYCPayload(b64url) = %x, want %x", got1, raw)
	}

	// 2. Base64 standard with whitespace and padding
	got2 := decodeYCPayload([]byte("  " + b64std + " \n"))
	if !bytes.Equal(got2, raw) {
		t.Fatalf("decodeYCPayload(b64std) = %x, want %x", got2, raw)
	}

	// 3. Raw binary
	got3 := decodeYCPayload(raw)
	if !bytes.Equal(got3, raw) {
		t.Fatalf("decodeYCPayload(raw) = %x, want %x", got3, raw)
	}

	// 4. Short payload
	short := []byte{0x01, 0x02}
	got4 := decodeYCPayload(short)
	if !bytes.Equal(got4, short) {
		t.Fatalf("decodeYCPayload(short) = %x, want %x", got4, short)
	}
}
