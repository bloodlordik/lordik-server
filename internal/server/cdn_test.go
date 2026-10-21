package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/telegramdesktop/tproxy-server/internal/config"
	"github.com/telegramdesktop/tproxy-server/internal/frame"
	"github.com/telegramdesktop/tproxy-server/internal/session"
)

func TestCDNActiveProbingResistance(t *testing.T) {
	backend := startEchoBackend(t)
	application, _ := newConfiguredTestServer(t, backend, func(value *config.Config) {
		value.Profiles[0].CarrierMode = config.CarrierCDNAdaptive
	})
	defer application.Shutdown()

	hosted := httptest.NewServer(application.Handler())
	defer hosted.Close()

	buildID := application.BuildID()

	// Probing attempts:
	// 1. GET collect without bootstrap
	// 2. POST collect with bogus token
	// 3. GET init with bogus token
	// 4. GET chunks without token
	// 5. GET media without token
	probingRequests := []*http.Request{
		request(t, http.MethodGet, hosted.URL+"/_next/data/"+buildID+"/collect.json", nil, ""),
		request(t, http.MethodPost, hosted.URL+"/_next/data/"+buildID+"/collect.json", []byte("probe"), ""),
		request(t, http.MethodGet, hosted.URL+"/_next/data/"+buildID+"/init/invalid_token/hello.json", nil, ""),
		request(t, http.MethodGet, hosted.URL+"/assets/chunks/invalid_short/1_payload.bin", nil, ""),
		request(t, http.MethodGet, hosted.URL+"/assets/media/invalid_short/seg_0_rand.m4s", nil, ""),
		request(t, http.MethodGet, hosted.URL+"/_next/data/"+buildID+"/unload/invalid_short.json", nil, ""),
	}

	for i, req := range probingRequests {
		res := perform(t, hosted.Client(), req)
		body := readResponse(t, res)
		// Should return public decoy 404
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("probe %d: expected status 404, got %d", i, res.StatusCode)
		}
		if !strings.Contains(string(body), "Operator Site") {
			t.Fatalf("probe %d: expected public site decoy body, got %q", i, string(body))
		}
		if res.Header.Get("X-Session-Token") != "" || res.Header.Get("X-Carrier-Mode") != "" {
			t.Fatalf("probe %d: proxy headers leaked in public response", i)
		}
	}
}

func TestCDNSessionEndToEnd(t *testing.T) {
	backend := startEchoBackend(t)
	application, _ := newConfiguredTestServer(t, backend, func(value *config.Config) {
		value.Profiles[0].CarrierMode = config.CarrierCDNAdaptive
	})
	defer application.Shutdown()

	hosted := httptest.NewServer(application.Handler())
	defer hosted.Close()

	buildID := application.BuildID()
	clientIP := "198.51.100.55"

	// 1. Issue bootstrap
	bootstrap, err := application.manager.IssueBootstrap(&application.config.Profiles[0], clientIP)
	if err != nil {
		t.Fatalf("IssueBootstrap failed: %v", err)
	}

	// 2. GET init handshake
	helloFrame := frame.Encode(frame.Hello, 0, []byte{1})
	helloB64 := base64.RawURLEncoding.EncodeToString(helloFrame)
	initURL := hosted.URL + "/_next/data/" + buildID + "/init/" + bootstrap + "/" + helloB64 + ".json"

	initReq := request(t, http.MethodGet, initURL, nil, clientIP)
	initReq.Header.Set("X-Client-Key", bootstrap)
	initRes := perform(t, hosted.Client(), initReq)
	initBody := readResponse(t, initRes)

	if initRes.StatusCode != http.StatusOK {
		t.Fatalf("init handshake failed: status=%d, body=%s", initRes.StatusCode, string(initBody))
	}

	var initJSON struct {
		Token   string `json:"token"`
		ShortID string `json:"short_id"`
		Welcome string `json:"welcome"`
		Mode    string `json:"mode"`
	}
	if err := json.Unmarshal(initBody, &initJSON); err != nil {
		t.Fatalf("decode init JSON failed: %v", err)
	}
	if initJSON.Token == "" || initJSON.ShortID == "" || initJSON.Mode != "cdn-get" {
		t.Fatalf("unexpected init response: %+v", initJSON)
	}

	sessionToken := initJSON.Token
	shortID := initJSON.ShortID

	// Verify WELCOME frame
	welcomeBytes, err := base64.RawURLEncoding.DecodeString(initJSON.Welcome)
	if err != nil {
		t.Fatalf("decode welcome frame failed: %v", err)
	}
	welcomeFrames, err := frame.ParseAll(welcomeBytes, 1024*1024)
	if err != nil || len(welcomeFrames) != 1 || welcomeFrames[0].Type != frame.Welcome {
		t.Fatalf("invalid welcome frame: %v", err)
	}

	// 3. Uplink OPEN + DATA frame via GET chunks (with header sharding)
	streamID := uint32(101)
	openFrame := frame.Encode(frame.Open, streamID, nil)
	payloadMsg := []byte("hello cdn echo")
	dataFrame := frame.Encode(frame.Data, streamID, payloadMsg)
	batch := append(openFrame, dataFrame...)

	urlPart, headers := session.EncodeCDNPayload(batch, 2048, 3584)
	chunkURL := hosted.URL + "/assets/chunks/" + shortID + "/1_" + urlPart + ".bin"

	chunkReq := request(t, http.MethodGet, chunkURL, nil, clientIP)
	chunkReq.Header.Set("X-Client-Key", sessionToken)
	chunkReq.Header.Set("X-Request-ID", "1.0.0")
	chunkReq.Header.Set("X-Down-Cursor", "0")
	for i, h := range headers {
		chunkReq.Header.Set(fmt.Sprintf("X-Client-Data-%d", i), h)
	}

	chunkRes := perform(t, hosted.Client(), chunkReq)
	chunkResBody := readResponse(t, chunkRes)
	if chunkRes.StatusCode != http.StatusOK {
		t.Fatalf("chunk uplink failed: status=%d, body=%s", chunkRes.StatusCode, string(chunkResBody))
	}
	// Verify that unauthorized chunk request with valid shortID but no X-Client-Key is rejected
	unauthChunkReq := request(t, http.MethodGet, chunkURL, nil, clientIP)
	unauthChunkRes := perform(t, hosted.Client(), unauthChunkReq)
	if unauthChunkRes.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for unauthenticated chunk GET, got %d", unauthChunkRes.StatusCode)
	}


	// 4. Downlink Long-Poll to receive the echoed data
	pollURL := hosted.URL + "/assets/media/" + shortID + "/seg_0_rand123.m4s"
	pollReq := request(t, http.MethodGet, pollURL, nil, clientIP)
	pollReq.Header.Set("X-Client-Key", sessionToken)

	pollRes := perform(t, hosted.Client(), pollReq)
	pollBody := readResponse(t, pollRes)
	if pollRes.StatusCode != http.StatusOK {
		t.Fatalf("media poll failed: status=%d, body=%s", pollRes.StatusCode, string(pollBody))
	}
	// Verify that unauthorized media poll with valid shortID but no X-Client-Key is rejected
	unauthPollReq := request(t, http.MethodGet, pollURL, nil, clientIP)
	unauthPollRes := perform(t, hosted.Client(), unauthPollReq)
	if unauthPollRes.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for unauthenticated media poll, got %d", unauthPollRes.StatusCode)
	}


	if pollRes.Header.Get("Content-Type") != "model/gltf-binary" {
		t.Fatalf("expected Content-Type model/gltf-binary, got %s", pollRes.Header.Get("Content-Type"))
	}

	cursor, demuxedBatch, err := session.UnwrapGLTF(pollBody)
	if err != nil {
		t.Fatalf("UnwrapGLTF on poll response failed: %v", err)
	}
	if cursor == 0 {
		t.Fatalf("expected cursor > 0, got %d", cursor)
	}

	recvFrames, err := frame.ParseAll(demuxedBatch, 1024*1024)
	if err != nil {
		t.Fatalf("ParseAll on demuxed downlink batch failed: %v", err)
	}

	var echoedPayload []byte
	for _, f := range recvFrames {
		if f.StreamID == streamID && f.Type == frame.Data {
			echoedPayload = append(echoedPayload, f.Payload...)
		}
	}
	if !bytes.Equal(echoedPayload, payloadMsg) {
		t.Fatalf("echoed payload mismatch: expected %q, got %q", payloadMsg, echoedPayload)
	}

	// 5. Unload session
	unloadURL := hosted.URL + "/_next/data/" + buildID + "/unload/" + shortID + ".json?t=123"
	unloadReq := request(t, http.MethodGet, unloadURL, nil, clientIP)
	unloadReq.Header.Set("X-Client-Key", sessionToken)
	unloadRes := perform(t, hosted.Client(), unloadReq)
	unloadBody := readResponse(t, unloadRes)

	if unloadRes.StatusCode != http.StatusOK {
		t.Fatalf("unload failed: status=%d, body=%s", unloadRes.StatusCode, string(unloadBody))
	}
	if string(unloadBody) != "{\"s\":1}" {
		t.Fatalf("unexpected unload body: %s", string(unloadBody))
	}

	// 6. Verify session is closed on subsequent poll
	closedPollReq := request(t, http.MethodGet, pollURL, nil, clientIP)
	closedPollReq.Header.Set("X-Client-Key", sessionToken)
	closedPollRes := perform(t, hosted.Client(), closedPollReq)
	_ = readResponse(t, closedPollRes)
	if closedPollRes.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after unload, got %d", closedPollRes.StatusCode)
	}
}

func TestCDNCollectAndSyncPost(t *testing.T) {
	backend := startEchoBackend(t)
	application, _ := newConfiguredTestServer(t, backend, func(value *config.Config) {
		value.Profiles[0].CarrierMode = config.CarrierCDNBody
	})
	defer application.Shutdown()

	hosted := httptest.NewServer(application.Handler())
	defer hosted.Close()

	buildID := application.BuildID()
	clientIP := "198.51.100.56"

	// 1. Issue bootstrap
	bootstrap, err := application.manager.IssueBootstrap(&application.config.Profiles[0], clientIP)
	if err != nil {
		t.Fatalf("IssueBootstrap failed: %v", err)
	}

	// 2. POST collect handshake
	helloFrame := frame.Encode(frame.Hello, 0, []byte{1})
	collectURL := hosted.URL + "/_next/data/" + buildID + "/collect.json?k=" + bootstrap[:8]
	collectReq := request(t, http.MethodPost, collectURL, helloFrame, clientIP)
	collectReq.Header.Set("X-Client-Key", bootstrap)
	collectReq.Header.Set("Content-Type", "application/octet-stream")

	collectRes := perform(t, hosted.Client(), collectReq)
	collectBody := readResponse(t, collectRes)

	if collectRes.StatusCode != http.StatusOK {
		t.Fatalf("collect POST failed: status=%d, body=%s", collectRes.StatusCode, string(collectBody))
	}
	sessionToken := collectRes.Header.Get("X-Session-Token")
	if sessionToken == "" {
		t.Fatal("missing X-Session-Token")
	}
	if collectRes.Header.Get("X-Carrier-Mode") != "cdn-body" {
		t.Fatalf("unexpected carrier mode header: %s", collectRes.Header.Get("X-Carrier-Mode"))
	}
	shortID := sessionToken[:12]

	// 3. POST sync uplink
	streamID := uint32(202)
	batch := append(frame.Encode(frame.Open, streamID, nil), frame.Encode(frame.Data, streamID, []byte("sync data post"))...)

	syncURL := hosted.URL + "/_next/data/" + buildID + "/sync/" + shortID + "/1.bin"
	syncReq := request(t, http.MethodPost, syncURL, batch, clientIP)
	syncReq.Header.Set("X-Client-Key", sessionToken)
	syncReq.Header.Set("X-Request-ID", "1.0.0")
	syncReq.Header.Set("X-Down-Cursor", "0")
	syncReq.Header.Set("Content-Type", "application/octet-stream")

	syncRes := perform(t, hosted.Client(), syncReq)
	syncBody := readResponse(t, syncRes)
	if syncRes.StatusCode != http.StatusOK {
		t.Fatalf("sync POST failed: status=%d, body=%s", syncRes.StatusCode, string(syncBody))
	}

	// Wait brief moment for echo backend to reply and then poll
	time.Sleep(20 * time.Millisecond)

	pollURL := hosted.URL + "/assets/media/" + shortID + "/seg_0_sync1.m4s"
	pollReq := request(t, http.MethodGet, pollURL, nil, clientIP)
	pollReq.Header.Set("X-Client-Key", sessionToken)

	pollRes := perform(t, hosted.Client(), pollReq)
	pollBody := readResponse(t, pollRes)
	if pollRes.StatusCode != http.StatusOK {
		t.Fatalf("sync media poll failed: status=%d, body=%s", pollRes.StatusCode, string(pollBody))
	}

	cursor, demuxed, err := session.UnwrapGLTF(pollBody)
	if err != nil {
		t.Fatalf("UnwrapGLTF failed: %v", err)
	}
	if cursor == 0 {
		t.Fatalf("expected cursor > 0, got %d", cursor)
	}

	recvFrames, err := frame.ParseAll(demuxed, 1024*1024)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}
	var echoed []byte
	for _, f := range recvFrames {
		if f.StreamID == streamID && f.Type == frame.Data {
			echoed = append(echoed, f.Payload...)
		}
	}
	if string(echoed) != "sync data post" {
		t.Fatalf("expected 'sync data post', got %q", string(echoed))
	}
}

func TestCDNChunkGetWithQueryParamPayload(t *testing.T) {
	backend := startEchoBackend(t)
	application, _ := newConfiguredTestServer(t, backend, func(value *config.Config) {
		value.Profiles[0].CarrierMode = config.CarrierCDNAdaptive
	})
	defer application.Shutdown()

	hosted := httptest.NewServer(application.Handler())
	defer hosted.Close()

	buildID := application.BuildID()
	clientIP := "198.51.100.56"

	bootstrap, err := application.manager.IssueBootstrap(&application.config.Profiles[0], clientIP)
	if err != nil {
		t.Fatalf("IssueBootstrap failed: %v", err)
	}

	helloFrame := frame.Encode(frame.Hello, 0, []byte{1})
	helloB64 := base64.RawURLEncoding.EncodeToString(helloFrame)
	initURL := hosted.URL + "/_next/data/" + buildID + "/init/" + bootstrap + "/" + helloB64 + ".json"

	initReq := request(t, http.MethodGet, initURL, nil, clientIP)
	initReq.Header.Set("X-Client-Key", bootstrap)
	initRes := perform(t, hosted.Client(), initReq)
	initBody := readResponse(t, initRes)
	if initRes.StatusCode != http.StatusOK {
		t.Fatalf("init handshake failed: %d %s", initRes.StatusCode, string(initBody))
	}

	var initJSON struct {
		Token   string `json:"token"`
		ShortID string `json:"short_id"`
		Welcome string `json:"welcome"`
	}
	_ = json.Unmarshal(initBody, &initJSON)

	// Uplink OPEN frame using query param format: /assets/chunks/{short_id}/{seq}.bin?p={payload}
	openFrame := frame.Encode(frame.Open, 202, nil)
	openB64 := base64.RawURLEncoding.EncodeToString(openFrame)
	chunkURL := hosted.URL + "/assets/chunks/" + initJSON.ShortID + "/1.bin?p=" + openB64

	chunkReq := request(t, http.MethodGet, chunkURL, nil, clientIP)
	chunkReq.Header.Set("X-Client-Key", initJSON.Token)
	chunkReq.Header.Set("X-Request-ID", "1.0.0")

	chunkRes := perform(t, hosted.Client(), chunkReq)
	if chunkRes.StatusCode != http.StatusOK {
		t.Fatalf("chunk GET with ?p= failed: %d", chunkRes.StatusCode)
	}
	if chunkRes.Header.Get("CDN-Cache-Control") != "no-store" {
		t.Fatalf("missing CDN-Cache-Control header")
	}
}
