package server

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/telegramdesktop/tproxy-server/internal/config"
	"github.com/telegramdesktop/tproxy-server/internal/frame"
)

func TestMultiDomainRoutingAndVHostIsolation(t *testing.T) {
	backend := startEchoBackend(t)
	tmpDir := t.TempDir()

	tokenKeyPath := filepath.Join(tmpDir, "token.key")
	if err := os.WriteFile(tokenKeyPath, bytes.Repeat([]byte{2}, 32), 0600); err != nil {
		t.Fatal(err)
	}

	siteADir := filepath.Join(tmpDir, "siteA")
	if err := os.MkdirAll(siteADir, 0700); err != nil {
		t.Fatal(err)
	}
	indexA := []byte("<!doctype html><title>Site A</title>")
	if err := os.WriteFile(filepath.Join(siteADir, "index.html"), indexA, 0600); err != nil {
		t.Fatal(err)
	}

	siteBDir := filepath.Join(tmpDir, "siteB")
	if err := os.MkdirAll(siteBDir, 0700); err != nil {
		t.Fatal(err)
	}
	indexB := []byte("<!doctype html><title>Site B</title>")
	if err := os.WriteFile(filepath.Join(siteBDir, "index.html"), indexB, 0600); err != nil {
		t.Fatal(err)
	}

	secretA, _ := hex.DecodeString("000102030405060708090a0b0c0d0e01")
	secretB, _ := hex.DecodeString("000102030405060708090a0b0c0d0e02")

	hostA := "direct.example.com"
	hostB := "cdn.example.com"
	hostC := "gateway.example.com"

	capA := config.DeriveCapability(hostA, "", secretA)
	capB := config.DeriveCapability(hostB, "assets", secretB)
	capC := config.DeriveCapability(hostC, "proxy", secretA)

	cfg := config.Defaults()
	cfg.PublicHostname = hostA
	cfg.PublicDir = siteADir
	cfg.TokenKeyFile = tokenKeyPath
	cfg.Profiles = []config.Profile{
		{
			Name:        "profile-a",
			Secret:      "000102030405060708090a0b0c0d0e01",
			Backend:     backend,
			CarrierMode: config.CarrierHTTPS,
			Hostname:    hostA,
			Capability:  capA,
			PublicDir:   siteADir,
		},
		{
			Name:               "profile-b",
			Secret:             "000102030405060708090a0b0c0d0e02",
			Backend:            backend,
			CarrierMode:        config.CarrierCDNAdaptive,
			Hostname:           hostB,
			BasePath:           "assets",
			Capability:         capB,
			PublicDir:          siteBDir,
			TrustedIPHeader:    "CF-Connecting-IP",
			DisableIPRateLimit: true,
		},
		{
			Name:              "profile-c",
			Secret:            "000102030405060708090a0b0c0d0e01",
			Backend:           backend,
			CarrierMode:       config.CarrierHTTPSLanes,
			Hostname:          hostC,
			BasePath:          "proxy",
			Capability:        capC,
			TrustedHostHeader: "X-Forwarded-Host",
		},
	}

	app, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer app.Shutdown()

	hosted := httptest.NewServer(app.Handler())
	defer hosted.Close()

	client := hosted.Client()

	// 1. Decoy Isolation: unauthenticated requests receive their respective decoy
	reqA, _ := http.NewRequest(http.MethodGet, hosted.URL+"/", nil)
	reqA.Host = hostA
	respA, err := client.Do(reqA)
	if err != nil {
		t.Fatal(err)
	}
	bodyA, _ := io.ReadAll(respA.Body)
	respA.Body.Close()
	if !bytes.Equal(bodyA, indexA) {
		t.Fatalf("hostA decoy mismatch: got %q, want %q", bodyA, indexA)
	}

	reqB, _ := http.NewRequest(http.MethodGet, hosted.URL+"/", nil)
	reqB.Host = hostB
	respB, err := client.Do(reqB)
	if err != nil {
		t.Fatal(err)
	}
	bodyB, _ := io.ReadAll(respB.Body)
	respB.Body.Close()
	if !bytes.Equal(bodyB, indexB) {
		t.Fatalf("hostB decoy mismatch: got %q, want %q", bodyB, indexB)
	}

	// 2. Bridge Retrieval: correct capability on correct host succeeds
	bridgeReqA, _ := http.NewRequest(http.MethodGet, hosted.URL+"/?bridge="+config.CapabilityString(capA), nil)
	bridgeReqA.Host = hostA
	bridgeReqA.Header.Set("X-Forwarded-For", "198.51.100.1")
	bridgeRespA, err := client.Do(bridgeReqA)
	if err != nil {
		t.Fatal(err)
	}
	bridgeBodyA, _ := io.ReadAll(bridgeRespA.Body)
	bridgeRespA.Body.Close()
	if bridgeRespA.StatusCode != http.StatusOK || !bytes.Contains(bridgeBodyA, []byte("tproxy-init")) {
		t.Fatalf("hostA bridge failed: status %d", bridgeRespA.StatusCode)
	}

	// 3. Cross-Domain Capability Probing: capA sent to hostB is rejected with decoy/404
	bridgeReqWrong, _ := http.NewRequest(http.MethodGet, hosted.URL+"/?bridge="+config.CapabilityString(capA), nil)
	bridgeReqWrong.Host = hostB
	bridgeRespWrong, err := client.Do(bridgeReqWrong)
	if err != nil {
		t.Fatal(err)
	}
	bodyWrong, _ := io.ReadAll(bridgeRespWrong.Body)
	bridgeRespWrong.Body.Close()
	if bridgeRespWrong.StatusCode == http.StatusOK && bytes.Contains(bodyWrong, []byte("tproxy-init")) {
		t.Fatal("hostB accepted capability minted for hostA!")
	}

	// 4. Session Creation and Cross-Domain Isolation:
	// Issue bootstrap for hostA
	tokenA, err := app.manager.IssueBootstrap(&cfg.Profiles[0], "198.51.100.1")
	if err != nil {
		t.Fatalf("issue bootstrap A: %v", err)
	}

	// Attempt to create session using tokenA on hostB -> MUST fail
	hello := frame.Encode(frame.Hello, 0, []byte{1})
	createReqWrong, _ := http.NewRequest(http.MethodPost, hosted.URL+"/assets/api/v1/session", bytes.NewReader(hello))
	createReqWrong.Host = hostB
	createReqWrong.Header.Set("Authorization", "Bearer "+tokenA)
	createReqWrong.Header.Set("Content-Type", "application/octet-stream")
	createReqWrong.Header.Set("X-Forwarded-For", "198.51.100.1")
	respCreateWrong, err := client.Do(createReqWrong)
	if err != nil {
		t.Fatal(err)
	}
	respCreateWrong.Body.Close()
	if respCreateWrong.StatusCode != http.StatusNotFound {
		t.Fatalf("tokenA on hostB session create was not rejected: %d", respCreateWrong.StatusCode)
	}

	// Create session on hostA -> succeeds
	createReqA, _ := http.NewRequest(http.MethodPost, hosted.URL+"/api/v1/session", bytes.NewReader(hello))
	createReqA.Host = hostA
	createReqA.Header.Set("Authorization", "Bearer "+tokenA)
	createReqA.Header.Set("Content-Type", "application/octet-stream")
	createReqA.Header.Set("X-Forwarded-For", "198.51.100.1")
	respCreateA, err := client.Do(createReqA)
	if err != nil {
		t.Fatal(err)
	}
	sessionTokenA := respCreateA.Header.Get("X-Session-Token")
	respCreateA.Body.Close()
	if respCreateA.StatusCode != http.StatusOK || sessionTokenA == "" {
		t.Fatalf("session create A failed: status %d", respCreateA.StatusCode)
	}

	// Uplink on hostB using sessionTokenA -> MUST fail
	openFrame := frame.Encode(frame.Open, 1, nil)
	upReqWrong, _ := http.NewRequest(http.MethodPost, hosted.URL+"/assets/api/v1/up", bytes.NewReader(openFrame))
	upReqWrong.Host = hostB
	upReqWrong.Header.Set("Authorization", "Bearer "+sessionTokenA)
	upReqWrong.Header.Set("Content-Type", "application/octet-stream")
	upReqWrong.Header.Set("X-Up-Seq", "1")
	upReqWrong.Header.Set("X-Forwarded-For", "198.51.100.1")
	respUpWrong, err := client.Do(upReqWrong)
	if err != nil {
		t.Fatal(err)
	}
	respUpWrong.Body.Close()
	if respUpWrong.StatusCode != http.StatusNotFound {
		t.Fatalf("sessionTokenA uplink on hostB was not rejected: %d", respUpWrong.StatusCode)
	}

	// Uplink on hostA using sessionTokenA -> succeeds
	upReqA, _ := http.NewRequest(http.MethodPost, hosted.URL+"/api/v1/up", bytes.NewReader(openFrame))
	upReqA.Host = hostA
	upReqA.Header.Set("Authorization", "Bearer "+sessionTokenA)
	upReqA.Header.Set("Content-Type", "application/octet-stream")
	upReqA.Header.Set("X-Up-Seq", "1")
	upReqA.Header.Set("X-Forwarded-For", "198.51.100.1")
	respUpA, err := client.Do(upReqA)
	if err != nil {
		t.Fatal(err)
	}
	respUpA.Body.Close()
	if respUpA.StatusCode != http.StatusNoContent {
		t.Fatalf("sessionTokenA uplink on hostA failed: status %d", respUpA.StatusCode)
	}

	// 5. Trusted Host Header (X-Forwarded-Host):
	// hostC accepts X-Forwarded-Host
	bridgeReqC, _ := http.NewRequest(http.MethodGet, hosted.URL+"/proxy/?bridge="+config.CapabilityString(capC), nil)
	bridgeReqC.Host = "internal-proxy.local:8080"
	bridgeReqC.Header.Set("X-Forwarded-Host", hostC)
	bridgeReqC.Header.Set("X-Forwarded-For", "198.51.100.1")
	bridgeRespC, err := client.Do(bridgeReqC)
	if err != nil {
		t.Fatal(err)
	}
	bridgeBodyC, _ := io.ReadAll(bridgeRespC.Body)
	bridgeRespC.Body.Close()
	if bridgeRespC.StatusCode != http.StatusOK || !bytes.Contains(bridgeBodyC, []byte("tproxy-init")) {
		t.Fatalf("hostC bridge via X-Forwarded-Host failed: status %d", bridgeRespC.StatusCode)
	}

	// Sending X-Forwarded-Host pointing to hostA (which does NOT enable trusted_host_header)
	// when requesting under an unknown host -> strictly ignored, treated as unknown host
	spoofReq, _ := http.NewRequest(http.MethodGet, hosted.URL+"/", nil)
	spoofReq.Host = "attacker.domain.com"
	spoofReq.Header.Set("X-Forwarded-Host", hostA)
	spoofResp, err := client.Do(spoofReq)
	if err != nil {
		t.Fatal(err)
	}
	spoofResp.Body.Close()
	// Should fall back to default VHost decoy (not panic, not bypass)
	if spoofResp.StatusCode != http.StatusOK {
		t.Fatalf("expected decoy for spoofed request, got status: %d", spoofResp.StatusCode)
	}

	// 6. Trusted IP Header (CF-Connecting-IP on hostB):
	vhostB := app.vhosts[hostB]
	if vhostB == nil {
		t.Fatalf("vhostB not found")
	}
	testReqIP, _ := http.NewRequest(http.MethodGet, "http://"+hostB+"/", nil)
	testReqIP.RemoteAddr = "127.0.0.1:12345"
	testReqIP.Header.Set("CF-Connecting-IP", "203.0.113.88")
	testReqIP.Header.Set("X-Forwarded-For", "198.51.100.99")
	ip, err := app.clientIPForVHost(testReqIP, vhostB)
	if err != nil {
		t.Fatalf("clientIPForVHost failed: %v", err)
	}
	if ip != "203.0.113.88" {
		t.Fatalf("expected client IP from CF-Connecting-IP (203.0.113.88), got: %s", ip)
	}
}
