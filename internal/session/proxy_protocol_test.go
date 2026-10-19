package session

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/telegramdesktop/tproxy-server/internal/config"
	"github.com/telegramdesktop/tproxy-server/internal/frame"
)

func TestProxyProtocolV1Headers(t *testing.T) {
	// IPv4
	v1IPv4 := buildProxyV1Header("198.51.100.42", "127.0.0.1:2398")
	expectedV1IPv4 := "PROXY TCP4 198.51.100.42 127.0.0.1 0 2398\r\n"
	if string(v1IPv4) != expectedV1IPv4 {
		t.Fatalf("unexpected PROXY v1 IPv4 header: got %q, want %q", string(v1IPv4), expectedV1IPv4)
	}

	// IPv6
	v1IPv6 := buildProxyV1Header("2001:db8::1", "127.0.0.1:2398")
	expectedV1IPv6 := "PROXY TCP6 2001:db8::1 ::1 0 2398\r\n"
	if string(v1IPv6) != expectedV1IPv6 {
		t.Fatalf("unexpected PROXY v1 IPv6 header: got %q, want %q", string(v1IPv6), expectedV1IPv6)
	}

	// Unknown / invalid
	v1Invalid := buildProxyV1Header("not-an-ip", "127.0.0.1:2398")
	expectedV1Invalid := "PROXY UNKNOWN\r\n"
	if string(v1Invalid) != expectedV1Invalid {
		t.Fatalf("unexpected PROXY v1 invalid header: got %q, want %q", string(v1Invalid), expectedV1Invalid)
	}
}

func TestProxyProtocolV2Headers(t *testing.T) {
	// IPv4
	v2IPv4 := buildProxyV2Header("198.51.100.42", "127.0.0.1:2398")
	if len(v2IPv4) != 28 {
		t.Fatalf("unexpected PROXY v2 IPv4 length: %d", len(v2IPv4))
	}
	if !bytes.Equal(v2IPv4[:12], proxyV2Signature) {
		t.Fatal("invalid PROXY v2 signature")
	}
	if v2IPv4[12] != 0x21 || v2IPv4[13] != 0x11 {
		t.Fatalf("unexpected command/family: cmd=%x fam=%x", v2IPv4[12], v2IPv4[13])
	}
	addrLen := binary.BigEndian.Uint16(v2IPv4[14:16])
	if addrLen != 12 {
		t.Fatalf("unexpected addrLen: %d", addrLen)
	}
	srcIP := net.IP(v2IPv4[16:20])
	if !srcIP.Equal(net.ParseIP("198.51.100.42")) {
		t.Fatalf("unexpected srcIP: %v", srcIP)
	}
	dstPort := binary.BigEndian.Uint16(v2IPv4[26:28])
	if dstPort != 2398 {
		t.Fatalf("unexpected dstPort: %d", dstPort)
	}

	// IPv6
	v2IPv6 := buildProxyV2Header("2001:db8::1", "127.0.0.1:2398")
	if len(v2IPv6) != 52 {
		t.Fatalf("unexpected PROXY v2 IPv6 length: %d", len(v2IPv6))
	}
	if v2IPv6[12] != 0x21 || v2IPv6[13] != 0x21 {
		t.Fatalf("unexpected command/family for IPv6: cmd=%x fam=%x", v2IPv6[12], v2IPv6[13])
	}
	srcIPv6 := net.IP(v2IPv6[16:32])
	if !srcIPv6.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("unexpected srcIPv6: %v", srcIPv6)
	}

	// Unknown / invalid
	v2Invalid := buildProxyV2Header("", "127.0.0.1:2398")
	if len(v2Invalid) != 16 {
		t.Fatalf("unexpected PROXY v2 invalid length: %d", len(v2Invalid))
	}
	if v2Invalid[12] != 0x20 || v2Invalid[13] != 0x00 {
		t.Fatalf("unexpected command/family for invalid: cmd=%x fam=%x", v2Invalid[12], v2Invalid[13])
	}
}

func TestTelemtBackendWithProxyProtocolRoundTrip(t *testing.T) {
	headerReceived := make(chan []byte, 1)
	dataReceived := make(chan []byte, 1)

	// Mock telemt listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		headerReceived <- append([]byte(nil), buf[:n]...)

		// Echo back
		_, _ = conn.Write([]byte("pong-from-telemt"))
		dataReceived <- append([]byte(nil), buf[:n]...)
	}()

	configuration := testConfig(listener.Addr().String())
	configuration.Profiles[0].BackendType = config.BackendTelemt
	configuration.Profiles[0].BackendProxyProtocol = config.BackendProxyV1

	manager := NewManager(configuration, [32]byte{1})
	defer manager.Shutdown()

	clientIP := "203.0.113.88"
	bootstrap, err := manager.IssueBootstrap(&configuration.Profiles[0], clientIP)
	if err != nil {
		t.Fatal(err)
	}

	hello := frame.Encode(frame.Hello, 0, []byte{1})
	sessionResult, err := manager.Create(bootstrap, clientIP, hello)
	if err != nil {
		t.Fatal(err)
	}

	// Send OPEN frame followed by DATA
	openFrame := frame.Encode(frame.Open, 10, nil)
	dataFrame := frame.Encode(frame.Data, 10, []byte("hello-telemt"))
	batch := append(openFrame, dataFrame...)
	_, err = sessionResult.Session.ProcessUp(1, batch)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case received := <-headerReceived:
		expectedPrefix := "PROXY TCP4 203.0.113.88 127.0.0.1 0"
		if !bytes.Contains(received, []byte(expectedPrefix)) {
			t.Fatalf("telemt mock did not receive PROXY v1 header: %q", string(received))
		}
		if !bytes.Contains(received, []byte("hello-telemt")) {
			t.Fatalf("telemt mock did not receive stream payload: %q", string(received))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for telemt mock to receive connection")
	}
}

func TestTelemtBackendWithProxyProtocolV2RoundTrip(t *testing.T) {
	headerReceived := make(chan []byte, 1)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		headerReceived <- append([]byte(nil), buf[:n]...)
	}()

	configuration := testConfig(listener.Addr().String())
	configuration.Profiles[0].BackendType = config.BackendTelemt
	configuration.Profiles[0].BackendProxyProtocol = config.BackendProxyV2

	manager := NewManager(configuration, [32]byte{1})
	defer manager.Shutdown()

	clientIP := "198.51.100.99"
	bootstrap, err := manager.IssueBootstrap(&configuration.Profiles[0], clientIP)
	if err != nil {
		t.Fatal(err)
	}

	hello := frame.Encode(frame.Hello, 0, []byte{1})
	sessionResult, err := manager.Create(bootstrap, clientIP, hello)
	if err != nil {
		t.Fatal(err)
	}

	openFrame := frame.Encode(frame.Open, 11, nil)
	dataFrame := frame.Encode(frame.Data, 11, []byte("data-v2"))
	batch := append(openFrame, dataFrame...)
	_, err = sessionResult.Session.ProcessUp(1, batch)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case received := <-headerReceived:
		if len(received) < 28 {
			t.Fatalf("received header too short: %d", len(received))
		}
		if !bytes.Equal(received[:12], proxyV2Signature) {
			t.Fatal("telemt mock did not receive PROXY v2 signature")
		}
		if !bytes.Contains(received, []byte("data-v2")) {
			t.Fatalf("telemt mock did not receive stream payload: %q", string(received))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for telemt mock to receive connection")
	}
}
