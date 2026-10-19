package session

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

	"github.com/telegramdesktop/tproxy-server/internal/config"
)

var proxyV2Signature = []byte{
	0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
}

func parsePort(addr string, defaultPort uint16) uint16 {
	_, portStr, err := net.SplitHostPort(addr)
	if err == nil {
		if p, err := strconv.Atoi(portStr); err == nil && p >= 1 && p <= 65535 {
			return uint16(p)
		}
	}
	return defaultPort
}

func buildProxyHeader(mode config.BackendProxyProtocol, clientIPStr string, backendAddr string) []byte {
	switch mode {
	case config.BackendProxyV1:
		return buildProxyV1Header(clientIPStr, backendAddr)
	case config.BackendProxyV2:
		return buildProxyV2Header(clientIPStr, backendAddr)
	default:
		return nil
	}
}

func buildProxyV1Header(clientIPStr string, backendAddr string) []byte {
	ip := net.ParseIP(clientIPStr)
	if ip == nil {
		return []byte("PROXY UNKNOWN\r\n")
	}
	dstPort := parsePort(backendAddr, 8443)
	if ip4 := ip.To4(); ip4 != nil {
		return []byte(fmt.Sprintf("PROXY TCP4 %s 127.0.0.1 0 %d\r\n", ip4.String(), dstPort))
	}
	return []byte(fmt.Sprintf("PROXY TCP6 %s ::1 0 %d\r\n", ip.String(), dstPort))
}

func buildProxyV2Header(clientIPStr string, backendAddr string) []byte {
	ip := net.ParseIP(clientIPStr)
	dstPort := parsePort(backendAddr, 8443)

	if ip == nil {
		header := make([]byte, 16)
		copy(header[:12], proxyV2Signature)
		header[12] = 0x20 // v2, LOCAL
		header[13] = 0x00 // AF_UNSPEC, UNSPEC
		binary.BigEndian.PutUint16(header[14:16], 0)
		return header
	}

	if ip4 := ip.To4(); ip4 != nil {
		header := make([]byte, 16+12)
		copy(header[:12], proxyV2Signature)
		header[12] = 0x21 // v2, PROXY
		header[13] = 0x11 // AF_INET, STREAM
		binary.BigEndian.PutUint16(header[14:16], 12)
		copy(header[16:20], ip4)
		copy(header[20:24], net.ParseIP("127.0.0.1").To4())
		binary.BigEndian.PutUint16(header[24:26], 0)
		binary.BigEndian.PutUint16(header[26:28], dstPort)
		return header
	}

	header := make([]byte, 16+36)
	copy(header[:12], proxyV2Signature)
	header[12] = 0x21 // v2, PROXY
	header[13] = 0x21 // AF_INET6, STREAM
	binary.BigEndian.PutUint16(header[14:16], 36)
	copy(header[16:32], ip.To16())
	copy(header[32:48], net.ParseIP("::1").To16())
	binary.BigEndian.PutUint16(header[48:50], 0)
	binary.BigEndian.PutUint16(header[50:52], dstPort)
	return header
}
