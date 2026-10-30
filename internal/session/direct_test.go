package session

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/telegramdesktop/tproxy-server/internal/config"
	"github.com/telegramdesktop/tproxy-server/internal/frame"
)

func createTestClientHandshake(tag uint32, dcIdx int16, secret []byte) []byte {
	nonce := make([]byte, 64)
	_, _ = rand.Read(nonce)
	binary.LittleEndian.PutUint32(nonce[56:60], tag)
	binary.LittleEndian.PutUint16(nonce[60:62], uint16(dcIdx))

	decPrekey := nonce[8:40]
	decIV := nonce[40:56]

	var readKey []byte
	var readIV []byte = decIV

	if len(secret) == 17 && secret[0] == 0xdd {
		secret = secret[1:]
	}

	if len(secret) == 16 {
		hash := sha256.Sum256(append(append([]byte(nil), decPrekey...), secret...))
		readKey = hash[:]
	} else {
		readKey = decPrekey
	}

	block, _ := aes.NewCipher(readKey)
	stream := cipher.NewCTR(block, readIV)

	encrypted := make([]byte, 64)
	stream.XORKeyStream(encrypted, nonce)

	result := make([]byte, 64)
	copy(result[0:56], nonce[0:56])
	copy(result[56:64], encrypted[56:64])
	return result
}

func TestParseClientHandshakeWithSecret(t *testing.T) {
	secret := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	header := createTestClientHandshake(TagIntermediate, 2, secret)

	res, err := ParseClientHandshake(header, secret)
	if err != nil {
		t.Fatalf("ParseClientHandshake failed: %v", err)
	}
	if res.Tag != TagIntermediate {
		t.Fatalf("expected tag %x, got %x", TagIntermediate, res.Tag)
	}
	if res.DCIdx != 2 {
		t.Fatalf("expected dcIdx 2, got %d", res.DCIdx)
	}

	// Verify encryption/decryption on subsequent stream
	// Client sends plaintext payload: client encrypts with client read cipher (from client perspective, it's their write cipher)
	// Our res.ClientDecryptor should decrypt it back to plaintext!
	decPrekey := header[8:40]
	decIV := header[40:56]
	hash := sha256.Sum256(append(append([]byte(nil), decPrekey...), secret...))
	clientBlock, _ := aes.NewCipher(hash[:])
	clientWriteCipher := cipher.NewCTR(clientBlock, decIV)
	// Advance client write cipher by 64 bytes (the handshake header)
	dummy := make([]byte, 64)
	clientWriteCipher.XORKeyStream(dummy, dummy)

	plaintext := []byte("hello telegram direct dc")
	ciphertext := make([]byte, len(plaintext))
	clientWriteCipher.XORKeyStream(ciphertext, plaintext)

	decrypted := make([]byte, len(ciphertext))
	res.ClientDecryptor.XORKeyStream(decrypted, ciphertext)

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("stream decryption mismatch: expected %q, got %q", plaintext, decrypted)
	}
}

func TestParseClientHandshakeWithDDSecret(t *testing.T) {
	ddSecret := []byte{0xdd, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	header := createTestClientHandshake(TagPaddedIntermediate, 4, ddSecret)

	res, err := ParseClientHandshake(header, ddSecret)
	if err != nil {
		t.Fatalf("ParseClientHandshake with dd-secret failed: %v", err)
	}
	if res.Tag != TagPaddedIntermediate {
		t.Fatalf("expected tag %x, got %x", TagPaddedIntermediate, res.Tag)
	}
	if res.DCIdx != 4 {
		t.Fatalf("expected dcIdx 4, got %d", res.DCIdx)
	}
}

func TestParseClientHandshakePlainWithoutSecret(t *testing.T) {
	header := createTestClientHandshake(TagAbridged, 1, nil)

	res, err := ParseClientHandshake(header, nil)
	if err != nil {
		t.Fatalf("ParseClientHandshake without secret failed: %v", err)
	}
	if res.Tag != TagAbridged {
		t.Fatalf("expected tag %x, got %x", TagAbridged, res.Tag)
	}
	if res.DCIdx != 1 {
		t.Fatalf("expected dcIdx 1, got %d", res.DCIdx)
	}
}

func TestParseClientHandshakeFailures(t *testing.T) {
	// Too short
	short := make([]byte, 63)
	if _, err := ParseClientHandshake(short, nil); err != ErrHandshakeTooShort {
		t.Fatalf("expected ErrHandshakeTooShort, got %v", err)
	}

	// Invalid garbage
	garbage := make([]byte, 64)
	if _, err := ParseClientHandshake(garbage, nil); err != ErrInvalidHandshake {
		t.Fatalf("expected ErrInvalidHandshake, got %v", err)
	}
}

func TestCreateTelegramHandshake(t *testing.T) {
	header, tgEncryptor, tgDecryptor, err := CreateTelegramHandshake(TagIntermediate, 2)
	if err != nil {
		t.Fatalf("CreateTelegramHandshake failed: %v", err)
	}
	if len(header) != 64 {
		t.Fatalf("expected 64 bytes header, got %d", len(header))
	}
	if header[0] == 0xef {
		t.Fatalf("header[0] must not be 0xef")
	}

	// Simulate Telegram DC receiving header:
	// TG DC extracts tgEncKey = header[8:40], tgEncIV = header[40:56]
	tgEncKey := header[8:40]
	tgEncIV := header[40:56]
	block, err := aes.NewCipher(tgEncKey)
	if err != nil {
		t.Fatal(err)
	}
	dcDecryptor := cipher.NewCTR(block, tgEncIV)
	decrypted := make([]byte, 64)
	dcDecryptor.XORKeyStream(decrypted, header)

	tag := binary.LittleEndian.Uint32(decrypted[56:60])
	dcIdx := int16(binary.LittleEndian.Uint16(decrypted[60:62]))
	if tag != TagIntermediate {
		t.Fatalf("TG DC decrypted tag mismatch: expected %x, got %x", TagIntermediate, tag)
	}
	if dcIdx != 2 {
		t.Fatalf("TG DC decrypted dcIdx mismatch: expected 2, got %d", dcIdx)
	}

	// Test uplink stream: proxy sends MTProto payload to TG DC
	payload := []byte("packet from client to telegram dc")
	encryptedPayload := make([]byte, len(payload))
	tgEncryptor.XORKeyStream(encryptedPayload, payload)

	decryptedPayload := make([]byte, len(encryptedPayload))
	dcDecryptor.XORKeyStream(decryptedPayload, encryptedPayload)
	if !bytes.Equal(decryptedPayload, payload) {
		t.Fatalf("uplink stream mismatch: expected %q, got %q", payload, decryptedPayload)
	}

	// Test downlink stream: TG DC responds to proxy
	tgDecKeyIV := make([]byte, 48)
	for i := range tgDecKeyIV {
		tgDecKeyIV[i] = header[55-i]
	}
	respBlock, err := aes.NewCipher(tgDecKeyIV[:32])
	if err != nil {
		t.Fatal(err)
	}
	dcEncryptor := cipher.NewCTR(respBlock, tgDecKeyIV[32:48])

	respPayload := []byte("packet from telegram dc to client")
	encryptedResp := make([]byte, len(respPayload))
	dcEncryptor.XORKeyStream(encryptedResp, respPayload)

	decryptedResp := make([]byte, len(encryptedResp))
	tgDecryptor.XORKeyStream(decryptedResp, encryptedResp)
	if !bytes.Equal(decryptedResp, respPayload) {
		t.Fatalf("downlink stream mismatch: expected %q, got %q", respPayload, decryptedResp)
	}
}

func TestCreateTelegramHandshakeNormalizedDC(t *testing.T) {
	header, _, _, err := CreateTelegramHandshake(TagIntermediate, 10002)
	if err != nil {
		t.Fatalf("CreateTelegramHandshake failed: %v", err)
	}
	tgEncKey := header[8:40]
	tgEncIV := header[40:56]
	block, err := aes.NewCipher(tgEncKey)
	if err != nil {
		t.Fatal(err)
	}
	dcDecryptor := cipher.NewCTR(block, tgEncIV)
	decrypted := make([]byte, 64)
	dcDecryptor.XORKeyStream(decrypted, header)

	dcIdx := int16(binary.LittleEndian.Uint16(decrypted[60:62]))
	if dcIdx != -2 {
		t.Fatalf("expected normalized dcIdx -2, got %d", dcIdx)
	}
}

func TestResolveTelegramDC(t *testing.T) {
	// Explicit host:port in backend
	addr, err := ResolveTelegramDC("1.2.3.4:443", "", 2, false, nil)
	if err != nil || addr != "1.2.3.4:443" {
		t.Fatalf("expected 1.2.3.4:443, got %q (%v)", addr, err)
	}

	// Explicit DC ID in backend
	addr, err = ResolveTelegramDC("2", "", 1, false, nil)
	if err != nil || addr != "149.154.167.51:443" {
		t.Fatalf("expected 149.154.167.51:443, got %q (%v)", addr, err)
	}

	// Explicit staticDC
	addr, err = ResolveTelegramDC("auto", "4", 1, false, nil)
	if err != nil || addr != "149.154.167.91:443" {
		t.Fatalf("expected 149.154.167.91:443, got %q (%v)", addr, err)
	}

	// Auto DC mode IPv4
	for dcIdx, expected := range defaultTelegramDCsIPv4 {
		addr, err = ResolveTelegramDC("auto", "", dcIdx, false, nil)
		if err != nil || addr != expected {
			t.Fatalf("dcIdx %d: expected %s, got %s (%v)", dcIdx, expected, addr, err)
		}
	}

	// Auto DC mode IPv6
	for dcIdx, expected := range defaultTelegramDCsIPv6 {
		addr, err = ResolveTelegramDC("auto", "", dcIdx, true, nil)
		if err != nil || addr != expected {
			t.Fatalf("IPv6 dcIdx %d: expected %s, got %s (%v)", dcIdx, expected, addr, err)
		}
	}

	// Negative DC resolution (-1, -2, -4)
	for _, negIdx := range []int16{-1, -2, -3, -4, -5} {
		addr, err = ResolveTelegramDC("auto", "", negIdx, false, nil)
		if err != nil || addr != defaultTelegramDCsIPv4[negIdx] {
			t.Fatalf("negIdx %d: expected %s, got %s (%v)", negIdx, defaultTelegramDCsIPv4[negIdx], addr, err)
		}
	}
	// Explicit check for dedicated Media DC2 and DC4 IPs (must NOT route to .51 or .91)
	addr, err = ResolveTelegramDC("auto", "", -2, false, nil)
	if err != nil || addr != "149.154.167.151:443" {
		t.Fatalf("Media DC -2 expected 149.154.167.151:443, got %s (%v)", addr, err)
	}
	addr, err = ResolveTelegramDC("auto", "", -4, false, nil)
	if err != nil || addr != "149.154.166.120:443" {
		t.Fatalf("Media DC -4 expected 149.154.166.120:443, got %s (%v)", addr, err)
	}


	// CDN DC 203 and -203
	addr, err = ResolveTelegramDC("auto", "", 203, false, nil)
	if err != nil || addr != "91.105.192.100:443" {
		t.Fatalf("DC 203: expected 91.105.192.100:443, got %s (%v)", addr, err)
	}
	addr, err = ResolveTelegramDC("auto", "", -203, false, nil)
	if err != nil || addr != "91.105.192.100:443" {
		t.Fatalf("DC -203: expected 91.105.192.100:443, got %s (%v)", addr, err)
	}

	// Older media representation (10002 -> -2)
	addr, err = ResolveTelegramDC("auto", "", 10002, false, nil)
	if err != nil || addr != defaultTelegramDCsIPv4[-2] {
		t.Fatalf("DC 10002: expected %s, got %s (%v)", defaultTelegramDCsIPv4[-2], addr, err)
	}

	// Unknown DC fallback to DC 2
	addr, err = ResolveTelegramDC("auto", "", 999, false, nil)
	if err != nil || addr != defaultTelegramDCsIPv4[2] {
		t.Fatalf("fallback: expected %s, got %s (%v)", defaultTelegramDCsIPv4[2], addr, err)
	}

	// Override map
	overrides := map[int16]string{
		2: "10.0.0.2:8443",
	}
	addr, err = ResolveTelegramDC("auto", "", 2, false, overrides)
	if err != nil || addr != "10.0.0.2:8443" {
		t.Fatalf("override: expected 10.0.0.2:8443, got %s (%v)", addr, err)
	}
}

func TestDirectBackendStreamEndToEnd(t *testing.T) {
	// 1. Start a mock Telegram DC listener
	dcListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dcListener.Close()

	dcAddr := dcListener.Addr().String()
	secretHex := "000102030405060708090a0b0c0d0e0f"
	secretBytes, _ := hex.DecodeString(secretHex)

	cfg := testConfig(dcAddr)
	cfg.Profiles[0].BackendType = config.BackendDirect
	cfg.Profiles[0].Secret = secretHex
	cfg.Profiles[0].Backend = dcAddr
	cfg.Timeouts.BackendDial = config.Duration(5 * time.Second)

	manager := NewManager(cfg, [32]byte{1})
	defer manager.Shutdown()

	bootstrap, err := manager.IssueBootstrap(&cfg.Profiles[0], "198.51.100.9")
	if err != nil {
		t.Fatal(err)
	}
	created, err := manager.Create(bootstrap, "198.51.100.9", frame.Encode(frame.Hello, 0, []byte{1}))
	if err != nil {
		t.Fatal(err)
	}
	sess := created.Session

	dcDone := make(chan struct{})
	clientPlainMsg := []byte("ping from client")
	dcPlainResp := []byte("pong from telegram dc")

	// Mock Telegram DC handler goroutine
	go func() {
		defer close(dcDone)
		conn, err := dcListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// TG DC receives 64-byte obfuscated handshake
		tgHeader := make([]byte, 64)
		if _, err := io.ReadFull(conn, tgHeader); err != nil {
			t.Errorf("mock TG DC read handshake failed: %v", err)
			return
		}
		tgEncKey := tgHeader[8:40]
		tgEncIV := tgHeader[40:56]
		block, _ := aes.NewCipher(tgEncKey)
		dcDecryptor := cipher.NewCTR(block, tgEncIV)
		decryptedHeader := make([]byte, 64)
		dcDecryptor.XORKeyStream(decryptedHeader, tgHeader)

		tag := binary.LittleEndian.Uint32(decryptedHeader[56:60])
		if tag != TagIntermediate {
			t.Errorf("mock TG DC unexpected tag: %x", tag)
			return
		}

		// TG DC reads forwarded client data
		encData := make([]byte, len(clientPlainMsg))
		if _, err := io.ReadFull(conn, encData); err != nil {
			t.Errorf("mock TG DC read client data failed: %v", err)
			return
		}
		plainData := make([]byte, len(encData))
		dcDecryptor.XORKeyStream(plainData, encData)
		if !bytes.Equal(plainData, clientPlainMsg) {
			t.Errorf("mock TG DC payload mismatch: expected %q, got %q", clientPlainMsg, plainData)
			return
		}

		// TG DC replies with dcPlainResp
		tgDecKeyIV := make([]byte, 48)
		for i := range tgDecKeyIV {
			tgDecKeyIV[i] = tgHeader[55-i]
		}
		respBlock, _ := aes.NewCipher(tgDecKeyIV[:32])
		dcEncryptor := cipher.NewCTR(respBlock, tgDecKeyIV[32:48])
		encResp := make([]byte, len(dcPlainResp))
		dcEncryptor.XORKeyStream(encResp, dcPlainResp)
		if _, err := conn.Write(encResp); err != nil {
			t.Errorf("mock TG DC write response failed: %v", err)
			return
		}
	}()

	// 2. Client side:
	// Stream 1 opens
	openFrame := frame.Encode(frame.Open, 1, nil)
	if _, err := sess.ProcessUp(1, openFrame); err != nil {
		t.Fatalf("ProcessUp OPEN failed: %v", err)
	}

	// Client sends handshake + clientPlainMsg in DATA frame
	clientHandshakeHeader := createTestClientHandshake(TagIntermediate, 2, secretBytes)
	decPrekey := clientHandshakeHeader[8:40]
	decIV := clientHandshakeHeader[40:56]
	readHash := sha256.Sum256(append(append([]byte(nil), decPrekey...), secretBytes...))
	cBlock, _ := aes.NewCipher(readHash[:])
	cStream := cipher.NewCTR(cBlock, decIV)
	// Advance cStream by 64 bytes
	dummy := make([]byte, 64)
	cStream.XORKeyStream(dummy, dummy)
	encClientMsg := make([]byte, len(clientPlainMsg))
	cStream.XORKeyStream(encClientMsg, clientPlainMsg)

	uplinkPayload := append(append([]byte(nil), clientHandshakeHeader...), encClientMsg...)
	dataFrame := frame.Encode(frame.Data, 1, uplinkPayload)
	if _, err := sess.ProcessUp(2, dataFrame); err != nil {
		t.Fatalf("ProcessUp DATA failed: %v", err)
	}

	// Wait for mock TG DC to process uplink and reply
	select {
	case <-dcDone:
	case <-time.After(3 * time.Second):
		t.Fatal("mock TG DC timed out")
	}

	// Now poll downlink from session
	cursor := uint64(0)
	var receivedCiphertext []byte
	deadline := time.Now().Add(3 * time.Second)
	for len(receivedCiphertext) == 0 && time.Now().Before(deadline) {
		downBatch, nextCursor, err := sess.Poll(context.Background(), cursor)
		if err != nil {
			t.Fatalf("Poll failed: %v", err)
		}
		cursor = nextCursor
		frames, err := frame.ParseAll(downBatch, frame.MaxPayload)
		if err != nil {
			t.Fatalf("ParseAll downlink failed: %v", err)
		}
		for _, f := range frames {
			if f.Type == frame.Data && f.StreamID == 1 {
				receivedCiphertext = append(receivedCiphertext, f.Payload...)
			}
		}
		if len(receivedCiphertext) == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if len(receivedCiphertext) == 0 {
		t.Fatal("no DATA frames received in downlink")
	}

	// Client decrypts received downlink with encPrekey + secret
	encPrekeyIV := make([]byte, 48)
	for i := range encPrekeyIV {
		encPrekeyIV[i] = clientHandshakeHeader[55-i]
	}
	writeHash := sha256.Sum256(append(append([]byte(nil), encPrekeyIV[:32]...), secretBytes...))
	clientRespBlock, _ := aes.NewCipher(writeHash[:])
	clientRespStream := cipher.NewCTR(clientRespBlock, encPrekeyIV[32:48])

	decryptedDownlink := make([]byte, len(receivedCiphertext))
	clientRespStream.XORKeyStream(decryptedDownlink, receivedCiphertext)

	if !bytes.Equal(decryptedDownlink, dcPlainResp) {
		t.Fatalf("downlink decrypted payload mismatch: expected %q, got %q", dcPlainResp, decryptedDownlink)
	}
}

func TestWarmDCPoolBasic(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	var serverConns []net.Conn
	stopServer := make(chan struct{})
	defer func() {
		close(stopServer)
		for _, c := range serverConns {
			_ = c.Close()
		}
	}()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			serverConns = append(serverConns, conn)
		}
	}()

	target := ln.Addr().String()
	pool := NewWarmDCPool(WarmDCPoolOptions{
		Targets:       []string{target},
		SizePerTarget: 2,
		MaxIdleAge:    5 * time.Second,
		DialTimeout:   time.Second,
		CheckInterval: 50 * time.Millisecond,
		AllowLoopback: true,
	})
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	defer pool.Close()

	// Wait for pool to pre-warm connection
	var conn net.Conn
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn = pool.Get(target)
		if conn != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if conn == nil {
		t.Fatal("expected warm connection from pool, got nil")
	}
	_ = conn.Close()

	if pool.Hits() < 1 {
		t.Fatalf("expected at least 1 hit, got %d", pool.Hits())
	}

	// Non-existent target should miss immediately
	missConn := pool.Get("127.0.0.1:1")
	if missConn != nil {
		_ = missConn.Close()
		t.Fatal("expected nil connection for unreachable target")
	}
	if pool.Misses() < 1 {
		t.Fatalf("expected at least 1 miss, got %d", pool.Misses())
	}
}

func TestWarmDCPoolStaleEviction(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 10)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()

	target := ln.Addr().String()
	pool := NewWarmDCPool(WarmDCPoolOptions{
		Targets:       []string{target},
		SizePerTarget: 1,
		MaxIdleAge:    100 * time.Millisecond,
		DialTimeout:   time.Second,
		CheckInterval: 50 * time.Millisecond,
		AllowLoopback: true,
	})
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	defer pool.Close()

	// Wait for first connection to arrive on server side
	var srvConn net.Conn
	select {
	case srvConn = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server connection")
	}

	// Remote closes the socket (FIN)
	_ = srvConn.Close()
	time.Sleep(20 * time.Millisecond)

	// Get() should detect EOF via isConnAlive, discard dead socket, and return nil
	deadConn := pool.Get(target)
	if deadConn != nil {
		_ = deadConn.Close()
		t.Fatal("expected dead connection to be evicted, got non-nil")
	}
}

func TestWarmDCPoolShutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	pool := NewWarmDCPool(WarmDCPoolOptions{
		Targets:       []string{ln.Addr().String()},
		SizePerTarget: 4,
		MaxIdleAge:    5 * time.Second,
		DialTimeout:   time.Second,
		CheckInterval: time.Second,
		AllowLoopback: true,
	})

	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	pool.Close()
	elapsed := time.Since(start)
	if elapsed > 500*time.Millisecond {
		t.Fatalf("pool.Close took too long: %v", elapsed)
	}

	if c := pool.Get(ln.Addr().String()); c != nil {
		_ = c.Close()
		t.Fatal("expected nil after pool closed")
	}
}

func TestDirectWithWarmPoolEndToEnd(t *testing.T) {
	dcListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer dcListener.Close()
	dcAddr := dcListener.Addr().String()

	clientPlainMsg := []byte("hello from telegram client via warm pool")
	dcPlainResp := []byte("rpc_result_from_dc_via_warm_pool")
	dcDone := make(chan struct{})

	go func() {
		defer close(dcDone)
		conn, err := dcListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		tgHeader := make([]byte, 64)
		if _, err := io.ReadFull(conn, tgHeader); err != nil {
			t.Errorf("failed to read TG header: %v", err)
			return
		}

		decPrekey := tgHeader[8:40]
		decIV := tgHeader[40:56]
		encPrekeyIV := make([]byte, 48)
		for i := range encPrekeyIV {
			encPrekeyIV[i] = tgHeader[55-i]
		}
		encPrekey := encPrekeyIV[:32]
		encIV := encPrekeyIV[32:48]

		readBlock, _ := aes.NewCipher(decPrekey)
		readStream := cipher.NewCTR(readBlock, decIV)
		writeBlock, _ := aes.NewCipher(encPrekey)
		writeStream := cipher.NewCTR(writeBlock, encIV)

		dummy := make([]byte, 64)
		readStream.XORKeyStream(dummy, dummy)

		encPayload := make([]byte, len(clientPlainMsg))
		if _, err := io.ReadFull(conn, encPayload); err != nil {
			t.Errorf("failed to read encrypted payload: %v", err)
			return
		}
		decryptedClientMsg := make([]byte, len(encPayload))
		readStream.XORKeyStream(decryptedClientMsg, encPayload)

		if !bytes.Equal(decryptedClientMsg, clientPlainMsg) {
			t.Errorf("TG DC received payload mismatch: expected %q, got %q", clientPlainMsg, decryptedClientMsg)
			return
		}

		encResp := make([]byte, len(dcPlainResp))
		writeStream.XORKeyStream(encResp, dcPlainResp)
		_, _ = conn.Write(encResp)
	}()

	pool := NewWarmDCPool(WarmDCPoolOptions{
		Targets:       []string{dcAddr},
		SizePerTarget: 2,
		MaxIdleAge:    5 * time.Second,
		DialTimeout:   time.Second,
		CheckInterval: 50 * time.Millisecond,
		AllowLoopback: true,
	})
	if pool == nil {
		t.Fatal("failed to initialize warm dc pool")
	}
	defer pool.Close()

	// Wait for pool to connect
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pool.mu.Lock()
		ch := pool.queues[dcAddr]
		count := len(ch)
		pool.mu.Unlock()
		if count > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	secretHex := "000102030405060708090a0b0c0d0e0f"
	secretBytes, _ := hex.DecodeString(secretHex)

	cfg := testConfig(dcAddr)
	cfg.Profiles[0].BackendType = config.BackendDirect
	cfg.Profiles[0].Secret = secretHex
	cfg.Profiles[0].Backend = dcAddr
	cfg.Timeouts.BackendDial = config.Duration(5 * time.Second)

	sess := newSession(sessionOptions{
		profile:    &cfg.Profiles[0],
		limits:     cfg.Limits,
		timeouts:   cfg.Timeouts,
		warmDCPool: pool,
	})
	defer sess.Close()

	openFrame := frame.Encode(frame.Open, 1, nil)
	if _, err := sess.ProcessUp(1, openFrame); err != nil {
		t.Fatalf("ProcessUp OPEN failed: %v", err)
	}

	clientHandshakeHeader := createTestClientHandshake(TagIntermediate, 2, secretBytes)
	cDecPrekey := clientHandshakeHeader[8:40]
	cDecIV := clientHandshakeHeader[40:56]
	readHash := sha256.Sum256(append(append([]byte(nil), cDecPrekey...), secretBytes...))
	cBlock, _ := aes.NewCipher(readHash[:])
	cStream := cipher.NewCTR(cBlock, cDecIV)
	dummy := make([]byte, 64)
	cStream.XORKeyStream(dummy, dummy)
	encClientMsg := make([]byte, len(clientPlainMsg))
	cStream.XORKeyStream(encClientMsg, clientPlainMsg)

	uplinkPayload := append(append([]byte(nil), clientHandshakeHeader...), encClientMsg...)
	dataFrame := frame.Encode(frame.Data, 1, uplinkPayload)
	if _, err := sess.ProcessUp(2, dataFrame); err != nil {
		t.Fatalf("ProcessUp DATA failed: %v", err)
	}

	select {
	case <-dcDone:
	case <-time.After(3 * time.Second):
		t.Fatal("mock TG DC timed out")
	}

	if pool.Hits() < 1 {
		t.Fatalf("expected warm dc pool hits >= 1, got %d", pool.Hits())
	}

	// Poll downlink from session
	cursor := uint64(0)
	var receivedCiphertext []byte
	pollDeadline := time.Now().Add(3 * time.Second)
	for len(receivedCiphertext) == 0 && time.Now().Before(pollDeadline) {
		downBatch, nextCursor, err := sess.Poll(context.Background(), cursor)
		if err != nil {
			t.Fatalf("Poll failed: %v", err)
		}
		cursor = nextCursor
		frames, err := frame.ParseAll(downBatch, frame.MaxPayload)
		if err != nil {
			t.Fatalf("ParseAll downlink failed: %v", err)
		}
		for _, f := range frames {
			if f.Type == frame.Data && f.StreamID == 1 {
				receivedCiphertext = append(receivedCiphertext, f.Payload...)
			}
		}
		if len(receivedCiphertext) == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if len(receivedCiphertext) == 0 {
		t.Fatal("no DATA frames received in downlink")
	}

	encPrekeyIV := make([]byte, 48)
	for i := range encPrekeyIV {
		encPrekeyIV[i] = clientHandshakeHeader[55-i]
	}
	writeHash := sha256.Sum256(append(append([]byte(nil), encPrekeyIV[:32]...), secretBytes...))
	clientRespBlock, _ := aes.NewCipher(writeHash[:])
	clientRespStream := cipher.NewCTR(clientRespBlock, encPrekeyIV[32:48])

	decryptedDownlink := make([]byte, len(receivedCiphertext))
	clientRespStream.XORKeyStream(decryptedDownlink, receivedCiphertext)

	if !bytes.Equal(decryptedDownlink, dcPlainResp) {
		t.Fatalf("downlink decrypted payload mismatch: expected %q, got %q", dcPlainResp, decryptedDownlink)
	}
}
