package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/telegramdesktop/tproxy-server/internal/config"
	"github.com/telegramdesktop/tproxy-server/internal/frame"
	"github.com/telegramdesktop/tproxy-server/internal/logger"
)

// Known Telegram DC IP addresses (standard port 443).
var defaultTelegramDCsIPv4 = map[int16]string{
	// Main DCs (API, messages)
	1: "149.154.175.50:443",
	2: "149.154.167.51:443",
	3: "149.154.175.100:443",
	4: "149.154.167.91:443",
	5: "149.154.171.5:443",

	// Media-only DCs (negative IDs for downloading/uploading photos/videos/files)
	-1: "149.154.175.50:443",
	-2: "149.154.167.151:443", // Dedicated Media DC2 server (upload.getFile)
	-3: "149.154.175.100:443",
	-4: "149.154.166.120:443", // Dedicated Media DC4 server (upload.getFile)
	-5: "149.154.171.5:443",
	// CDN DCs (public channels and media)
	203:  "91.105.192.100:443",
	-203: "91.105.192.100:443",
}

var defaultTelegramDCsIPv6 = map[int16]string{
	// Main DCs (API, messages)
	1: "[2001:b28:f23d:f001::a]:443",
	2: "[2001:67c:04e8:f002::a]:443",
	3: "[2001:b28:f23d:f003::a]:443",
	4: "[2001:67c:04e8:f004::a]:443",
	5: "[2001:b28:f23f:f005::a]:443",

	// Media-only DCs
	-1: "[2001:b28:f23d:f001::a]:443",
	-2: "[2001:67c:04e8:f002::a]:443",
	-3: "[2001:b28:f23d:f003::a]:443",
	-4: "[2001:67c:04e8:f004::a]:443",
	-5: "[2001:b28:f23f:f005::a]:443",

	// CDN DCs
	203:  "[2001:b28:f23d:f003::a]:443",
	-203: "[2001:b28:f23d:f003::a]:443",
}

const (
	TagAbridged           uint32 = 0xefefefef
	TagIntermediate       uint32 = 0xeeeeeeee
	TagPaddedIntermediate uint32 = 0xdddddddd
)

var (
	ErrHandshakeTooShort = errors.New("handshake buffer must be at least 64 bytes")
	ErrInvalidHandshake  = errors.New("invalid MTProto handshake protocol tag or decryption failure")
)

// ClientHandshakeResult holds decrypted handshake metadata and ciphers.
type ClientHandshakeResult struct {
	Tag             uint32
	DCIdx           int16
	ClientDecryptor cipher.Stream // Pre-advanced by 64 bytes (ready for client uplink data)
	ClientEncryptor cipher.Stream // Initialized at offset 0 (ready for client downlink data)
}

// ParseClientHandshake parses and decrypts the client's 64-byte MTProto handshake header.
// It verifies the protocol tag (abridged, intermediate, padded) and returns the extracted
// DC index along with configured stream ciphers.
func ParseClientHandshake(handshake []byte, rawSecret []byte) (*ClientHandshakeResult, error) {
	if len(handshake) < 64 {
		return nil, ErrHandshakeTooShort
	}
	h := handshake[:64]

	decPrekey := h[8:40] // 32 bytes
	decIV := h[40:56]     // 16 bytes

	// encPrekeyIV is h[8:56] reversed (48 bytes)
	encPrekeyIV := make([]byte, 48)
	for i := range encPrekeyIV {
		encPrekeyIV[i] = h[55-i]
	}
	encPrekey := encPrekeyIV[:32]
	encIV := encPrekeyIV[32:48]

	// Normalize secret: if 17 bytes starting with 0xdd, strip mode byte.
	secret := rawSecret
	if len(secret) == 17 && secret[0] == 0xdd {
		secret = secret[1:]
	}

	// Try candidate 1: with secret (if secret has 16 bytes)
	if len(secret) == 16 {
		readHash := sha256.Sum256(append(append([]byte(nil), decPrekey...), secret...))
		writeHash := sha256.Sum256(append(append([]byte(nil), encPrekey...), secret...))

		readBlock, err := aes.NewCipher(readHash[:])
		if err == nil {
			writeBlock, err2 := aes.NewCipher(writeHash[:])
			if err2 == nil {
				readStream := cipher.NewCTR(readBlock, decIV)
				writeStream := cipher.NewCTR(writeBlock, encIV)

				decrypted := make([]byte, 64)
				readStream.XORKeyStream(decrypted, h)

				tag := binary.LittleEndian.Uint32(decrypted[56:60])
				if isValidProtoTag(tag) {
					dcIdx := int16(binary.LittleEndian.Uint16(decrypted[60:62]))
					return &ClientHandshakeResult{
						Tag:             tag,
						DCIdx:           dcIdx,
						ClientDecryptor: readStream,
						ClientEncryptor: writeStream,
					}, nil
				}
			}
		}
	}

	// Try candidate 2: without secret (plain MTProto obfuscated2)
	readBlock, err := aes.NewCipher(decPrekey)
	if err == nil {
		writeBlock, err2 := aes.NewCipher(encPrekey)
		if err2 == nil {
			readStream := cipher.NewCTR(readBlock, decIV)
			writeStream := cipher.NewCTR(writeBlock, encIV)

			decrypted := make([]byte, 64)
			readStream.XORKeyStream(decrypted, h)

			tag := binary.LittleEndian.Uint32(decrypted[56:60])
			if isValidProtoTag(tag) {
				dcIdx := int16(binary.LittleEndian.Uint16(decrypted[60:62]))
				return &ClientHandshakeResult{
					Tag:             tag,
					DCIdx:           dcIdx,
					ClientDecryptor: readStream,
					ClientEncryptor: writeStream,
				}, nil
			}
		}
	}

	return nil, ErrInvalidHandshake
}

func isValidProtoTag(tag uint32) bool {
	return tag == TagAbridged || tag == TagIntermediate || tag == TagPaddedIntermediate
}

// CreateTelegramHandshake generates a genuine 64-byte MTProto obfuscated2 handshake
// to connect directly to an official Telegram DC.
// It returns:
// - headerToSend: 64 bytes with random nonce and encrypted protocol tag/dcIdx
// - tgEncryptor: cipher stream for uplink to Telegram DC (pre-advanced by 64 bytes)
// - tgDecryptor: cipher stream for downlink from Telegram DC (starting at offset 0)
func CreateTelegramHandshake(protoTag uint32, dcIdx int16) ([]byte, cipher.Stream, cipher.Stream, error) {
	if protoTag == 0 {
		protoTag = TagIntermediate
	}
	if dcIdx == 0 {
		dcIdx = 2
	}
	tgNonce := make([]byte, 64)
	for {
		if _, err := rand.Read(tgNonce); err != nil {
			return nil, nil, nil, fmt.Errorf("generate nonce: %w", err)
		}
		if tgNonce[0] == 0xef || tgNonce[0] == 0x16 {
			continue
		}
		val0 := binary.BigEndian.Uint32(tgNonce[0:4])
		// Avoid clash with HTTP methods: HEAD, POST, GET , OPTI
		if val0 == 0x48454144 || val0 == 0x504f5354 || val0 == 0x47455420 || val0 == 0x4f505449 {
			continue
		}
		// Avoid clash with MTProto tags in big-endian
		if val0 == TagIntermediate || val0 == TagPaddedIntermediate || val0 == TagAbridged {
			continue
		}
		val1 := binary.BigEndian.Uint32(tgNonce[4:8])
		if val1 == 0x00000000 {
			continue
		}
		break
	}

	binary.LittleEndian.PutUint32(tgNonce[56:60], protoTag)
	binary.LittleEndian.PutUint16(tgNonce[60:62], uint16(dcIdx))

	tgEncKey := tgNonce[8:40]
	tgEncIV := tgNonce[40:56]

	tgDecKeyIV := make([]byte, 48)
	for i := range tgDecKeyIV {
		tgDecKeyIV[i] = tgNonce[55-i]
	}
	tgDecKey := tgDecKeyIV[:32]
	tgDecIV := tgDecKeyIV[32:48]

	tgEncBlock, err := aes.NewCipher(tgEncKey)
	if err != nil {
		return nil, nil, nil, err
	}
	tgEncryptor := cipher.NewCTR(tgEncBlock, tgEncIV)

	tgDecBlock, err := aes.NewCipher(tgDecKey)
	if err != nil {
		return nil, nil, nil, err
	}
	tgDecryptor := cipher.NewCTR(tgDecBlock, tgDecIV)

	encryptedNonce := make([]byte, 64)
	tgEncryptor.XORKeyStream(encryptedNonce, tgNonce)

	headerToSend := make([]byte, 64)
	copy(headerToSend[0:56], tgNonce[0:56])
	copy(headerToSend[56:64], encryptedNonce[56:64])

	return headerToSend, tgEncryptor, tgDecryptor, nil
}

func absDC(dcIdx int16) int16 {
	if dcIdx == math.MinInt16 {
		return 0
	}
	if dcIdx < 0 {
		return -dcIdx
	}
	return dcIdx
}

// ResolveTelegramDC resolves the destination address for a direct Telegram connection.
// It prioritizes explicit backend/staticDC configurations, falling back to dynamic DC index
// resolution from the handshake.
func ResolveTelegramDC(backend, staticDC string, dcIdx int16, preferIPv6 bool, overrides map[int16]string) (string, error) {
	// 1. Check if backend specifies a static address or DC index
	candidate := strings.TrimSpace(backend)
	if candidate != "" && !strings.EqualFold(candidate, "auto") {
		return resolveCandidate(candidate, preferIPv6)
	}

	// 2. Check if staticDC specifies a static address or DC index
	candidate = strings.TrimSpace(staticDC)
	if candidate != "" && !strings.EqualFold(candidate, "auto") {
		return resolveCandidate(candidate, preferIPv6)
	}

	// Normalize older media DC representation (10000 + DC)
	if dcIdx > 10000 && dcIdx <= 10005 {
		dcIdx = -(dcIdx - 10000)
	}

	absIdx := absDC(dcIdx)

	// 3. Dynamic resolution from handshake dcIdx
	// 3a. Check overrides
	if overrides != nil {
		if addr, ok := overrides[dcIdx]; ok && addr != "" {
			return addr, nil
		}
		if addr, ok := overrides[absIdx]; ok && addr != "" {
			return addr, nil
		}
	}

	// 3b. IPv6 resolution if preferred
	if preferIPv6 {
		if addr, ok := defaultTelegramDCsIPv6[dcIdx]; ok {
			return addr, nil
		}
		if addr, ok := defaultTelegramDCsIPv6[absIdx]; ok {
			return addr, nil
		}
	}

	// 3c. IPv4 resolution
	if addr, ok := defaultTelegramDCsIPv4[dcIdx]; ok {
		return addr, nil
	}
	if addr, ok := defaultTelegramDCsIPv4[absIdx]; ok {
		return addr, nil
	}

	// 3d. Fallback across IP versions
	if preferIPv6 {
		if addr, ok := defaultTelegramDCsIPv4[dcIdx]; ok {
			return addr, nil
		}
		if addr, ok := defaultTelegramDCsIPv4[absIdx]; ok {
			return addr, nil
		}
	} else {
		if addr, ok := defaultTelegramDCsIPv6[dcIdx]; ok {
			return addr, nil
		}
		if addr, ok := defaultTelegramDCsIPv6[absIdx]; ok {
			return addr, nil
		}
	}

	// Fallback to default DC 2 (Amsterdam) if dcIdx is unknown or 0
	if preferIPv6 {
		return defaultTelegramDCsIPv6[2], nil
	}
	return defaultTelegramDCsIPv4[2], nil
}

func resolveCandidate(val string, preferIPv6 bool) (string, error) {
	// If it contains a port or colon (e.g. "149.154.167.51:443" or "[2001:...]:443")
	if strings.Contains(val, ":") {
		_, _, err := net.SplitHostPort(val)
		if err != nil {
			return "", fmt.Errorf("invalid DC host:port %q: %w", val, err)
		}
		return val, nil
	}

	// Clean optional "dc" prefix, e.g. "dc2" -> "2", "dc-2" -> "-2", "dc203" -> "203"
	cleanVal := strings.TrimPrefix(strings.ToLower(val), "dc")
	dcNum, err := strconv.Atoi(cleanVal)
	if err == nil {
		idx := int16(dcNum)
		absIdx := absDC(idx)
		if preferIPv6 {
			if addr, ok := defaultTelegramDCsIPv6[idx]; ok {
				return addr, nil
			}
			if addr, ok := defaultTelegramDCsIPv6[absIdx]; ok {
				return addr, nil
			}
		}
		if addr, ok := defaultTelegramDCsIPv4[idx]; ok {
			return addr, nil
		}
		if addr, ok := defaultTelegramDCsIPv4[absIdx]; ok {
			return addr, nil
		}
	}

	return "", fmt.Errorf("unrecognized DC target %q", val)
}

func (s *backendStream) runDirect() {
	dialAccounted := false
	defer func() {
		if !dialAccounted {
			s.session.backendDialFinished(false)
		}
	}()

	// 1. Wait for client's initial handshake data with timeout (minimum 64 bytes)
	hsTimer := time.AfterFunc(s.session.timeouts.BackendDial.Value(), func() {
		s.close()
	})
	firstData, ok := s.session.nextWrite(s.id, s.ctx.Done())
	if !ok {
		hsTimer.Stop()
		return
	}
	consumedItems := 1
	for len(firstData) < 64 {
		nextChunk, ok := s.session.nextWrite(s.id, s.ctx.Done())
		if !ok {
			hsTimer.Stop()
			return
		}
		firstData = append(firstData, nextChunk...)
		consumedItems++
	}
	hsTimer.Stop()

	// 2. Parse client handshake
	secretBytes := s.session.RawSecret()
	if len(secretBytes) == 0 && s.session.profile != nil {
		secretBytes, _ = config.DecodeSecret(s.session.profile.Secret)
	}
	hsRes, err := ParseClientHandshake(firstData[:64], secretBytes)
	if err != nil {
		logger.Warn("direct client handshake failed", "stream_id", s.id, "err", err)
		return
	}

	// 3. Resolve target Telegram DC address
	var backendStr, staticDCStr string
	var preferIPv6 bool
	if s.session.profile != nil {
		backendStr = s.session.profile.Backend
		staticDCStr = s.session.profile.StaticDC.String()
		preferIPv6 = s.session.profile.PreferIPv6
	}
	targetAddress, err := ResolveTelegramDC(backendStr, staticDCStr, hsRes.DCIdx, preferIPv6, nil)
	if err != nil {
		logger.Warn("direct telegram dc resolve failed", "stream_id", s.id, "dc", hsRes.DCIdx, "err", err)
		return
	}
	logger.Debug("direct stream handshake parsed",
		"stream_id", s.id,
		"dc", hsRes.DCIdx,
		"tag", fmt.Sprintf("0x%08x", hsRes.Tag),
		"target", targetAddress,
	)

	// 4. Dial target DC
	dialer := net.Dialer{Timeout: s.session.timeouts.BackendDial.Value()}
	connection, err := dialer.DialContext(s.ctx, "tcp", targetAddress)
	dialAccounted = true
	s.session.backendDialFinished(err != nil && s.ctx.Err() == nil)
	if err != nil {
		if s.ctx.Err() == nil {
			logger.Warn("direct telegram dc dial failed", "stream_id", s.id, "target", targetAddress, "dc", hsRes.DCIdx, "err", err)
		}
		return
	}
	logger.Debug("direct telegram dc connected", "stream_id", s.id, "target", targetAddress, "dc", hsRes.DCIdx)
	s.connMu.Lock()
	if s.ctx.Err() != nil {
		s.connMu.Unlock()
		_ = connection.Close()
		return
	}
	s.conn = connection
	s.connMu.Unlock()

	// 5. Handshake + Initial Payload in one TCP write (Zero-overhead First Packet)
	tgHandshake, tgEncryptor, tgDecryptor, err := CreateTelegramHandshake(hsRes.Tag, hsRes.DCIdx)
	if err != nil {
		s.close()
		return
	}

	// Re-encrypt trailing payload in-place
	if len(firstData) > 64 {
		rem := firstData[64:]
		hsRes.ClientDecryptor.XORKeyStream(rem, rem)
		tgEncryptor.XORKeyStream(rem, rem)
	}
	// Place generated Telegram obfuscated2 handshake in first 64 bytes
	copy(firstData[:64], tgHandshake)

	_ = connection.SetWriteDeadline(time.Now().Add(s.session.timeouts.BackendDial.Value()))
	totalToWrite := firstData
	for len(totalToWrite) != 0 {
		written, err := connection.Write(totalToWrite)
		if written > 0 {
			if !s.session.backendDrained(s.id, written) {
				s.close()
				return
			}
			totalToWrite = totalToWrite[written:]
		}
		if err != nil || written == 0 {
			s.close()
			return
		}
	}
	_ = connection.SetWriteDeadline(time.Time{})

	for i := 0; i < consumedItems; i++ {
		if !s.session.backendWriteFinished(s.id) {
			s.close()
			return
		}
	}

	// 6. Start write loop and read loop
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		s.directWriteLoop(connection, hsRes.ClientDecryptor, tgEncryptor)
		s.close()
	}()
	s.directReadLoop(connection, hsRes.ClientEncryptor, tgDecryptor)
	s.close()
	<-writeDone
}

func (s *backendStream) directWriteLoop(connection net.Conn, clientDec, tgEnc cipher.Stream) {
	for {
		data, ok := s.session.nextWrite(s.id, s.ctx.Done())
		if !ok {
			return
		}
		clientDec.XORKeyStream(data, data)
		tgEnc.XORKeyStream(data, data)
		_ = connection.SetWriteDeadline(time.Now().Add(s.session.timeouts.Idle.Value()))
		for len(data) != 0 {
			written, err := connection.Write(data)
			if written > 0 {
				if !s.session.backendDrained(s.id, written) {
					return
				}
				data = data[written:]
			}
			if err != nil || written == 0 {
				return
			}
		}
		if !s.session.backendWriteFinished(s.id) {
			return
		}
	}
}

func (s *backendStream) directReadLoop(connection net.Conn, clientEnc, tgDec cipher.Stream) {
	buffer := make([]byte, frame.DataChunk)
	for {
		allowance, ok := s.session.nextReadAllowance(s.id, s.ctx.Done())
		if !ok {
			return
		}
		chunk := buffer
		if allowance < len(chunk) {
			chunk = chunk[:allowance]
		}
		_ = connection.SetReadDeadline(time.Now().Add(s.session.timeouts.Idle.Value()))
		count, err := connection.Read(chunk)
		if count > 0 {
			payload := chunk[:count]
			tgDec.XORKeyStream(payload, payload)
			clientEnc.XORKeyStream(payload, payload)
			if !s.session.backendData(s.id, payload) {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
