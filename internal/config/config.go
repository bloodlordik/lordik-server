package config

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"runtime"
	"time"
	"github.com/telegramdesktop/tproxy-server/internal/logger"
)

const (
	capabilityContext   = "tdesktop-web-proxy-bridge-v1\n"
	capabilityContextV2 = "tdesktop-web-proxy-bridge-v2\n"
)

// MaxBasePathLength bounds the optional relay prefix. See BASE_PATH.md.
const MaxBasePathLength = 128

// MaxCarrierBatchBytes is the largest downlink body a carrier may deliver:
// the desktop client's browser-fallback loopback WebSocket rejects messages
// above 2 MiB, so a larger relay batch would kill that carrier.
const MaxCarrierBatchBytes = 2 * 1024 * 1024

type CarrierMode string

const (
	CarrierHTTPS          CarrierMode = "https"
	CarrierHTTPSLanes     CarrierMode = "https-lanes"
	CarrierWebSocket      CarrierMode = "websocket"
	CarrierWebSocketLanes CarrierMode = "websocket-lanes"
	CarrierCDN            CarrierMode = "cdn"
	CarrierCDNAdaptive    CarrierMode = "cdn-adaptive"
	CarrierCDNGet         CarrierMode = "cdn-get"
	CarrierCDNBody        CarrierMode = "cdn-body"
	CarrierCDNWS          CarrierMode = "cdn-ws"
)

func (m CarrierMode) Valid() bool {
	return m == CarrierHTTPS ||
		m == CarrierHTTPSLanes ||
		m == CarrierWebSocket ||
		m == CarrierWebSocketLanes ||
		m == CarrierCDN ||
		m == CarrierCDNAdaptive ||
		m == CarrierCDNGet ||
		m == CarrierCDNBody ||
		m == CarrierCDNWS
}

func (m CarrierMode) IsCDN() bool {
	return m == CarrierCDN ||
		m == CarrierCDNAdaptive ||
		m == CarrierCDNGet ||
		m == CarrierCDNBody ||
		m == CarrierCDNWS
}

func (m CarrierMode) WithDefault() CarrierMode {
	if m == "" {
		return CarrierHTTPS
	}
	return m
}

type BackendType string

const (
	BackendMTProxy BackendType = "mtproxy"
	BackendTelemt  BackendType = "telemt"
	BackendDirect  BackendType = "direct"
)

func (b BackendType) Valid() bool {
	return b == "" || b == BackendMTProxy || b == BackendTelemt || b == BackendDirect
}

func (b BackendType) WithDefault() BackendType {
	if b == "" {
		return BackendMTProxy
	}
	return b
}

func (b *BackendType) UnmarshalJSON(input []byte) error {
	var str string
	if err := json.Unmarshal(input, &str); err != nil {
		return err
	}
	normalized := BackendType(strings.ToLower(strings.TrimSpace(str)))
	if normalized == "" {
		*b = BackendMTProxy
		return nil
	}
	if !normalized.Valid() {
		return fmt.Errorf("backend_type must be %q, %q or %q, got %q", BackendMTProxy, BackendTelemt, BackendDirect, str)
	}
	*b = normalized
	return nil
}

type BackendProxyProtocol string

const (
	BackendProxyNone BackendProxyProtocol = "none"
	BackendProxyV1   BackendProxyProtocol = "v1"
	BackendProxyV2   BackendProxyProtocol = "v2"
)

func (p BackendProxyProtocol) Valid() bool {
	return p == "" || p == BackendProxyNone || p == BackendProxyV1 || p == BackendProxyV2
}

func (p BackendProxyProtocol) WithDefault() BackendProxyProtocol {
	if p == "" {
		return BackendProxyNone
	}
	return p
}

func (p *BackendProxyProtocol) UnmarshalJSON(input []byte) error {
	var boolVal bool
	if err := json.Unmarshal(input, &boolVal); err == nil {
		if boolVal {
			*p = BackendProxyV1
		} else {
			*p = BackendProxyNone
		}
		return nil
	}
	var str string
	if err := json.Unmarshal(input, &str); err != nil {
		return err
	}
	normalized := BackendProxyProtocol(strings.ToLower(strings.TrimSpace(str)))
	if normalized == "" {
		*p = BackendProxyNone
		return nil
	}
	if !normalized.Valid() {
		return fmt.Errorf("backend_proxy_protocol must be %q, %q, or %q, got %q", BackendProxyNone, BackendProxyV1, BackendProxyV2, str)
	}
	*p = normalized
	return nil
}
type StaticDC string

func (s *StaticDC) UnmarshalJSON(input []byte) error {
	var intVal int
	if err := json.Unmarshal(input, &intVal); err == nil {
		*s = StaticDC(strconv.Itoa(intVal))
		return nil
	}
	var strVal string
	if err := json.Unmarshal(input, &strVal); err != nil {
		return err
	}
	*s = StaticDC(strings.TrimSpace(strVal))
	return nil
}

func (s StaticDC) String() string {
	return string(s)
}

type Duration time.Duration

func (d *Duration) UnmarshalJSON(input []byte) error {
	var text string
	if err := json.Unmarshal(input, &text); err != nil {
		return errors.New("duration must be a string such as \"5s\"")
	}
	value, err := time.ParseDuration(text)
	if err != nil {
		return err
	}
	*d = Duration(value)
	return nil
}

func (d Duration) Value() time.Duration {
	return time.Duration(d)
}

type Limits struct {
	MaxHeaderBytes            int `json:"max_header_bytes"`
	MaxBodyBytes              int `json:"max_body_bytes"`
	MaxFramePayload           int `json:"max_frame_payload"`
	CarrierBatchBytes         int `json:"carrier_batch_bytes"`
	MaxStreamsPerSession      int `json:"max_streams_per_session"`
	MaxClosedStreamIDs        int `json:"max_closed_stream_ids"`
	MaxPendingPerSession      int `json:"max_pending_per_session"`
	MaxPendingGlobal          int `json:"max_pending_global"`
	MaxPendingItemsPerSession int `json:"max_pending_items_per_session"`
	MaxPendingItemsGlobal     int `json:"max_pending_items_global"`
	MaxSessionsPerIP          int `json:"max_sessions_per_ip"`
	MaxSessionsGlobal         int `json:"max_sessions_global"`
	MaxStreamsGlobal          int `json:"max_streams_global"`
	MaxBackendDialsInFlight   int `json:"max_backend_dials_in_flight"`
	NewSessionsPerMinute      int `json:"new_sessions_per_minute"`
	NewSessionsBurst          int `json:"new_sessions_burst"`
	NewStreamsPerMinute       int `json:"new_streams_per_minute"`
	NewStreamsBurst           int `json:"new_streams_burst"`
	MaxBootstrapsPerIP        int `json:"max_bootstraps_per_ip"`
	MaxBootstrapsGlobal       int `json:"max_bootstraps_global"`
	NewBootstrapsPerMinute    int `json:"new_bootstraps_per_minute"`
	NewBootstrapsBurst        int `json:"new_bootstraps_burst"`
	MaxProfiles               int `json:"max_profiles"`
	CDNPollTimeoutSecs        int `json:"cdn_poll_timeout_secs"`
	CDNMaxDownBatchBytes      int `json:"cdn_max_down_batch_bytes"`
	CDNUplinkWindowSize       int `json:"cdn_uplink_window_size"`
	CDNStreamMaxDurationSecs  int `json:"cdn_stream_max_duration_secs"`
	CDNStreamHeartbeatSecs    int `json:"cdn_stream_heartbeat_secs"`
	CDNMaxUnackedBatches      int `json:"cdn_max_unacked_batches"`
}

type Timeouts struct {
	BackendDial       Duration `json:"backend_dial"`
	LongPoll          Duration `json:"long_poll"`
	ReconnectGrace    Duration `json:"reconnect_grace"`
	BootstrapLifetime Duration `json:"bootstrap_lifetime"`
	ReadHeader        Duration `json:"read_header"`
	Idle              Duration `json:"idle"`
	Shutdown          Duration `json:"shutdown"`
}
type LoggingConfig struct {
	Enabled bool   `json:"enabled"`
	Level   string `json:"level"`
	Format  string `json:"format"`
	Output  string `json:"output"`
	Dir     string `json:"dir"`
	Prefix  string `json:"prefix"`
	MaxDays int    `json:"max_days"`
}
func (l LoggingConfig) ToLoggerOptions() logger.Options {
	prefix := l.Prefix
	if prefix == "" {
		prefix = "tproxy"
	}
	return logger.Options{
		Enabled: l.Enabled,
		Level:   l.Level,
		Format:  l.Format,
		Output:  l.Output,
		Dir:     l.Dir,
		Prefix:  prefix,
		MaxDays: l.MaxDays,
	}
}



type Config struct {
	PublicHostname       string               `json:"public_hostname"`
	BasePath             string               `json:"base_path"`
	Listen               string               `json:"listen"`
	AdminListen          string               `json:"admin_listen"`
	BackendType          BackendType          `json:"backend_type,omitempty"`
	BackendProxyProtocol BackendProxyProtocol `json:"backend_proxy_protocol,omitempty"`
	StaticDC             StaticDC             `json:"static_dc,omitempty"`
	PreferIPv6           bool                 `json:"prefer_ipv6,omitempty"`
	PublicDir            string               `json:"public_dir"`
	PublicUpstream       string               `json:"public_upstream"`
	StaticRoutes         string               `json:"static_routes"`
	TokenKeyFile         string               `json:"token_key_file"`
	ProfilesFile         string               `json:"profiles_file"`
	EnablePprof          bool                 `json:"enable_pprof"`
	Limits               Limits               `json:"limits"`
	Timeouts             Timeouts             `json:"timeouts"`
	Logging              LoggingConfig        `json:"logging"`
	Profiles             []Profile            `json:"-"`
	LegacyTokenDrain     bool                 `json:"-"`
}

type profileFile struct {
	Profiles []profileInput `json:"profiles"`
}

type profileInput struct {
	Name                 string               `json:"name"`
	Secret               string               `json:"secret"`
	Backend              string               `json:"backend"`
	BackendType          BackendType          `json:"backend_type,omitempty"`
	BackendProxyProtocol BackendProxyProtocol `json:"backend_proxy_protocol,omitempty"`
	StaticDC             StaticDC             `json:"static_dc,omitempty"`
	PreferIPv6           bool                 `json:"prefer_ipv6,omitempty"`
	CarrierMode          CarrierMode          `json:"carrier_mode"`
	Limits               ProfileLimits        `json:"limits"`

	// Virtual Host configuration (optional, defaults inherited from global Config)
	Hostname           string  `json:"hostname,omitempty"`
	BasePath           *string `json:"base_path,omitempty"`
	PublicDir          string  `json:"public_dir,omitempty"`
	PublicUpstream     string  `json:"public_upstream,omitempty"`
	TrustedHostHeader  string  `json:"trusted_host_header,omitempty"`
	TrustedIPHeader    string  `json:"trusted_ip_header,omitempty"`
	DisableIPRateLimit bool    `json:"disable_ip_rate_limit,omitempty"`
}

type ProfileLimits struct {
	MaxSessions             int `json:"max_sessions"`
	MaxStreams              int `json:"max_streams"`
	MaxBackendDialsInFlight int `json:"max_backend_dials_in_flight"`
	NewSessionsPerMinute    int `json:"new_sessions_per_minute"`
	NewSessionsBurst        int `json:"new_sessions_burst"`
	NewStreamsPerMinute     int `json:"new_streams_per_minute"`
	NewStreamsBurst         int `json:"new_streams_burst"`
	MaxStreamsPerSession    int `json:"max_streams_per_session"`
	MaxPendingPerSession    int `json:"max_pending_per_session"`
	CDNPollTimeoutSecs      int `json:"cdn_poll_timeout_secs"`
	CDNMaxDownBatchBytes    int `json:"cdn_max_down_batch_bytes"`
	CDNUplinkWindowSize     int `json:"cdn_uplink_window_size"`
	CDNStreamMaxDurationSecs int `json:"cdn_stream_max_duration_secs"`
	CDNStreamHeartbeatSecs   int `json:"cdn_stream_heartbeat_secs"`
	CDNMaxUnackedBatches     int `json:"cdn_max_unacked_batches"`
}

type Profile struct {
	Name                 string
	Secret               string
	Backend              string
	BackendType          BackendType
	BackendProxyProtocol BackendProxyProtocol
	StaticDC             StaticDC
	PreferIPv6           bool
	CarrierMode          CarrierMode
	Capability           [sha256.Size]byte
	Limits               ProfileLimits

	// Normalized Effective VHost settings
	Hostname           string
	BasePath           string
	PublicDir          string
	PublicUpstream     string
	TrustedHostHeader  string
	TrustedIPHeader    string
	DisableIPRateLimit bool
}

func (p Profile) BackendNetworkAndAddress() (string, string) {
	if p.BackendType == BackendDirect {
		return "tcp", p.Backend
	}
	if strings.HasPrefix(p.Backend, "unix://") {
		return "unix", strings.TrimPrefix(p.Backend, "unix://")
	}
	if strings.HasPrefix(p.Backend, "unix:") {
		return "unix", strings.TrimPrefix(p.Backend, "unix:")
	}
	if strings.HasPrefix(p.Backend, "/") {
		return "unix", p.Backend
	}
	return "tcp", p.Backend
}

func (limits ProfileLimits) WithDefaults(global Limits) ProfileLimits {
	result := limits
	if result.MaxSessions == 0 {
		result.MaxSessions = global.MaxSessionsGlobal
	}
	if result.MaxStreams == 0 {
		result.MaxStreams = global.MaxStreamsGlobal
	}
	if result.MaxBackendDialsInFlight == 0 {
		result.MaxBackendDialsInFlight = minInt(
			global.MaxBackendDialsInFlight,
			result.MaxStreams)
	}
	if result.NewSessionsPerMinute == 0 {
		result.NewSessionsPerMinute = global.NewSessionsPerMinute
	}
	if result.NewSessionsBurst == 0 {
		result.NewSessionsBurst = global.NewSessionsBurst
	}
	if result.NewStreamsPerMinute == 0 {
		result.NewStreamsPerMinute = global.NewStreamsPerMinute
	}
	if result.NewStreamsBurst == 0 {
		result.NewStreamsBurst = global.NewStreamsBurst
	}
	if result.MaxStreamsPerSession == 0 {
		result.MaxStreamsPerSession = minInt(
			global.MaxStreamsPerSession,
			result.MaxStreams)
	}
	if result.MaxPendingPerSession == 0 {
		result.MaxPendingPerSession = global.MaxPendingPerSession
	}
	if result.CDNPollTimeoutSecs == 0 {
		result.CDNPollTimeoutSecs = global.CDNPollTimeoutSecs
	}
	if result.CDNMaxDownBatchBytes == 0 {
		result.CDNMaxDownBatchBytes = global.CDNMaxDownBatchBytes
	}
	if result.CDNUplinkWindowSize == 0 {
		result.CDNUplinkWindowSize = global.CDNUplinkWindowSize
	}
	if result.CDNStreamMaxDurationSecs == 0 {
		result.CDNStreamMaxDurationSecs = global.CDNStreamMaxDurationSecs
	}
	if result.CDNStreamHeartbeatSecs == 0 {
		result.CDNStreamHeartbeatSecs = global.CDNStreamHeartbeatSecs
	}
	if result.CDNMaxUnackedBatches == 0 {
		result.CDNMaxUnackedBatches = global.CDNMaxUnackedBatches
	}
	return result
}

func Defaults() Config {
	return Config{
		BackendType:          BackendMTProxy,
		BackendProxyProtocol: BackendProxyNone,
		Listen:               "127.0.0.1:8080",
		AdminListen:          "127.0.0.1:8081",
		StaticRoutes:         "legacy",
		TokenKeyFile:         "token.key",
		Limits: Limits{
			MaxHeaderBytes:            16 * 1024,
			MaxBodyBytes:              2 * 1024 * 1024,
			MaxFramePayload:           1024 * 1024,
			CarrierBatchBytes:         2 * 1024 * 1024,
			MaxStreamsPerSession:      128,
			MaxClosedStreamIDs:        4096,
			MaxPendingPerSession:      32 * 1024 * 1024,
			MaxPendingGlobal:          512 * 1024 * 1024,
			MaxPendingItemsPerSession: 16 * 1024,
			MaxPendingItemsGlobal:     256 * 1024,
			MaxSessionsPerIP:          0,
			MaxSessionsGlobal:         128,
			MaxStreamsGlobal:          4096,
			MaxBackendDialsInFlight:   256,
			NewSessionsPerMinute:      600,
			NewSessionsBurst:          128,
			NewStreamsPerMinute:       6000,
			NewStreamsBurst:           512,
			MaxBootstrapsPerIP:        0,
			MaxBootstrapsGlobal:       512,
			NewBootstrapsPerMinute:    1200,
			NewBootstrapsBurst:        256,
			MaxProfiles:               32,
			CDNPollTimeoutSecs:        12,
			CDNMaxDownBatchBytes:      524288,
			CDNUplinkWindowSize:       64,
			CDNStreamMaxDurationSecs:  45,
			CDNStreamHeartbeatSecs:    10,
			CDNMaxUnackedBatches:      32,
		},
		Timeouts: Timeouts{
			BackendDial:       Duration(5 * time.Second),
			LongPoll:          Duration(25 * time.Second),
			ReconnectGrace:    Duration(2 * time.Minute),
			BootstrapLifetime: Duration(2 * time.Minute),
			ReadHeader:        Duration(10 * time.Second),
			Idle:              Duration(75 * time.Second),
			Shutdown:          Duration(15 * time.Second),
		},
		Logging: LoggingConfig{
			Enabled: true,
			Level:   "info",
			Format:  "text",
			Output:  "stdout",
			Dir:     "logs",
			Prefix:  "tproxy",
			MaxDays: 7,
		},
	}
}

func Load(path string, profilesOverride ...string) (Config, error) {
	result := Defaults()
	input, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(input)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Config{}, errors.New("decode config: trailing data")
	}
	if result.PublicDir != "" && !filepath.IsAbs(result.PublicDir) {
		result.PublicDir = filepath.Join(filepath.Dir(path), result.PublicDir)
	}
	if result.ProfilesFile != "" && !filepath.IsAbs(result.ProfilesFile) {
		result.ProfilesFile = filepath.Join(filepath.Dir(path), result.ProfilesFile)
	}
	if !filepath.IsAbs(result.TokenKeyFile) {
		result.TokenKeyFile = filepath.Join(filepath.Dir(path), result.TokenKeyFile)
	}
	if result.Logging.Dir != "" && !filepath.IsAbs(result.Logging.Dir) {
		result.Logging.Dir = filepath.Join(filepath.Dir(path), result.Logging.Dir)
	}
	if len(profilesOverride) > 1 {
		return Config{}, errors.New("only one profiles override is allowed")
	}
	if len(profilesOverride) == 1 && profilesOverride[0] != "" {
		result.ProfilesFile = profilesOverride[0]
	}
	if err := result.validate(); err != nil {
		return Config{}, err
	}
	profiles, err := loadProfiles(result.ProfilesFile, result.PublicHostname, result.BasePath, result.Limits, result.BackendType)
	if err != nil {
		return Config{}, err
	}
	result.Profiles = profiles
	return result, nil
}

func (c Config) validate() error {
	if !c.BackendType.Valid() {
		return fmt.Errorf("backend_type must be %q, %q or %q", BackendMTProxy, BackendTelemt, BackendDirect)
	}
	if !c.BackendProxyProtocol.Valid() {
		return fmt.Errorf("backend_proxy_protocol must be %q, %q, or %q", BackendProxyNone, BackendProxyV1, BackendProxyV2)
	}
	if c.BackendType.WithDefault() == BackendMTProxy && c.BackendProxyProtocol.WithDefault() != BackendProxyNone {
		return errors.New("official mtproxy does not support PROXY protocol; use telemt or disable backend_proxy_protocol")
	}
	if c.BackendType.WithDefault() == BackendDirect && c.BackendProxyProtocol.WithDefault() != BackendProxyNone {
		return errors.New("direct backend does not support PROXY protocol; disable backend_proxy_protocol")
	}
	if c.StaticRoutes != "exact" && c.StaticRoutes != "legacy" {
		return errors.New("static_routes must be exact or legacy")
	}
	if err := ValidateHostname(c.PublicHostname); err != nil {
		return fmt.Errorf("public_hostname: %w", err)
	}
	if c.PublicHostname != strings.ToLower(c.PublicHostname) {
		return errors.New("public_hostname must already be lowercase ASCII/IDNA")
	}
	if err := ValidateBasePath(c.BasePath); err != nil {
		return fmt.Errorf("base_path: %w", err)
	}
	if err := validateLoopbackAddress(c.Listen); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if err := validateLoopbackAddress(c.AdminListen); err != nil {
		return fmt.Errorf("admin_listen: %w", err)
	}
	if c.Listen == c.AdminListen {
		return errors.New("listen and admin_listen must differ")
	}
	if (c.PublicDir == "") == (c.PublicUpstream == "") {
		return errors.New("exactly one of public_dir or public_upstream is required")
	}
	if c.PublicDir != "" {
		info, err := os.Stat(c.PublicDir)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("public_dir is not a directory: %s", c.PublicDir)
		}
		if _, err := os.Stat(filepath.Join(c.PublicDir, "index.html")); err != nil {
			return errors.New("public_dir must contain index.html")
		}
	} else if err := validatePublicUpstream(c.PublicUpstream); err != nil {
		return fmt.Errorf("public_upstream: %w", err)
	}
	if c.ProfilesFile == "" {
		return errors.New("profiles_file is required")
	}
	if c.Limits.MaxHeaderBytes < 4096 || c.Limits.MaxBodyBytes < 1024 || c.Limits.MaxFramePayload <= 0 || c.Limits.MaxFramePayload > 1024*1024 || c.Limits.CarrierBatchBytes < 256*1024 || c.Limits.CarrierBatchBytes > c.Limits.MaxBodyBytes {
		return errors.New("invalid HTTP or frame limits")
	}
	if c.Limits.CarrierBatchBytes > MaxCarrierBatchBytes {
		return errors.New("carrier_batch_bytes must not exceed the 2 MiB desktop loopback message cap")
	}
	if c.Limits.CDNPollTimeoutSecs <= 0 {
		return errors.New("cdn_poll_timeout_secs must be positive")
	}
	if c.Limits.CDNMaxDownBatchBytes <= 0 || c.Limits.CDNMaxDownBatchBytes > c.Limits.MaxBodyBytes {
		return errors.New("cdn_max_down_batch_bytes must be positive and not exceed max_body_bytes")
	}
	if c.Limits.CDNUplinkWindowSize <= 0 || c.Limits.CDNUplinkWindowSize > 128 {
		return errors.New("cdn_uplink_window_size must be between 1 and 128")
	}
	if c.Limits.CDNStreamMaxDurationSecs < 10 || c.Limits.CDNStreamMaxDurationSecs > 300 {
		return errors.New("cdn_stream_max_duration_secs must be between 10 and 300")
	}
	if c.Limits.CDNStreamHeartbeatSecs < 1 || c.Limits.CDNStreamHeartbeatSecs > 30 {
		return errors.New("cdn_stream_heartbeat_secs must be between 1 and 30")
	}
	if c.Limits.CDNMaxUnackedBatches < 4 || c.Limits.CDNMaxUnackedBatches > 128 {
		return errors.New("cdn_max_unacked_batches must be between 4 and 128")
	}
	values := []int{
		c.Limits.MaxStreamsPerSession, c.Limits.MaxClosedStreamIDs,
		c.Limits.MaxPendingPerSession, c.Limits.MaxPendingGlobal,
		c.Limits.MaxPendingItemsPerSession, c.Limits.MaxPendingItemsGlobal,
		c.Limits.MaxSessionsGlobal, c.Limits.MaxStreamsGlobal,
		c.Limits.MaxBackendDialsInFlight,
		c.Limits.NewSessionsPerMinute, c.Limits.NewSessionsBurst,
		c.Limits.NewStreamsPerMinute, c.Limits.NewStreamsBurst,
		c.Limits.MaxBootstrapsGlobal,
		c.Limits.NewBootstrapsPerMinute, c.Limits.NewBootstrapsBurst,
		c.Limits.MaxProfiles,
	}
	for _, value := range values {
		if value <= 0 {
			return errors.New("all resource limits must be positive")
		}
	}
	if c.Limits.MaxSessionsPerIP < 0 || c.Limits.MaxBootstrapsPerIP < 0 {
		return errors.New("per-IP limits must not be negative")
	}
	if c.Limits.MaxPendingGlobal < c.Limits.MaxPendingPerSession ||
		c.Limits.MaxPendingItemsGlobal < c.Limits.MaxPendingItemsPerSession ||
		c.Limits.MaxSessionsGlobal < c.Limits.MaxSessionsPerIP ||
		c.Limits.MaxStreamsGlobal < c.Limits.MaxStreamsPerSession ||
		c.Limits.MaxStreamsGlobal < c.Limits.MaxBackendDialsInFlight ||
		c.Limits.MaxBootstrapsGlobal < c.Limits.MaxBootstrapsPerIP {
		return errors.New("global limits must not be smaller than per-session or per-IP limits")
	}
	durations := []time.Duration{
		c.Timeouts.BackendDial.Value(), c.Timeouts.LongPoll.Value(),
		c.Timeouts.ReconnectGrace.Value(), c.Timeouts.BootstrapLifetime.Value(),
		c.Timeouts.ReadHeader.Value(), c.Timeouts.Idle.Value(), c.Timeouts.Shutdown.Value(),
	}
	for _, value := range durations {
		if value <= 0 {
			return errors.New("all timeouts must be positive")
		}
	}
	if c.Logging.Enabled {
		lvl := strings.ToLower(strings.TrimSpace(c.Logging.Level))
		if lvl != "" && lvl != "debug" && lvl != "info" && lvl != "warn" && lvl != "warning" && lvl != "error" {
			return fmt.Errorf("invalid logging.level %q: must be debug, info, warn, or error", c.Logging.Level)
		}
		fmtStr := strings.ToLower(strings.TrimSpace(c.Logging.Format))
		if fmtStr != "" && fmtStr != "text" && fmtStr != "json" {
			return fmt.Errorf("invalid logging.format %q: must be text or json", c.Logging.Format)
		}
		out := strings.ToLower(strings.TrimSpace(c.Logging.Output))
		if out != "" && out != "stdout" && out != "file" && out != "both" {
			return fmt.Errorf("invalid logging.output %q: must be stdout, file, or both", c.Logging.Output)
		}
		if (out == "file" || out == "both") && c.Logging.MaxDays < 0 {
			return errors.New("logging.max_days must be non-negative")
		}
	}
	return nil
}

func ValidateHostname(host string) error {
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") || strings.ContainsAny(host, ":/@?#[]") {
		return errors.New("must be a DNS hostname without scheme, port, path, query, fragment, or trailing dot")
	}
	if net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return errors.New("IP addresses and single-label names are not allowed")
	}
	for _, character := range host {
		if character > 127 {
			return errors.New("use the lowercase ASCII IDNA A-label form")
		}
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid DNS label")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return errors.New("hostname must be lowercase ASCII/IDNA")
			}
		}
	}
	return nil
}

// DeriveCapability binds the capability to the host, and to the base path when
// one is configured. A root deployment keeps the frozen v1 context byte for
// byte, so a capability minted for one prefix authenticates nothing at another
// prefix or at the root.
// ValidateBasePath accepts only the canonical form: one or more "/"-separated
// segments, each starting with an ASCII letter or digit and continuing with
// those, "-" or "_". An empty value serves the host root. "." is not in the
// alphabet, so "." and ".." segments cannot occur and no dot-segment resolution
// is ever needed. Noncanonical values are rejected rather than repaired, so the
// configured value and the wire path stay the same string.
func ValidateBasePath(path string) error {
	if path == "" {
		return nil
	}
	if len(path) > MaxBasePathLength {
		return fmt.Errorf("must be at most %d characters", MaxBasePathLength)
	}
	if strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") {
		return errors.New("must not start or end with \"/\"")
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "" {
			return errors.New("must not contain an empty segment")
		}
		for i := 0; i < len(segment); i++ {
			character := segment[i]
			switch {
			case character >= 'a' && character <= 'z',
				character >= 'A' && character <= 'Z',
				character >= '0' && character <= '9':
			case (character == '-' || character == '_') && i > 0:
			default:
				return errors.New("segments must match [A-Za-z0-9][A-Za-z0-9_-]*")
			}
		}
	}
	return nil
}

// Base is the wire prefix every relay endpoint sits under. It always begins and
// ends with "/", so an endpoint is Base() + "api/v1/up".
func Base(basePath string) string {
	if basePath == "" {
		return "/"
	}
	return "/" + basePath + "/"
}

func (c Config) Base() string {
	return Base(c.BasePath)
}

func DeriveCapability(host, basePath string, secret []byte) [sha256.Size]byte {
	mac := hmac.New(sha256.New, secret)
	if basePath == "" {
		_, _ = mac.Write([]byte(capabilityContext + host))
	} else {
		_, _ = mac.Write([]byte(capabilityContextV2 + host + "\n" + basePath))
	}
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func CapabilityString(capability [sha256.Size]byte) string {
	return base64.RawURLEncoding.EncodeToString(capability[:])
}

func DecodeSecret(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	var decoded []byte
	var err error
	if len(value) == 32 || len(value) == 34 {
		decoded, err = hex.DecodeString(value)
	} else {
		encodings := []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding}
		for _, encoding := range encodings {
			decoded, err = encoding.DecodeString(value)
			if err == nil {
				break
			}
		}
	}
	if err != nil || (len(decoded) != 16 && len(decoded) != 17) {
		return nil, errors.New("secret must decode to 16 bytes, optionally prefixed with dd")
	}
	if len(decoded) == 17 && decoded[0] != 0xdd {
		return nil, errors.New("17-byte secret must use the dd prefix")
	}
	return decoded, nil
}

func validateLoopbackAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("must use a numeric loopback address")
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return errors.New("invalid port")
	}
	return nil
}

func validateDirectBackendAddress(backend string) error {
	trimmed := strings.ToLower(strings.TrimSpace(backend))
	if trimmed == "" || trimmed == "auto" {
		return nil
	}
	cleanVal := strings.TrimPrefix(trimmed, "dc")
	if dcNum, err := strconv.Atoi(cleanVal); err == nil {
		if (dcNum >= 1 && dcNum <= 5) || (dcNum >= -5 && dcNum <= -1) || dcNum == 203 || dcNum == -203 {
			return nil
		}
		return fmt.Errorf("direct backend dc index must be between 1 and 5 (or -1 to -5, 203, -203), got %d", dcNum)
	}
	host, portStr, err := net.SplitHostPort(trimmed)
	if err != nil {
		return fmt.Errorf("direct backend must be \"auto\", DC index (1-5), or host:port: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("invalid port")
	}
	if host == "" {
		return errors.New("empty host in direct backend address")
	}
	return nil
}

func validateBackendAddress(backend string, backendType BackendType) error {
	if backendType == BackendDirect {
		if strings.HasPrefix(backend, "unix://") || strings.HasPrefix(backend, "unix:") || strings.HasPrefix(backend, "/") {
			return errors.New("direct backend does not support unix domain sockets")
		}
		return validateDirectBackendAddress(backend)
	}
	if strings.HasPrefix(backend, "unix://") || strings.HasPrefix(backend, "unix:") || strings.HasPrefix(backend, "/") {
		if backendType == BackendMTProxy {
			return errors.New("official mtproxy does not support unix domain sockets; use telemt or loopback tcp")
		}
		path := backend
		if strings.HasPrefix(path, "unix://") {
			path = strings.TrimPrefix(path, "unix://")
		} else if strings.HasPrefix(path, "unix:") {
			path = strings.TrimPrefix(path, "unix:")
		}
		if path == "" {
			return errors.New("empty unix socket path")
		}
		if !filepath.IsAbs(path) {
			return errors.New("unix socket path must be absolute")
		}
		if len(path) > 108 {
			return errors.New("unix socket path exceeds maximum length of 108 characters")
		}
		if strings.ContainsRune(path, 0) {
			return errors.New("unix socket path must not contain null bytes")
		}
		return nil
	}
	return validateLoopbackAddress(backend)
}

func validatePublicUpstream(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if parsed.Scheme != "http" {
		return errors.New("must use http on a numeric loopback address")
	}
	if parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("must contain only scheme, loopback address, and port")
	}
	if err := validateLoopbackAddress(parsed.Host); err != nil {
		return err
	}
	return nil
}

func loadProfiles(path, host, basePath string, limits Limits, defaultBackendType ...BackendType) ([]Profile, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("profiles_file: %w", err)
	}
	extraPermissions := info.Mode().Perm() & 0077
	credentialReadOnly := isSystemdCredential(path) &&
		extraPermissions&0033 == 0
	if runtime.GOOS != "windows" && extraPermissions != 0 && !credentialReadOnly {
		return nil, errors.New("profiles_file must not be readable or writable by group or others")
	}
	input, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range input {
			input[i] = 0
		}
	}()
	var source profileFile
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&source); err != nil {
		return nil, fmt.Errorf("decode profiles: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("decode profiles: trailing data")
	}
	if len(source.Profiles) == 0 || len(source.Profiles) > limits.MaxProfiles {
		return nil, fmt.Errorf("profiles must contain between 1 and %d entries", limits.MaxProfiles)
	}
	names := make(map[string]struct{})
	capabilities := make(map[[sha256.Size]byte]struct{})
	result := make([]Profile, 0, len(source.Profiles))
	for _, input := range source.Profiles {
		if input.Name == "" || len(input.Name) > 64 {
			return nil, errors.New("profile name must contain 1-64 characters")
		}
		if _, exists := names[input.Name]; exists {
			return nil, fmt.Errorf("duplicate profile name %q", input.Name)
		}
		backendType := input.BackendType
		if backendType == "" && len(defaultBackendType) > 0 {
			backendType = defaultBackendType[0]
		}
		backendType = backendType.WithDefault()
		if !backendType.Valid() {
			return nil, fmt.Errorf("profile %q backend_type must be %q, %q or %q", input.Name, BackendMTProxy, BackendTelemt, BackendDirect)
		}
		proxyProtocol := input.BackendProxyProtocol.WithDefault()
		if !proxyProtocol.Valid() {
			return nil, fmt.Errorf("profile %q backend_proxy_protocol must be %q, %q, or %q", input.Name, BackendProxyNone, BackendProxyV1, BackendProxyV2)
		}
		if backendType == BackendMTProxy && proxyProtocol != BackendProxyNone {
			return nil, fmt.Errorf("profile %q: official mtproxy does not support PROXY protocol; use telemt or disable backend_proxy_protocol", input.Name)
		}
		if backendType == BackendDirect && proxyProtocol != BackendProxyNone {
			return nil, fmt.Errorf("profile %q: direct backend does not support PROXY protocol; disable backend_proxy_protocol", input.Name)
		}
		backendAddress := input.Backend
		if backendType == BackendDirect {
			if backendAddress == "" {
				if input.StaticDC != "" {
					backendAddress = input.StaticDC.String()
				} else {
					backendAddress = "auto"
				}
			}
		}
		if err := validateBackendAddress(backendAddress, backendType); err != nil {
			return nil, fmt.Errorf("profile %q backend: %w", input.Name, err)
		}
		carrierMode := input.CarrierMode.WithDefault()
		if !carrierMode.Valid() {
			return nil, fmt.Errorf("profile %q carrier_mode must be https, https-lanes, websocket, websocket-lanes, cdn, cdn-adaptive, cdn-get, cdn-body, or cdn-ws", input.Name)
		}
		if err := validateProfileLimits(input.Limits, limits); err != nil {
			return nil, fmt.Errorf("profile %q: %w", input.Name, err)
		}
		profileLimits := input.Limits.WithDefaults(limits)

		// VHost normalization and validation
		effectiveHost := host
		if input.Hostname != "" {
			normHost := strings.ToLower(strings.TrimSpace(input.Hostname))
			if err := ValidateHostname(normHost); err != nil {
				return nil, fmt.Errorf("profile %q hostname: %w", input.Name, err)
			}
			effectiveHost = normHost
		}

		effectiveBasePath := basePath
		if input.BasePath != nil {
			normBase := strings.TrimSpace(*input.BasePath)
			if err := ValidateBasePath(normBase); err != nil {
				return nil, fmt.Errorf("profile %q base_path: %w", input.Name, err)
			}
			effectiveBasePath = normBase
		}

		if input.PublicDir != "" && input.PublicUpstream != "" {
			return nil, fmt.Errorf("profile %q: public_dir and public_upstream are mutually exclusive", input.Name)
		}
		if input.PublicUpstream != "" {
			if err := validatePublicUpstream(input.PublicUpstream); err != nil {
				return nil, fmt.Errorf("profile %q public_upstream: %w", input.Name, err)
			}
		}

		secret, err := DecodeSecret(input.Secret)
		if err != nil {
			return nil, fmt.Errorf("profile %q: %w", input.Name, err)
		}
		capability := DeriveCapability(effectiveHost, effectiveBasePath, secret)
		for i := range secret {
			secret[i] = 0
		}
		if _, exists := capabilities[capability]; exists {
			return nil, fmt.Errorf("duplicate capability for profile %q", input.Name)
		}
		result = append(result, Profile{
			Name:                 input.Name,
			Secret:               input.Secret,
			Backend:              backendAddress,
			BackendType:          backendType,
			BackendProxyProtocol: proxyProtocol,
			StaticDC:             input.StaticDC,
			PreferIPv6:           input.PreferIPv6,
			CarrierMode:          carrierMode,
			Capability:           capability,
			Limits:               profileLimits,
			Hostname:             effectiveHost,
			BasePath:             effectiveBasePath,
			PublicDir:            input.PublicDir,
			PublicUpstream:       input.PublicUpstream,
			TrustedHostHeader:    input.TrustedHostHeader,
			TrustedIPHeader:      input.TrustedIPHeader,
			DisableIPRateLimit:   input.DisableIPRateLimit,
		})
		names[input.Name] = struct{}{}
		capabilities[capability] = struct{}{}
	}

	// Validate VHost consistency across profiles sharing the same effective Hostname
	type hostSettings struct {
		publicDir         string
		publicUpstream    string
		trustedHostHeader string
		trustedIPHeader   string
	}
	vhostConfigs := make(map[string]hostSettings)
	for _, p := range result {
		current, exists := vhostConfigs[p.Hostname]
		if !exists {
			vhostConfigs[p.Hostname] = hostSettings{
				publicDir:         p.PublicDir,
				publicUpstream:    p.PublicUpstream,
				trustedHostHeader: p.TrustedHostHeader,
				trustedIPHeader:   p.TrustedIPHeader,
			}
			continue
		}
		if p.PublicDir != "" {
			if current.publicDir != "" && current.publicDir != p.PublicDir {
				return nil, fmt.Errorf("conflicting public_dir for hostname %q between profiles: %q vs %q", p.Hostname, current.publicDir, p.PublicDir)
			}
			if current.publicUpstream != "" {
				return nil, fmt.Errorf("conflicting decoy configuration for hostname %q: public_dir %q conflicts with public_upstream %q", p.Hostname, p.PublicDir, current.publicUpstream)
			}
			current.publicDir = p.PublicDir
		}
		if p.PublicUpstream != "" {
			if current.publicUpstream != "" && current.publicUpstream != p.PublicUpstream {
				return nil, fmt.Errorf("conflicting public_upstream for hostname %q between profiles: %q vs %q", p.Hostname, current.publicUpstream, p.PublicUpstream)
			}
			if current.publicDir != "" {
				return nil, fmt.Errorf("conflicting decoy configuration for hostname %q: public_upstream %q conflicts with public_dir %q", p.Hostname, p.PublicUpstream, current.publicDir)
			}
			current.publicUpstream = p.PublicUpstream
		}
		if p.TrustedHostHeader != "" {
			if current.trustedHostHeader != "" && current.trustedHostHeader != p.TrustedHostHeader {
				return nil, fmt.Errorf("conflicting trusted_host_header for hostname %q between profiles: %q vs %q", p.Hostname, current.trustedHostHeader, p.TrustedHostHeader)
			}
			current.trustedHostHeader = p.TrustedHostHeader
		}
		if p.TrustedIPHeader != "" {
			if current.trustedIPHeader != "" && current.trustedIPHeader != p.TrustedIPHeader {
				return nil, fmt.Errorf("conflicting trusted_ip_header for hostname %q between profiles: %q vs %q", p.Hostname, current.trustedIPHeader, p.TrustedIPHeader)
			}
			current.trustedIPHeader = p.TrustedIPHeader
		}
		vhostConfigs[p.Hostname] = current
	}
	return result, nil
}

func validateProfileLimits(value ProfileLimits, global Limits) error {
	checks := []struct {
		name  string
		value int
		limit int
	}{
		{"max_sessions", value.MaxSessions, global.MaxSessionsGlobal},
		{"max_streams", value.MaxStreams, global.MaxStreamsGlobal},
		{"max_backend_dials_in_flight", value.MaxBackendDialsInFlight, global.MaxBackendDialsInFlight},
		{"new_sessions_per_minute", value.NewSessionsPerMinute, global.NewSessionsPerMinute},
		{"new_sessions_burst", value.NewSessionsBurst, global.NewSessionsBurst},
		{"new_streams_per_minute", value.NewStreamsPerMinute, global.NewStreamsPerMinute},
		{"new_streams_burst", value.NewStreamsBurst, global.NewStreamsBurst},
		{"max_streams_per_session", value.MaxStreamsPerSession, global.MaxStreamsPerSession},
		{"max_pending_per_session", value.MaxPendingPerSession, global.MaxPendingPerSession},
	}
	for _, check := range checks {
		if check.value < 0 || check.value > check.limit {
			return fmt.Errorf("%s must be between 0 and %d", check.name, check.limit)
		}
	}
	if value.CDNPollTimeoutSecs < 0 {
		return errors.New("cdn_poll_timeout_secs must be non-negative")
	}
	if value.CDNMaxDownBatchBytes < 0 || value.CDNMaxDownBatchBytes > global.MaxBodyBytes {
		return fmt.Errorf("cdn_max_down_batch_bytes must be between 0 and %d", global.MaxBodyBytes)
	}
	if value.CDNUplinkWindowSize < 0 || value.CDNUplinkWindowSize > 128 {
		return errors.New("cdn_uplink_window_size must be between 0 and 128")
	}
	if value.CDNStreamMaxDurationSecs < 0 || value.CDNStreamMaxDurationSecs > 300 {
		return errors.New("cdn_stream_max_duration_secs must be between 0 and 300")
	}
	if value.CDNStreamHeartbeatSecs < 0 || value.CDNStreamHeartbeatSecs > 30 {
		return errors.New("cdn_stream_heartbeat_secs must be between 0 and 30")
	}
	if value.CDNMaxUnackedBatches < 0 || value.CDNMaxUnackedBatches > 128 {
		return errors.New("cdn_max_unacked_batches must be between 0 and 128")
	}
	resolved := value.WithDefaults(global)
	if resolved.MaxStreamsPerSession > resolved.MaxStreams {
		return errors.New("max_streams_per_session must not exceed max_streams")
	}
	if resolved.MaxBackendDialsInFlight > resolved.MaxStreams {
		return errors.New("max_backend_dials_in_flight must not exceed max_streams")
	}
	return nil
}

func minInt(first, second int) int {
	if first < second {
		return first
	}
	return second
}

func isSystemdCredential(path string) bool {
	directory := os.Getenv("CREDENTIALS_DIRECTORY")
	if directory == "" || !filepath.IsAbs(directory) {
		return false
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	return filepath.Dir(absolute) == filepath.Clean(directory)
}
