package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCapabilityVectors(t *testing.T) {
	tests := []struct {
		secret string
		want   string
	}{
		{"000102030405060708090a0b0c0d0e0f", "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk"},
		{"dd000102030405060708090a0b0c0d0e0f", "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA"},
	}
	for _, test := range tests {
		secret, err := DecodeSecret(test.secret)
		if err != nil {
			t.Fatal(err)
		}
		got := CapabilityString(DeriveCapability("proxy.example.com", "", secret))
		if got != test.want {
			t.Fatalf("got %q, want %q", got, test.want)
		}
	}
}

func TestHostnameValidation(t *testing.T) {
	for _, valid := range []string{
		"site.example",
		"xn--bcher-kva.example",
		"a.b.example",
		strings.Repeat("a", 63) + ".example",
	} {
		if err := ValidateHostname(valid); err != nil {
			t.Errorf("%q: %v", valid, err)
		}
	}
	for _, invalid := range []string{
		"localhost",
		"127.0.0.1",
		"[::1]",
		"HTTPS://site.example",
		"Site.example",
		"bücher.example",
		"site.example.",
		"site.example:443",
		"site/example",
		"site\\example",
		"site..example",
		"-site.example",
		"site-.example",
		"site_example.com",
		strings.Repeat("a", 64) + ".example",
		strings.Repeat("a.", 127) + "aa",
	} {
		if err := ValidateHostname(invalid); err == nil {
			t.Errorf("accepted %q", invalid)
		}
	}
}

func TestPublicSourceValidation(t *testing.T) {
	value := Defaults()
	value.PublicHostname = "proxy.example.com"
	value.ProfilesFile = "profiles.json"
	if err := value.validate(); err == nil {
		t.Fatal("configuration without a public source was accepted")
	}
	for _, upstream := range []string{
		"http://127.0.0.1:3000",
		"http://[::1]:3000",
	} {
		value.PublicUpstream = upstream
		if err := value.validate(); err != nil {
			t.Fatalf("valid public upstream %q was rejected: %v", upstream, err)
		}
	}
	for _, upstream := range []string{
		"https://127.0.0.1:3000",
		"http://localhost:3000",
		"http://192.0.2.1:3000",
		"http://127.0.0.1",
		"http://127.0.0.1:3000/path",
		"http://user@127.0.0.1:3000",
	} {
		value.PublicUpstream = upstream
		if err := value.validate(); err == nil {
			t.Fatalf("invalid public upstream %q was accepted", upstream)
		}
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "index.html"), []byte("site"), 0600); err != nil {
		t.Fatal(err)
	}
	value.PublicDir = directory
	value.PublicUpstream = "http://127.0.0.1:3000"
	if err := value.validate(); err == nil {
		t.Fatal("configuration with both public sources was accepted")
	}
}

func TestPlainSecretMayBeginWithEE(t *testing.T) {
	secret, err := DecodeSecret("ee0102030405060708090a0b0c0d0e0f")
	if err != nil || len(secret) != 16 || secret[0] != 0xee {
		t.Fatalf("valid plain secret was rejected: %v", err)
	}
}

func TestLoadAppliesDefaultsAndRelativePaths(t *testing.T) {
	directory := t.TempDir()
	public := filepath.Join(directory, "public")
	if err := os.Mkdir(public, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(public, "index.html"), []byte("site"), 0600); err != nil {
		t.Fatal(err)
	}
	profiles := `{"profiles":[{"name":"default","secret":"000102030405060708090a0b0c0d0e0f","backend":"127.0.0.1:2398","carrier_mode":"https-lanes"}]}`
	if err := os.WriteFile(filepath.Join(directory, "profiles.json"), []byte(profiles), 0600); err != nil {
		t.Fatal(err)
	}
	server := `{"public_hostname":"proxy.example.com","public_dir":"public","profiles_file":"profiles.json"}`
	path := filepath.Join(directory, "config.json")
	if err := os.WriteFile(path, []byte(server), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.TokenKeyFile != filepath.Join(directory, "token.key") || loaded.StaticRoutes != "legacy" || loaded.PublicDir != public || len(loaded.Profiles) != 1 || loaded.Limits.MaxBodyBytes != 2*1024*1024 || loaded.Profiles[0].CarrierMode != CarrierHTTPSLanes {
		t.Fatalf("unexpected loaded configuration: %#v", loaded)
	}
	profileLimits := loaded.Profiles[0].Limits
	if profileLimits.MaxSessions != loaded.Limits.MaxSessionsGlobal ||
		profileLimits.MaxStreams != loaded.Limits.MaxStreamsGlobal ||
		profileLimits.MaxBackendDialsInFlight != loaded.Limits.MaxBackendDialsInFlight ||
		profileLimits.NewSessionsPerMinute != loaded.Limits.NewSessionsPerMinute ||
		profileLimits.NewStreamsPerMinute != loaded.Limits.NewStreamsPerMinute {
		t.Fatalf("profile limits did not inherit global values: %#v", profileLimits)
	}
}

func TestProfileCarrierModeDefaultsAndValidation(t *testing.T) {
	directory := t.TempDir()
	public := filepath.Join(directory, "public")
	if err := os.Mkdir(public, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(public, "index.html"), []byte("site"), 0600); err != nil {
		t.Fatal(err)
	}
	profilesPath := filepath.Join(directory, "profiles.json")
	writeProfiles := func(carrier string) {
		value := `{"profiles":[{"name":"default","secret":"000102030405060708090a0b0c0d0e0f","backend":"127.0.0.1:2398"` + carrier + `}]}`
		if err := os.WriteFile(profilesPath, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	server := `{"public_hostname":"proxy.example.com","public_dir":"public","profiles_file":"profiles.json"}`
	configPath := filepath.Join(directory, "config.json")
	if err := os.WriteFile(configPath, []byte(server), 0600); err != nil {
		t.Fatal(err)
	}
	writeProfiles("")
	loaded, err := Load(configPath)
	if err != nil || loaded.Profiles[0].CarrierMode != CarrierHTTPS {
		t.Fatalf("omitted carrier mode did not default to HTTPS: %#v %v", loaded.Profiles, err)
	}
	for _, carrier := range []CarrierMode{
		CarrierHTTPS,
		CarrierHTTPSLanes,
		CarrierWebSocket,
		CarrierWebSocketLanes,
		CarrierCDN,
		CarrierCDNAdaptive,
		CarrierCDNGet,
		CarrierCDNBody,
		CarrierCDNWS,
	} {
		writeProfiles(`,"carrier_mode":"` + string(carrier) + `"`)
		loaded, err := Load(configPath)
		if err != nil || loaded.Profiles[0].CarrierMode != carrier {
			t.Fatalf("carrier mode %q was not loaded: %#v %v", carrier, loaded.Profiles, err)
		}
	}
	writeProfiles(`,"carrier_mode":"unknown"`)
	if _, err := Load(configPath); err == nil {
		t.Fatal("invalid carrier mode was accepted")
	}
}

func TestProfileStreamDefaultsRespectProfileCeiling(t *testing.T) {
	global := Defaults().Limits
	resolved := (ProfileLimits{MaxStreams: 32}).WithDefaults(global)
	if resolved.MaxStreamsPerSession != 32 ||
		resolved.MaxBackendDialsInFlight != 32 ||
		resolved.MaxSessions != global.MaxSessionsGlobal ||
		resolved.NewStreamsPerMinute != global.NewStreamsPerMinute {
		t.Fatalf("unexpected resolved profile limits: %#v", resolved)
	}
}

func TestProfileLimitsCannotExceedGlobalCeilings(t *testing.T) {
	global := Defaults().Limits
	if err := validateProfileLimits(ProfileLimits{
		MaxStreams: global.MaxStreamsGlobal + 1,
	}, global); err == nil {
		t.Fatal("profile max_streams exceeded the global ceiling")
	}
	if err := validateProfileLimits(ProfileLimits{
		MaxStreams:           16,
		MaxStreamsPerSession: 17,
	}, global); err == nil {
		t.Fatal("per-session stream limit exceeded the profile stream ceiling")
	}
}

func TestLoadAcceptsSystemdCredentialReadPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping POSIX permission test on Windows")
	}
	directory := t.TempDir()
	public := filepath.Join(directory, "public")
	if err := os.Mkdir(public, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(public, "index.html"), []byte("site"), 0600); err != nil {
		t.Fatal(err)
	}
	credentials := filepath.Join(directory, "credentials")
	if err := os.Mkdir(credentials, 0700); err != nil {
		t.Fatal(err)
	}
	profiles := filepath.Join(credentials, "profiles.json")
	content := `{"profiles":[{"name":"default","secret":"000102030405060708090a0b0c0d0e0f","backend":"127.0.0.1:2398"}]}`
	if err := os.WriteFile(profiles, []byte(content), 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(profiles, 0444); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", credentials)
	server := `{"public_hostname":"proxy.example.com","public_dir":"public","profiles_file":"credentials/profiles.json"}`
	path := filepath.Join(directory, "config.json")
	if err := os.WriteFile(path, []byte(server), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if _, err := Load(path); err == nil {
		t.Fatal("group/other-readable profiles file outside a credential directory was accepted")
	}
}

func TestCarrierBatchMustFitDesktopLoopbackCap(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "index.html"), []byte("index"), 0600); err != nil {
		t.Fatal(err)
	}
	profiles := filepath.Join(directory, "profiles.json")
	if err := os.WriteFile(profiles, []byte(`{"profiles":[{"name":"a","secret":"000102030405060708090a0b0c0d0e0f","backend":"127.0.0.1:443"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	write := func(batch, body int) string {
		path := filepath.Join(directory, "config.json")
		cfgData, err := json.Marshal(map[string]any{
			"public_hostname": "proxy.example.com",
			"public_dir":      directory,
			"profiles_file":   profiles,
			"limits": map[string]any{
				"carrier_batch_bytes": batch,
				"max_body_bytes":      body,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, cfgData, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if _, err := Load(write(3*1024*1024, 4*1024*1024)); err == nil {
		t.Fatal("accepted carrier_batch_bytes above 2 MiB")
	}
	if _, err := Load(write(2*1024*1024, 4*1024*1024)); err != nil {
		t.Fatalf("rejected a 2 MiB carrier batch: %v", err)
	}
}

func TestDefaultReconnectGraceIsShort(t *testing.T) {
	if Defaults().Timeouts.ReconnectGrace.Value() != 2*time.Minute {
		t.Fatal("reconnect_grace default is not 2m")
	}
}

func TestTelemtBackendConfiguration(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "index.html"), []byte("index"), 0600); err != nil {
		t.Fatal(err)
	}

	writeConfig := func(profilesContent string, globalBackendType string, globalPP string) (Config, error) {
		profPath := filepath.Join(directory, "profiles.json")
		if err := os.WriteFile(profPath, []byte(profilesContent), 0600); err != nil {
			t.Fatal(err)
		}
		cfgMap := map[string]any{
			"public_hostname": "proxy.example.com",
			"public_dir":      directory,
			"profiles_file":   profPath,
		}
		if globalBackendType != "" {
			cfgMap["backend_type"] = globalBackendType
		}
		if globalPP != "" {
			cfgMap["backend_proxy_protocol"] = globalPP
		}
		cfgBytes, err := json.Marshal(cfgMap)
		if err != nil {
			t.Fatal(err)
		}
		cfgPath := filepath.Join(directory, "config.json")
		if err := os.WriteFile(cfgPath, cfgBytes, 0600); err != nil {
			t.Fatal(err)
		}
		return Load(cfgPath)
	}

	// 1. Valid telemt profile with TCP
	validTelemt := `{"profiles":[{"name":"telemt1","secret":"000102030405060708090a0b0c0d0e0f","backend":"127.0.0.1:8443","backend_type":"telemt","backend_proxy_protocol":"v2"}]}`
	loaded, err := writeConfig(validTelemt, "", "")
	if err != nil {
		t.Fatalf("valid telemt config was rejected: %v", err)
	}
	if loaded.Profiles[0].BackendType != BackendTelemt || loaded.Profiles[0].BackendProxyProtocol != BackendProxyV2 {
		t.Fatalf("unexpected telemt profile settings: %#v", loaded.Profiles[0])
	}

	// 2. Valid telemt profile with unix socket
	sockPath := "/run/telemt/telemt.sock"
	if runtime.GOOS == "windows" {
		sockPath = "C:/run/telemt/telemt.sock"
	}
	validUnix := `{"profiles":[{"name":"telemt_unix","secret":"000102030405060708090a0b0c0d0e0f","backend":"unix:` + sockPath + `","backend_type":"telemt"}]}`
	loaded, err = writeConfig(validUnix, "", "")
	if err != nil {
		t.Fatalf("valid telemt unix socket was rejected: %v", err)
	}
	netw, addr := loaded.Profiles[0].BackendNetworkAndAddress()
	if netw != "unix" || addr != sockPath {
		t.Fatalf("unexpected network/addr: %s, %s", netw, addr)
	}

	// 3. Official mtproxy with unix socket rejected
	invalidUnixMT := `{"profiles":[{"name":"mt_unix","secret":"000102030405060708090a0b0c0d0e0f","backend":"unix:` + sockPath + `","backend_type":"mtproxy"}]}`
	if _, err := writeConfig(invalidUnixMT, "", ""); err == nil {
		t.Fatal("accepted unix socket for official mtproxy")
	}

	// 4. Official mtproxy with PROXY protocol rejected
	invalidPPMT := `{"profiles":[{"name":"mt_pp","secret":"000102030405060708090a0b0c0d0e0f","backend":"127.0.0.1:2398","backend_type":"mtproxy","backend_proxy_protocol":"v1"}]}`
	if _, err := writeConfig(invalidPPMT, "", ""); err == nil {
		t.Fatal("accepted PROXY protocol for official mtproxy")
	}

	// 5. Invalid backend_type rejected
	invalidType := `{"profiles":[{"name":"bad","secret":"000102030405060708090a0b0c0d0e0f","backend":"127.0.0.1:2398","backend_type":"unknown"}]}`
	if _, err := writeConfig(invalidType, "", ""); err == nil {
		t.Fatal("accepted unknown backend_type")
	}
}

func TestDirectBackendConfiguration(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "index.html"), []byte("index"), 0600); err != nil {
		t.Fatal(err)
	}

	writeConfig := func(profilesContent string, globalBackendType string, globalPP string) (Config, error) {
		profPath := filepath.Join(directory, "profiles.json")
		if err := os.WriteFile(profPath, []byte(profilesContent), 0600); err != nil {
			t.Fatal(err)
		}
		cfgMap := map[string]any{
			"public_hostname": "proxy.example.com",
			"public_dir":      directory,
			"profiles_file":   profPath,
		}
		if globalBackendType != "" {
			cfgMap["backend_type"] = globalBackendType
		}
		if globalPP != "" {
			cfgMap["backend_proxy_protocol"] = globalPP
		}
		cfgBytes, err := json.Marshal(cfgMap)
		if err != nil {
			t.Fatal(err)
		}
		cfgPath := filepath.Join(directory, "config.json")
		if err := os.WriteFile(cfgPath, cfgBytes, 0600); err != nil {
			t.Fatal(err)
		}
		return Load(cfgPath)
	}

	// 1. Valid direct profile (auto DC)
	autoDirect := `{"profiles":[{"name":"direct_auto","secret":"000102030405060708090a0b0c0d0e0f","backend_type":"direct"}]}`
	loaded, err := writeConfig(autoDirect, "", "")
	if err != nil {
		t.Fatalf("valid direct auto config rejected: %v", err)
	}
	if loaded.Profiles[0].BackendType != BackendDirect || loaded.Profiles[0].Backend != "auto" {
		t.Fatalf("unexpected direct profile: %#v", loaded.Profiles[0])
	}

	// 2. Valid direct profile with static_dc integer
	staticDirectInt := `{"profiles":[{"name":"direct_static","secret":"000102030405060708090a0b0c0d0e0f","backend_type":"direct","static_dc":2}]}`
	loaded, err = writeConfig(staticDirectInt, "", "")
	if err != nil {
		t.Fatalf("valid direct static_dc int rejected: %v", err)
	}
	if loaded.Profiles[0].BackendType != BackendDirect || loaded.Profiles[0].StaticDC != "2" || loaded.Profiles[0].Backend != "2" {
		t.Fatalf("unexpected static direct profile: %#v", loaded.Profiles[0])
	}
	// 2b. Valid direct profile with static_dc 203 (CDN) and negative -2 (media)
	staticCDN := `{"profiles":[{"name":"direct_cdn","secret":"000102030405060708090a0b0c0d0e0f","backend_type":"direct","static_dc":203}]}`
	loaded, err = writeConfig(staticCDN, "", "")
	if err != nil {
		t.Fatalf("valid direct static_dc 203 rejected: %v", err)
	}
	if loaded.Profiles[0].StaticDC != "203" {
		t.Fatalf("unexpected static_dc: %s", loaded.Profiles[0].StaticDC)
	}

	// 3. Valid direct profile with explicit IP:port backend
	explicitAddr := `{"profiles":[{"name":"direct_addr","secret":"000102030405060708090a0b0c0d0e0f","backend_type":"direct","backend":"149.154.167.51:443"}]}`
	loaded, err = writeConfig(explicitAddr, "", "")
	if err != nil {
		t.Fatalf("valid direct explicit addr rejected: %v", err)
	}
	if loaded.Profiles[0].Backend != "149.154.167.51:443" {
		t.Fatalf("unexpected backend address: %s", loaded.Profiles[0].Backend)
	}

	// 4. Direct backend with PROXY protocol rejected
	directWithPP := `{"profiles":[{"name":"direct_pp","secret":"000102030405060708090a0b0c0d0e0f","backend_type":"direct","backend_proxy_protocol":"v1"}]}`
	if _, err := writeConfig(directWithPP, "", ""); err == nil {
		t.Fatal("accepted PROXY protocol for direct backend")
	}

	// 5. Direct backend with unix socket rejected
	directWithUnix := `{"profiles":[{"name":"direct_unix","secret":"000102030405060708090a0b0c0d0e0f","backend_type":"direct","backend":"unix:/run/tg.sock"}]}`
	if _, err := writeConfig(directWithUnix, "", ""); err == nil {
		t.Fatal("accepted unix socket for direct backend")
	}
}

func TestLoggingConfiguration(t *testing.T) {
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "token.key")
	if err := os.WriteFile(tokenPath, []byte("0123456789abcdef0123456789abcdef"), 0600); err != nil {
		t.Fatal(err)
	}
	profilesPath := filepath.Join(directory, "profiles.json")
	if err := os.WriteFile(profilesPath, []byte(`{"profiles":[{"name":"default","secret":"000102030405060708090a0b0c0d0e0f","backend":"127.0.0.1:443"}]}`), 0600); err != nil {
		t.Fatal(err)
	}

	writeMainConfig := func(loggingJSON string) error {
		cfgJSON := `{
			"public_hostname": "proxy.example.com",
			"public_upstream": "http://127.0.0.1:3000",
			"token_key_file": "` + filepath.ToSlash(tokenPath) + `",
			"profiles_file": "` + filepath.ToSlash(profilesPath) + `",
			"logging": ` + loggingJSON + `
		}`
		configPath := filepath.Join(directory, "config.json")
		if err := os.WriteFile(configPath, []byte(cfgJSON), 0600); err != nil {
			return err
		}
		_, err := Load(configPath)
		return err
	}

	// Valid logging config
	validLogging := `{"enabled": true, "level": "debug", "format": "json", "output": "both", "dir": "custom_logs", "max_days": 14}`
	if err := writeMainConfig(validLogging); err != nil {
		t.Fatalf("valid logging config rejected: %v", err)
	}

	// Invalid level
	invalidLevel := `{"enabled": true, "level": "verbose", "format": "json", "output": "stdout"}`
	if err := writeMainConfig(invalidLevel); err == nil {
		t.Fatal("accepted invalid log level")
	}

	// Invalid format
	invalidFormat := `{"enabled": true, "level": "info", "format": "xml", "output": "stdout"}`
	if err := writeMainConfig(invalidFormat); err == nil {
		t.Fatal("accepted invalid log format")
	}

	// Invalid output
	invalidOutput := `{"enabled": true, "level": "info", "format": "text", "output": "syslog"}`
	if err := writeMainConfig(invalidOutput); err == nil {
		t.Fatal("accepted invalid log output")
	}

	// Negative max_days
	negativeDays := `{"enabled": true, "output": "file", "max_days": -5}`
	if err := writeMainConfig(negativeDays); err == nil {
		t.Fatal("accepted negative max_days")
	}
}
