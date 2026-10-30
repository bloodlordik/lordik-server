package bridge

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"sync"

	"github.com/telegramdesktop/tproxy-server/internal/config"
	"github.com/telegramdesktop/tproxy-server/internal/logger"
)

//go:embed templates/*.html
var embeddedTemplatesFS embed.FS

// Options defines parameters for rendering a bridge Page.
type Options struct {
	Hostname       string
	BasePath       string
	BootstrapToken string
	CarrierMode    string
	BatchBytes     int
	Platform       string // Optional platform: e.g. "android", "ios", "desktop"
	Template       string // Optional explicit template name override
	BuildID        string // Optional build ID for CDN routing
}
// Factory manages bridge page templates and generates Page instances based on carrier mode and platform conditions.
type Factory struct {
	mu        sync.RWMutex
	fs        fs.FS
	templates map[string]string
}

var (
	defaultFactoryOnce sync.Once
	defaultFactoryInst *Factory
)

// DefaultFactory returns the singleton bridge page factory using embedded templates.
func DefaultFactory() *Factory {
	defaultFactoryOnce.Do(func() {
		sub, err := fs.Sub(embeddedTemplatesFS, "templates")
		if err != nil {
			panic(fmt.Sprintf("failed to initialize embedded templates: %v", err))
		}
		defaultFactoryInst = NewFactory(sub)
	})
	return defaultFactoryInst
}

// NewFactory creates a new Factory backed by the provided filesystem.
func NewFactory(templateFS fs.FS) *Factory {
	return &Factory{
		fs:        templateFS,
		templates: make(map[string]string),
	}
}

// RegisterTemplate registers or overrides an in-memory template.
func (f *Factory) RegisterTemplate(name string, content string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.templates[name] = content
}

// HasTemplate checks whether a template with the given name exists in the factory.
func (f *Factory) HasTemplate(name string) bool {
	f.mu.RLock()
	if _, ok := f.templates[name]; ok {
		f.mu.RUnlock()
		return true
	}
	f.mu.RUnlock()

	if f.fs != nil {
		if file, err := f.fs.Open(name); err == nil {
			_ = file.Close()
			return true
		}
	}
	return false
}

// GetTemplate retrieves template content by name from in-memory overrides or filesystem.
func (f *Factory) GetTemplate(name string) (string, error) {
	f.mu.RLock()
	if content, ok := f.templates[name]; ok {
		f.mu.RUnlock()
		return content, nil
	}
	f.mu.RUnlock()

	if f.fs != nil {
		data, err := fs.ReadFile(f.fs, name)
		if err == nil {
			return string(data), nil
		}
	}
	return "", fmt.Errorf("template %q not found", name)
}

// ResolveTemplateName selects the most specific template for the given options.
// Resolution order:
// 1. Explicit template override in opts.Template
// 2. Platform + CarrierMode (e.g. "android_websocket-lanes.html", "android_websocket_lanes.html")
// 3. Platform (e.g. "android.html")
// 4. CarrierMode (e.g. "https.html", "https_lanes.html", "https-lanes.html")
// 5. Fallback: "bridge.html"
func (f *Factory) ResolveTemplateName(opts Options) string {
	if opts.Template != "" {
		return opts.Template
	}

	platform := strings.ToLower(strings.TrimSpace(opts.Platform))
	mode := strings.ToLower(strings.TrimSpace(opts.CarrierMode))
	modeUnder := strings.ReplaceAll(mode, "-", "_")
	modeHyphen := strings.ReplaceAll(mode, "_", "-")

	if platform != "" && mode != "" {
		candidates := []string{
			platform + "_" + mode + ".html",
			platform + "_" + modeUnder + ".html",
			platform + "_" + modeHyphen + ".html",
			platform + "-" + mode + ".html",
			platform + "/" + mode + ".html",
		}
		for _, candidate := range candidates {
			if f.HasTemplate(candidate) {
				return candidate
			}
		}
	}

	if platform != "" {
		candidate := platform + ".html"
		if f.HasTemplate(candidate) {
			return candidate
		}
	}

	if mode != "" {
		candidates := []string{
			mode + ".html",
			modeUnder + ".html",
			modeHyphen + ".html",
		}
		if strings.HasPrefix(mode, "cdn") {
			candidates = append(candidates, "cdn.html")
		}
		if strings.HasPrefix(mode, "yc") {
			candidates = append(candidates, "yc_ws.html")
		}
		for _, candidate := range candidates {
			if f.HasTemplate(candidate) {
				return candidate
			}
		}
	}

	return "bridge.html"
}

// Render generates a bridge Page using the most appropriate template resolved for opts.
func (f *Factory) Render(opts Options) (Page, error) {
	if err := config.ValidateHostname(opts.Hostname); err != nil {
		return Page{}, err
	}
	if err := config.ValidateBasePath(opts.BasePath); err != nil {
		return Page{}, err
	}
	if opts.BatchBytes <= 0 || opts.BatchBytes > config.MaxCarrierBatchBytes {
		return Page{}, errors.New("carrier batch size out of range")
	}
	if !config.CarrierMode(opts.CarrierMode).Valid() {
		return Page{}, errors.New("invalid carrier mode")
	}

	templateName := f.ResolveTemplateName(opts)
	return f.RenderTemplate(templateName, opts)
}

// RenderTemplate generates a bridge Page using an explicitly named template.
func (f *Factory) RenderTemplate(templateName string, opts Options) (Page, error) {
	if err := config.ValidateHostname(opts.Hostname); err != nil {
		return Page{}, err
	}
	if err := config.ValidateBasePath(opts.BasePath); err != nil {
		return Page{}, err
	}
	if opts.BatchBytes <= 0 || opts.BatchBytes > config.MaxCarrierBatchBytes {
		return Page{}, errors.New("carrier batch size out of range")
	}
	if !config.CarrierMode(opts.CarrierMode).Valid() {
		return Page{}, errors.New("invalid carrier mode")
	}

	content, err := f.GetTemplate(templateName)
	if err != nil {
		return Page{}, err
	}
	logger.Debug("rendering bridge template", "template", templateName, "carrier", opts.CarrierMode, "platform", opts.Platform)


	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return Page{}, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	baseJSON, _ := json.Marshal("https://" + opts.Hostname + config.Base(opts.BasePath))
	tokenJSON, _ := json.Marshal(opts.BootstrapToken)
	carrierJSON, _ := json.Marshal(opts.CarrierMode)

	body := strings.ReplaceAll(content, "__NONCE__", nonce)
	body = strings.ReplaceAll(body, "__RELAY_BASE__", string(baseJSON))
	body = strings.ReplaceAll(body, "__BOOTSTRAP__", string(tokenJSON))
	body = strings.ReplaceAll(body, "__CARRIER_MODE__", string(carrierJSON))
	body = strings.ReplaceAll(body, "__BATCH_LIMIT__", strconv.Itoa(opts.BatchBytes))
	buildID := opts.BuildID
	if buildID == "" {
		buildID = "k9x2m4p1"
	}
	body = strings.ReplaceAll(body, "__BUILD_ID__", buildID)

	if strings.Contains(body, "__NONCE__") ||
		strings.Contains(body, "__RELAY_BASE__") ||
		strings.Contains(body, "__BOOTSTRAP__") ||
		strings.Contains(body, "__CARRIER_MODE__") ||
		strings.Contains(body, "__BATCH_LIMIT__") ||
		strings.Contains(body, "__BUILD_ID__") {
		return Page{}, errors.New("bridge template replacement failed")
	}

	return Page{
		Body:  []byte(body),
		Nonce: nonce,
		CSP: strings.Join([]string{
			"default-src 'none'",
			"base-uri 'none'",
			"child-src 'none'",
			"connect-src 'self' wss://" + opts.Hostname,
			"font-src 'none'",
			"form-action 'none'",
			"frame-ancestors http://127.0.0.1:*",
			"frame-src 'none'",
			"img-src 'none'",
			"manifest-src 'none'",
			"media-src 'none'",
			"object-src 'none'",
			"script-src 'nonce-" + nonce + "'",
			"style-src 'none'",
			"worker-src 'none'",
			"sandbox allow-same-origin allow-scripts",
		}, "; "),
	}, nil
}
