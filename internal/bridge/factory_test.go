package bridge

import (
	"strings"
	"testing"
)

func TestFactoryResolveTemplateNamePrecedence(t *testing.T) {
	factory := DefaultFactory()

	// 1. Explicit template override
	resolved := factory.ResolveTemplateName(Options{
		CarrierMode: "https",
		Platform:    "android",
		Template:    "custom.html",
	})
	if resolved != "custom.html" {
		t.Fatalf("expected custom.html, got %q", resolved)
	}

	// 2. CarrierMode resolution
	for _, mode := range []string{"https", "https-lanes", "websocket", "websocket-lanes"} {
		resolved := factory.ResolveTemplateName(Options{
			CarrierMode: mode,
		})
		if !strings.HasPrefix(resolved, strings.ReplaceAll(mode, "-", "_")) && !strings.HasPrefix(resolved, mode) {
			t.Fatalf("expected carrier template for %q, got %q", mode, resolved)
		}
	}

	// 3. Fallback to bridge.html when mode is empty or unrecognized
	resolved = factory.ResolveTemplateName(Options{
		CarrierMode: "unknown-mode",
	})
	if resolved != "bridge.html" {
		t.Fatalf("expected bridge.html fallback, got %q", resolved)
	}
}

func TestFactoryCustomRegistrationAndPlatformResolution(t *testing.T) {
	factory := NewFactory(nil)
	factory.RegisterTemplate("bridge.html", `<!doctype html><html><script nonce="__NONCE__">const c=__CARRIER_MODE__,b=__BOOTSTRAP__,r=__RELAY_BASE__,l=__BATCH_LIMIT__;</script></html>`)
	factory.RegisterTemplate("android_websocket-lanes.html", `<!doctype html><html><!-- android-ws-lanes --><script nonce="__NONCE__">const c=__CARRIER_MODE__,b=__BOOTSTRAP__,r=__RELAY_BASE__,l=__BATCH_LIMIT__;</script></html>`)
	factory.RegisterTemplate("android.html", `<!doctype html><html><!-- android-default --><script nonce="__NONCE__">const c=__CARRIER_MODE__,b=__BOOTSTRAP__,r=__RELAY_BASE__,l=__BATCH_LIMIT__;</script></html>`)

	// Match platform + carrier
	resolved := factory.ResolveTemplateName(Options{
		Platform:    "android",
		CarrierMode: "websocket-lanes",
	})
	if resolved != "android_websocket-lanes.html" {
		t.Fatalf("expected android_websocket-lanes.html, got %q", resolved)
	}

	// Match platform fallback when carrier not specifically defined for platform
	resolved = factory.ResolveTemplateName(Options{
		Platform:    "android",
		CarrierMode: "https",
	})
	if resolved != "android.html" {
		t.Fatalf("expected android.html, got %q", resolved)
	}

	// Render with platform
	page, err := factory.Render(Options{
		Hostname:       "example.com",
		BasePath:       "",
		BootstrapToken: "token123",
		CarrierMode:    "websocket-lanes",
		BatchBytes:     1024 * 1024,
		Platform:       "android",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page.Body), "<!-- android-ws-lanes -->") {
		t.Fatal("rendered page did not use the platform+carrier template")
	}
}

func TestRenderWithOptions(t *testing.T) {
	page, err := RenderWithOptions(Options{
		Hostname:       "example.com",
		BasePath:       "proxy",
		CarrierMode:    "https",
		BatchBytes:     2 * 1024 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page.Body), `carrierMode="https"`) {
		t.Fatal("RenderWithOptions did not embed carrierMode")
	}
	if !strings.Contains(string(page.Body), `relayBase="https://example.com/proxy/"`) {
		t.Fatal("RenderWithOptions did not embed relayBase")
	}
}

func TestFactoryErrorHandling(t *testing.T) {
	factory := DefaultFactory()

	// Invalid hostname
	if _, err := factory.Render(Options{
		Hostname:       "bad hostname",
		BasePath:       "",
		BootstrapToken: "tok",
		CarrierMode:    "https",
		BatchBytes:     1024,
	}); err == nil {
		t.Fatal("expected error on invalid hostname")
	}

	// Invalid basePath
	if _, err := factory.Render(Options{
		Hostname:       "example.com",
		BasePath:       "//bad",
		BootstrapToken: "tok",
		CarrierMode:    "https",
		BatchBytes:     1024,
	}); err == nil {
		t.Fatal("expected error on invalid basePath")
	}

	// Invalid batch size
	if _, err := factory.Render(Options{
		Hostname:       "example.com",
		BasePath:       "",
		BootstrapToken: "tok",
		CarrierMode:    "https",
		BatchBytes:     0,
	}); err == nil {
		t.Fatal("expected error on zero batch size")
	}

	// Invalid carrier mode
	if _, err := factory.Render(Options{
		Hostname:       "example.com",
		BasePath:       "",
		BootstrapToken: "tok",
		CarrierMode:    "invalid-carrier",
		BatchBytes:     1024,
	}); err == nil {
		t.Fatal("expected error on invalid carrier mode")
	}

	// Non-existent template in RenderTemplate
	if _, err := factory.RenderTemplate("non_existent.html", Options{
		Hostname:       "example.com",
		BasePath:       "",
		BootstrapToken: "tok",
		CarrierMode:    "https",
		BatchBytes:     1024,
	}); err == nil {
		t.Fatal("expected error on non-existent template")
	}
}
