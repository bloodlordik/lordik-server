package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatServerParam(t *testing.T) {
	tests := []struct {
		host     string
		basePath string
		want     string
	}{
		{"proxy.example.com", "", "proxy.example.com"},
		{"proxy.example.com", "phcf2vfe7zgbrslg", "proxy.example.com%2Fphcf2vfe7zgbrslg"},
		{"proxy.example.com", "/phcf2vfe7zgbrslg/", "proxy.example.com%2Fphcf2vfe7zgbrslg"},
		{"proxy.example.com", "a/b/c", "proxy.example.com%2Fa%2Fb%2Fc"},
		{"  proxy.example.com  ", "  sub  ", "proxy.example.com%2Fsub"},
	}

	for _, tt := range tests {
		got := FormatServerParam(tt.host, tt.basePath)
		if got != tt.want {
			t.Errorf("FormatServerParam(%q, %q) = %q; want %q", tt.host, tt.basePath, got, tt.want)
		}
	}
}

func TestDeriveLinkSecret(t *testing.T) {
	// Vector from README.md line 354:
	// 8561944064fc730cbfa4473562d8ec59 -> cIVhlEBk_HMMv6RHNWLY7Fk under base path
	secret := "8561944064fc730cbfa4473562d8ec59"

	// Root deployment: unchanged hex
	rootSecret, err := DeriveLinkSecret(secret, "")
	if err != nil {
		t.Fatalf("unexpected error for root secret: %v", err)
	}
	if rootSecret != secret {
		t.Errorf("root secret = %q; want %q", rootSecret, secret)
	}

	// Base path deployment: derived 0x70 marked base64url
	baseSecret, err := DeriveLinkSecret(secret, "phcf2vfe7zgbrslg")
	if err != nil {
		t.Fatalf("unexpected error for base path secret: %v", err)
	}
	wantDerived := "cIVhlEBk_HMMv6RHNWLY7Fk"
	if baseSecret != wantDerived {
		t.Errorf("derived secret = %q; want %q", baseSecret, wantDerived)
	}

	// Invalid hex secret error
	if _, err := DeriveLinkSecret("not-hex", "base"); err == nil {
		t.Error("expected error for invalid hex secret, got nil")
	}
}

func TestBuildLinks(t *testing.T) {
	serverParam := "proxy.example.com%2Fsub"
	port := 443
	secret := "cIVhlEBk_HMMv6RHNWLY7Fk"

	tgProxy := BuildTGProxyLink(serverParam, port, secret)
	wantTG := "tg://proxy?server=proxy.example.com%2Fsub&port=443&secret=cIVhlEBk_HMMv6RHNWLY7Fk"
	if tgProxy != wantTG {
		t.Errorf("BuildTGProxyLink = %q; want %q", tgProxy, wantTG)
	}

	tgWeb := BuildTGWebProxyLink(serverParam, secret)
	wantWeb := "tg://webproxy?server=proxy.example.com%2Fsub&secret=cIVhlEBk_HMMv6RHNWLY7Fk"
	if tgWeb != wantWeb {
		t.Errorf("BuildTGWebProxyLink = %q; want %q", tgWeb, wantWeb)
	}

	httpsWeb := BuildHTTPSWebProxyLink(serverParam, secret)
	wantHTTPS := "https://t.me/webproxy?server=proxy.example.com%2Fsub&secret=cIVhlEBk_HMMv6RHNWLY7Fk"
	if httpsWeb != wantHTTPS {
		t.Errorf("BuildHTTPSWebProxyLink = %q; want %q", httpsWeb, wantHTTPS)
	}
}

func TestRunLink(t *testing.T) {
	// Help flag
	var stdout, stderr bytes.Buffer
	code := RunLink([]string{"-h"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("RunLink -h exit code = %d; want 0", code)
	}
	if !strings.Contains(stdout.String(), "Usage of link:") {
		t.Errorf("RunLink -h output missing usage: %s", stdout.String())
	}

	// Explicit parameters without config file
	stdout.Reset()
	stderr.Reset()
	code = RunLink([]string{
		"-host", "example.com",
		"-port", "8443",
		"-secret", "000102030405060708090a0b0c0d0e0f",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("RunLink exit code = %d; stderr: %s", code, stderr.String())
	}
	wantLink := "tg://proxy?server=example.com&port=8443&secret=000102030405060708090a0b0c0d0e0f"
	if strings.TrimSpace(stdout.String()) != wantLink {
		t.Errorf("RunLink output = %q; want %q", strings.TrimSpace(stdout.String()), wantLink)
	}

	// With base path
	stdout.Reset()
	stderr.Reset()
	code = RunLink([]string{
		"-host", "proxy.example.com",
		"-base-path", "phcf2vfe7zgbrslg",
		"-secret", "8561944064fc730cbfa4473562d8ec59",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("RunLink with base-path exit code = %d; stderr: %s", code, stderr.String())
	}
	wantBaseLink := "tg://proxy?server=proxy.example.com%2Fphcf2vfe7zgbrslg&port=443&secret=cIVhlEBk_HMMv6RHNWLY7Fk"
	if strings.TrimSpace(stdout.String()) != wantBaseLink {
		t.Errorf("RunLink with base-path output = %q; want %q", strings.TrimSpace(stdout.String()), wantBaseLink)
	}

	// Type "all"
	stdout.Reset()
	stderr.Reset()
	code = RunLink([]string{
		"-host", "example.com",
		"-secret", "000102030405060708090a0b0c0d0e0f",
		"-type", "all",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("RunLink -type all exit code = %d; stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "tg://proxy:") || !strings.Contains(out, "tg://webproxy:") || !strings.Contains(out, "https:") {
		t.Errorf("RunLink -type all missing links: %s", out)
	}
}

func TestReadLastLinesFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	// Write 10 lines
	var content strings.Builder
	for i := 1; i <= 10; i++ {
		fmt.Fprintf(&content, "line %d\n", i)
	}
	if err := os.WriteFile(logFile, []byte(content.String()), 0600); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	// Read last 3 lines
	lines, err := ReadLastLinesFromFile(logFile, 3)
	if err != nil {
		t.Fatalf("ReadLastLinesFromFile error: %v", err)
	}
	if len(lines) != 3 {
		t.Fatalf("got %d lines; want 3", len(lines))
	}
	if lines[0] != "line 8" || lines[1] != "line 9" || lines[2] != "line 10" {
		t.Errorf("unexpected lines: %v", lines)
	}

	// Request more lines than in file
	linesAll, err := ReadLastLinesFromFile(logFile, 20)
	if err != nil {
		t.Fatalf("ReadLastLinesFromFile error: %v", err)
	}
	if len(linesAll) != 10 {
		t.Fatalf("got %d lines; want 10", len(linesAll))
	}
	if linesAll[0] != "line 1" || linesAll[9] != "line 10" {
		t.Errorf("unexpected lines: %v", linesAll)
	}

	// Zero or negative count
	zeroLines, err := ReadLastLinesFromFile(logFile, 0)
	if err != nil || zeroLines != nil {
		t.Errorf("expected nil for 0 lines, got %v, %v", zeroLines, err)
	}
}

func TestCollectLastLines(t *testing.T) {
	tmpDir := t.TempDir()
	file1 := filepath.Join(tmpDir, "tproxy-2026-10-19.log")
	file2 := filepath.Join(tmpDir, "tproxy-2026-10-20.log")

	os.WriteFile(file1, []byte("day1 line 1\nday1 line 2\nday1 line 3\n"), 0600)
	os.WriteFile(file2, []byte("day2 line 1\nday2 line 2\n"), 0600)

	// Collect last 4 lines across newest (file2) and older (file1)
	files := []string{file2, file1}
	lines, err := CollectLastLines(files, 4)
	if err != nil {
		t.Fatalf("CollectLastLines error: %v", err)
	}
	if len(lines) != 4 {
		t.Fatalf("got %d lines; want 4", len(lines))
	}
	expected := []string{"day1 line 2", "day1 line 3", "day2 line 1", "day2 line 2"}
	for i, want := range expected {
		if lines[i] != want {
			t.Errorf("line %d = %q; want %q", i, lines[i], want)
		}
	}
}

func TestRunLogs(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "tproxy-2026-10-20.log")
	os.WriteFile(logFile, []byte("log row 1\nlog row 2\nlog row 3\n"), 0600)

	// Help flag
	var stdout, stderr bytes.Buffer
	code := RunLogs([]string{"-h"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("RunLogs -h exit code = %d; want 0", code)
	}
	if !strings.Contains(stdout.String(), "Usage of logs:") {
		t.Errorf("RunLogs -h output missing usage: %s", stdout.String())
	}

	// Direct -file flag
	stdout.Reset()
	stderr.Reset()
	code = RunLogs([]string{"-file", logFile, "-n", "2"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("RunLogs -file exit code = %d; stderr: %s", code, stderr.String())
	}
	outLines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(outLines) != 2 || outLines[0] != "log row 2" || outLines[1] != "log row 3" {
		t.Errorf("unexpected logs output: %v", outLines)
	}

	// Via -dir flag
	stdout.Reset()
	stderr.Reset()
	code = RunLogs([]string{"-dir", tmpDir, "-prefix", "tproxy", "-n", "1"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("RunLogs -dir exit code = %d; stderr: %s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "log row 3" {
		t.Errorf("RunLogs -dir output = %q; want %q", strings.TrimSpace(stdout.String()), "log row 3")
	}
}

func TestRunTestAndDispatch(t *testing.T) {
	// Help flag
	var stdout, stderr bytes.Buffer
	code := RunTest([]string{"-h"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("RunTest -h exit code = %d; want 0", code)
	}
	if !strings.Contains(stdout.String(), "Usage of test:") {
		t.Errorf("RunTest -h output missing usage: %s", stdout.String())
	}

	// Non-existent config
	stdout.Reset()
	stderr.Reset()
	code = RunTest([]string{"-config", "non_existent_file.json"}, &stdout, &stderr)
	if code == 0 {
		t.Errorf("RunTest with non-existent config returned 0, want error")
	}

	// Dispatch tests
	stdout.Reset()
	stderr.Reset()
	handled, code := Dispatch([]string{"link", "-h"}, &stdout, &stderr)
	if !handled || code != 0 {
		t.Errorf("Dispatch(link -h) = (%v, %d); want (true, 0)", handled, code)
	}

	stdout.Reset()
	stderr.Reset()
	handled, code = Dispatch([]string{"logs", "-h"}, &stdout, &stderr)
	if !handled || code != 0 {
		t.Errorf("Dispatch(logs -h) = (%v, %d); want (true, 0)", handled, code)
	}

	stdout.Reset()
	stderr.Reset()
	handled, code = Dispatch([]string{"test", "-h"}, &stdout, &stderr)
	if !handled || code != 0 {
		t.Errorf("Dispatch(test -h) = (%v, %d); want (true, 0)", handled, code)
	}

	stdout.Reset()
	stderr.Reset()
	handled, code = Dispatch([]string{"-t", "-h"}, &stdout, &stderr)
	if !handled || code != 0 {
		t.Errorf("Dispatch(-t -h) = (%v, %d); want (true, 0)", handled, code)
	}

	stdout.Reset()
	stderr.Reset()
	handled, code = Dispatch([]string{"-h"}, &stdout, &stderr)
	if !handled || code != 0 {
		t.Errorf("Dispatch(-h) = (%v, %d); want (true, 0)", handled, code)
	}

	// Normal server invocation should not be handled by Dispatch
	handled, _ = Dispatch([]string{"-config", "config.json"}, &stdout, &stderr)
	if handled {
		t.Errorf("Dispatch(-config config.json) handled = true; want false")
	}

	handled, _ = Dispatch([]string{}, &stdout, &stderr)
	if handled {
		t.Errorf("Dispatch() handled = true; want false")
	}
}
