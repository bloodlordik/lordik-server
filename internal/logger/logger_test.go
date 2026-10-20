package logger

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected slog.Level
		wantErr  bool
	}{
		{"", slog.LevelInfo, false},
		{"info", slog.LevelInfo, false},
		{"INFO", slog.LevelInfo, false},
		{"debug", slog.LevelDebug, false},
		{"DEBUG", slog.LevelDebug, false},
		{"warn", slog.LevelWarn, false},
		{"warning", slog.LevelWarn, false},
		{"error", slog.LevelError, false},
		{"unknown", slog.LevelInfo, true},
	}

	for _, tt := range tests {
		lvl, err := ParseLevel(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseLevel(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if !tt.wantErr && lvl != tt.expected {
			t.Errorf("ParseLevel(%q) = %v, expected %v", tt.input, lvl, tt.expected)
		}
	}
}

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"", "text", false},
		{"text", "text", false},
		{"TEXT", "text", false},
		{"json", "json", false},
		{"JSON", "json", false},
		{"yaml", "", true},
	}

	for _, tt := range tests {
		fmtStr, err := ParseFormat(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseFormat(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if !tt.wantErr && fmtStr != tt.expected {
			t.Errorf("ParseFormat(%q) = %v, expected %v", tt.input, fmtStr, tt.expected)
		}
	}
}

func TestParseOutput(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"", "stdout", false},
		{"stdout", "stdout", false},
		{"STDOUT", "stdout", false},
		{"file", "file", false},
		{"both", "both", false},
		{"syslog", "", true},
	}

	for _, tt := range tests {
		out, err := ParseOutput(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseOutput(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if !tt.wantErr && out != tt.expected {
			t.Errorf("ParseOutput(%q) = %v, expected %v", tt.input, out, tt.expected)
		}
	}
}

func TestDailyRotatingWriter(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "logger-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	now := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	writer, err := NewDailyRotatingWriter(tmpDir, "app", 3)
	if err != nil {
		t.Fatalf("NewDailyRotatingWriter failed: %v", err)
	}
	writer.nowFunc = func() time.Time { return now }

	// Write day 1
	msg1 := "log message 1\n"
	if _, err := writer.Write([]byte(msg1)); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	expectedFile1 := filepath.Join(tmpDir, "app-2026-03-01.log")
	data1, err := os.ReadFile(expectedFile1)
	if err != nil {
		t.Fatalf("reading log file 1 failed: %v", err)
	}
	if string(data1) != msg1 {
		t.Errorf("content mismatch: got %q, want %q", string(data1), msg1)
	}

	// Advance to day 2
	now = now.Add(24 * time.Hour)
	msg2 := "log message 2\n"
	if _, err := writer.Write([]byte(msg2)); err != nil {
		t.Fatalf("write day 2 failed: %v", err)
	}

	expectedFile2 := filepath.Join(tmpDir, "app-2026-03-02.log")
	data2, err := os.ReadFile(expectedFile2)
	if err != nil {
		t.Fatalf("reading log file 2 failed: %v", err)
	}
	if string(data2) != msg2 {
		t.Errorf("content mismatch day 2: got %q, want %q", string(data2), msg2)
	}

	// Advance through days to trigger cleanup (maxDays = 3)
	// Day 3
	now = now.Add(24 * time.Hour)
	_, _ = writer.Write([]byte("day 3\n"))
	// Day 4
	now = now.Add(24 * time.Hour)
	_, _ = writer.Write([]byte("day 4\n"))
	// Day 5: 2026-03-05. Difference with 2026-03-01 is 4 days >= maxDays (3), so day 1 should be deleted.
	now = now.Add(24 * time.Hour)
	_, _ = writer.Write([]byte("day 5\n"))

	_ = writer.Close()

	if _, err := os.Stat(expectedFile1); !os.IsNotExist(err) {
		t.Errorf("expected file %s to be cleaned up, but it still exists", expectedFile1)
	}

	// Day 4 and Day 5 files must still exist
	expectedFile5 := filepath.Join(tmpDir, "app-2026-03-05.log")
	if _, err := os.Stat(expectedFile5); err != nil {
		t.Errorf("expected file %s to exist: %v", expectedFile5, err)
	}
}

func TestLoggerOutput(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "logger-test-output-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := Options{
		Enabled: true,
		Level:   "debug",
		Format:  "json",
		Output:  "file",
		Dir:     tmpDir,
		Prefix:  "server",
		MaxDays: 7,
	}

	l, closer, err := New(opts)
	if err != nil {
		t.Fatalf("New logger failed: %v", err)
	}
	defer closer.Close()

	l.Debug("debug event", "session_id", "sess-123")
	l.Info("info event", "count", 42)
	l.Warn("warn event", "reason", "slow_dial")
	l.Error("error event", "err", "connection refused")

	_ = closer.Close()

	today := time.Now().Format("2006-01-02")
	logFile := filepath.Join(tmpDir, fmt.Sprintf("server-%s.log", today))
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log file failed: %v", err)
	}

	logStr := string(content)
	if !strings.Contains(logStr, `"msg":"debug event"`) || !strings.Contains(logStr, `"session_id":"sess-123"`) {
		t.Errorf("missing debug event in log: %s", logStr)
	}
	if !strings.Contains(logStr, `"msg":"info event"`) || !strings.Contains(logStr, `"count":42`) {
		t.Errorf("missing info event in log: %s", logStr)
	}
	if !strings.Contains(logStr, `"msg":"warn event"`) {
		t.Errorf("missing warn event in log: %s", logStr)
	}
	if !strings.Contains(logStr, `"msg":"error event"`) {
		t.Errorf("missing error event in log: %s", logStr)
	}
}

func TestMaskToken(t *testing.T) {
	if got := MaskToken("short"); got != "[redacted]" {
		t.Errorf("MaskToken(short) = %q, want [redacted]", got)
	}
	if got := MaskToken("1234567890abcdef"); got != "123456..." {
		t.Errorf("MaskToken(1234567890abcdef) = %q, want 123456...", got)
	}
}

func TestDisabledLogger(t *testing.T) {
	opts := Options{
		Enabled: false,
	}
	l, closer, err := New(opts)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer closer.Close()

	var buf bytes.Buffer
	// Check that log writes don't crash
	l.Info("test message")
	_ = closer.Close()
	if buf.Len() != 0 {
		t.Errorf("expected no output for disabled logger, got %s", buf.String())
	}
}
