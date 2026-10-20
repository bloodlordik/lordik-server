package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Options configures the logging system.
type Options struct {
	Enabled bool   `json:"enabled"`
	Level   string `json:"level"`
	Format  string `json:"format"`
	Output  string `json:"output"`
	Dir     string `json:"dir"`
	Prefix  string `json:"prefix"`
	MaxDays int    `json:"max_days"`
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

type multiCloser struct {
	closers []io.Closer
}

func (m *multiCloser) Close() error {
	var firstErr error
	for _, c := range m.closers {
		if c != nil {
			if err := c.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// ParseLevel parses level string into slog.Level.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("invalid log level %q: must be debug, info, warn, or error", s)
	}
}

// ParseFormat parses format string.
func ParseFormat(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "text":
		return "text", nil
	case "json":
		return "json", nil
	default:
		return "", fmt.Errorf("invalid log format %q: must be text or json", s)
	}
}

// ParseOutput parses output destination string.
func ParseOutput(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "stdout":
		return "stdout", nil
	case "file":
		return "file", nil
	case "both":
		return "both", nil
	default:
		return "", fmt.Errorf("invalid log output %q: must be stdout, file, or both", s)
	}
}

// New creates a new *slog.Logger and an io.Closer for file resources.
func New(opts Options) (*slog.Logger, io.Closer, error) {
	if !opts.Enabled {
		handler := slog.NewTextHandler(io.Discard, nil)
		return slog.New(handler), nopCloser{}, nil
	}

	level, err := ParseLevel(opts.Level)
	if err != nil {
		return nil, nil, err
	}

	format, err := ParseFormat(opts.Format)
	if err != nil {
		return nil, nil, err
	}

	output, err := ParseOutput(opts.Output)
	if err != nil {
		return nil, nil, err
	}

	var writer io.Writer
	var closer io.Closer = nopCloser{}

	switch output {
	case "stdout":
		writer = os.Stdout
	case "file":
		fileWriter, err := NewDailyRotatingWriter(opts.Dir, opts.Prefix, opts.MaxDays)
		if err != nil {
			return nil, nil, err
		}
		writer = fileWriter
		closer = fileWriter
	case "both":
		fileWriter, err := NewDailyRotatingWriter(opts.Dir, opts.Prefix, opts.MaxDays)
		if err != nil {
			return nil, nil, err
		}
		writer = io.MultiWriter(os.Stdout, fileWriter)
		closer = fileWriter
	}

	handlerOpts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(writer, handlerOpts)
	} else {
		handler = slog.NewTextHandler(writer, handlerOpts)
	}

	return slog.New(handler), closer, nil
}

// Setup initializes the logger and sets it as the default slog logger.
func Setup(opts Options) (*slog.Logger, io.Closer, error) {
	l, closer, err := New(opts)
	if err != nil {
		return nil, nil, err
	}
	slog.SetDefault(l)
	return l, closer, nil
}

// MaskToken safely masks a capability token, secret, or key for logging without leaking secrets.
func MaskToken(token string) string {
	if len(token) <= 8 {
		return "[redacted]"
	}
	return token[:6] + "..."
}

// Convenience package-level logging wrappers delegating to slog.Default()
func Debug(msg string, args ...any) {
	slog.Default().Debug(msg, args...)
}

func Info(msg string, args ...any) {
	slog.Default().Info(msg, args...)
}

func Warn(msg string, args ...any) {
	slog.Default().Warn(msg, args...)
}

func Error(msg string, args ...any) {
	slog.Default().Error(msg, args...)
}

func With(args ...any) *slog.Logger {
	return slog.Default().With(args...)
}
