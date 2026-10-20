package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DailyRotatingWriter writes log data to files split by date (YYYY-MM-DD)
// and automatically removes log files older than maxDays.
type DailyRotatingWriter struct {
	mu          sync.Mutex
	dir         string
	prefix      string
	maxDays     int
	currentDate string
	currentFile *os.File
	closed      bool
	nowFunc     func() time.Time
}

var _ io.WriteCloser = (*DailyRotatingWriter)(nil)

// NewDailyRotatingWriter creates a writer that rotates files daily in dir with the given prefix.
// If maxDays > 0, log files older than maxDays are automatically deleted.
func NewDailyRotatingWriter(dir, prefix string, maxDays int) (*DailyRotatingWriter, error) {
	if dir == "" {
		dir = "logs"
	}
	if prefix == "" {
		prefix = "tproxy"
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("create log directory %q: %w", dir, err)
	}

	w := &DailyRotatingWriter{
		dir:     dir,
		prefix:  prefix,
		maxDays: maxDays,
		nowFunc: time.Now,
	}

	// Trigger initial file opening and old log cleanup
	if err := w.rotateLocked(w.now()); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *DailyRotatingWriter) now() time.Time {
	if w.nowFunc != nil {
		return w.nowFunc()
	}
	return time.Now()
}

// Write writes data to the active daily log file, rotating if the date has changed.
func (w *DailyRotatingWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return 0, os.ErrClosed
	}

	now := w.now()
	today := now.Format("2006-01-02")
	if w.currentFile == nil || w.currentDate != today {
		if err := w.rotateLocked(now); err != nil {
			return 0, err
		}
	}

	return w.currentFile.Write(p)
}

// rotateLocked rotates to the log file for date and cleans up old files.
// Caller must hold w.mu.
func (w *DailyRotatingWriter) rotateLocked(now time.Time) error {
	today := now.Format("2006-01-02")
	if w.currentFile != nil {
		_ = w.currentFile.Close()
		w.currentFile = nil
	}

	filePath := filepath.Join(w.dir, fmt.Sprintf("%s-%s.log", w.prefix, today))
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("open log file %q: %w", filePath, err)
	}

	w.currentFile = f
	w.currentDate = today

	w.cleanupLocked(now)
	return nil
}

// cleanupLocked removes log files matching prefix-YYYY-MM-DD.log older than maxDays.
// Caller must hold w.mu.
func (w *DailyRotatingWriter) cleanupLocked(now time.Time) {
	if w.maxDays <= 0 {
		return
	}

	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return
	}

	prefixMatch := w.prefix + "-"
	const suffixMatch = ".log"

	nowDate := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, prefixMatch) || !strings.HasSuffix(name, suffixMatch) {
			continue
		}

		dateStr := strings.TrimSuffix(strings.TrimPrefix(name, prefixMatch), suffixMatch)
		fileDate, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			continue
		}

		fDate := time.Date(fileDate.Year(), fileDate.Month(), fileDate.Day(), 0, 0, 0, 0, time.UTC)
		daysOld := int(nowDate.Sub(fDate).Hours() / 24)
		if daysOld >= w.maxDays {
			_ = os.Remove(filepath.Join(w.dir, name))
		}
	}
}

// Close closes the underlying log file.
func (w *DailyRotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	w.closed = true

	if w.currentFile != nil {
		err := w.currentFile.Close()
		w.currentFile = nil
		return err
	}
	return nil
}

// Sync flushes data to disk.
func (w *DailyRotatingWriter) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.currentFile != nil {
		return w.currentFile.Sync()
	}
	return nil
}
