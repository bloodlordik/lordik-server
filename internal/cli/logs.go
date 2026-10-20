package cli

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/telegramdesktop/tproxy-server/internal/config"
)

// ReadLastLinesFromFile reads up to count lines from the end of the specified file.
func ReadLastLinesFromFile(filePath string, count int) ([]string, error) {
	if count <= 0 {
		return nil, nil
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read all lines using a ring buffer of size count
	ring := make([]string, count)
	total := 0
	scanner := bufio.NewScanner(f)
	// Allow scanning lines up to 1MB
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		ring[total%count] = scanner.Text()
		total++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if total == 0 {
		return nil, nil
	}

	if total < count {
		result := make([]string, total)
		copy(result, ring[:total])
		return result, nil
	}

	result := make([]string, count)
	start := total % count
	for i := 0; i < count; i++ {
		result[i] = ring[(start+i)%count]
	}
	return result, nil
}

// CollectLastLines collects up to n lines across multiple log files
// ordered newest to oldest, returning them in chronological order.
func CollectLastLines(files []string, n int) ([]string, error) {
	if n <= 0 || len(files) == 0 {
		return nil, nil
	}

	remaining := n
	var chunks [][]string

	for _, file := range files {
		lines, err := ReadLastLinesFromFile(file, remaining)
		if err != nil {
			return nil, fmt.Errorf("read %q: %w", file, err)
		}
		if len(lines) > 0 {
			chunks = append(chunks, lines)
			remaining -= len(lines)
			if remaining <= 0 {
				break
			}
		}
	}

	// chunks contains lines from newest file first.
	// We want chronological order: oldest chunk first.
	var result []string
	for i := len(chunks) - 1; i >= 0; i-- {
		result = append(result, chunks[i]...)
	}
	return result, nil
}

// RunLogs executes the "logs" subcommand.
func RunLogs(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	fs.SetOutput(stderr)

	nLines := fs.Int("n", 50, "number of log lines to display")
	configPath := fs.String("config", "config.json", "path to server configuration")
	dirOverride := fs.String("dir", "", "override log directory")
	fileOverride := fs.String("file", "", "explicit path to log file")
	prefixOverride := fs.String("prefix", "", "override log file prefix (default: from config or tproxy)")

	fs.Usage = func() {
		fmt.Fprintln(stdout, "Usage of logs:")
		fmt.Fprintln(stdout, "  tproxy-server logs [flags]")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Flags:")
		fs.SetOutput(stdout)
		fs.PrintDefaults()
		fs.SetOutput(stderr)
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}

	if *nLines <= 0 {
		return 0
	}

	if *fileOverride != "" {
		lines, err := ReadLastLinesFromFile(*fileOverride, *nLines)
		if err != nil {
			fmt.Fprintf(stderr, "error reading log file %q: %v\n", *fileOverride, err)
			return 1
		}
		for _, line := range lines {
			fmt.Fprintln(stdout, line)
		}
		return 0
	}

	// Resolve log directory and prefix
	dir := "logs"
	prefix := "tproxy"

	if _, err := os.Stat(*configPath); err == nil {
		cfg, err := config.Load(*configPath)
		if err == nil {
			if cfg.Logging.Dir != "" {
				dir = cfg.Logging.Dir
			}
			if cfg.Logging.Prefix != "" {
				prefix = cfg.Logging.Prefix
			}
		}
	}

	if *dirOverride != "" {
		dir = *dirOverride
	}
	if *prefixOverride != "" {
		prefix = *prefixOverride
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(stderr, "error reading log directory %q: %v\n", dir, err)
		return 1
	}

	filePrefix := prefix + "-"
	const fileSuffix = ".log"

	var matchingFiles []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, filePrefix) && strings.HasSuffix(name, fileSuffix) {
			matchingFiles = append(matchingFiles, filepath.Join(dir, name))
		}
	}

	if len(matchingFiles) == 0 {
		fmt.Fprintf(stderr, "no log files matching %q found in %q\n", prefix+"-*.log", dir)
		return 0
	}

	// Sort filenames descending so newest (latest date) comes first
	sort.Slice(matchingFiles, func(i, j int) bool {
		return matchingFiles[i] > matchingFiles[j]
	})

	lines, err := CollectLastLines(matchingFiles, *nLines)
	if err != nil {
		fmt.Fprintf(stderr, "error reading logs: %v\n", err)
		return 1
	}

	for _, line := range lines {
		fmt.Fprintln(stdout, line)
	}

	return 0
}
