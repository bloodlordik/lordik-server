package cli

import (
	"fmt"
	"io"
)

// PrintHelp prints root usage information.
func PrintHelp(w io.Writer) {
	fmt.Fprintln(w, "tproxy-server - Telegram WEB proxy server")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  tproxy-server [command] [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Available Commands:")
	fmt.Fprintln(w, "  link    Generate shareable Telegram proxy links")
	fmt.Fprintln(w, "  logs    Display recent log entries")
	fmt.Fprintln(w, "  test    Validate server configuration")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  -config string")
	fmt.Fprintln(w, "        path to server configuration (default \"config.json\")")
	fmt.Fprintln(w, "  -profiles-file string")
	fmt.Fprintln(w, "        override profiles file path")
	fmt.Fprintln(w, "  -check, -t")
	fmt.Fprintln(w, "        validate configuration and exit")
	fmt.Fprintln(w, "  -h, --help")
	fmt.Fprintln(w, "        show this help message")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Use \"tproxy-server [command] -h\" for more information about a command.")
}

// Dispatch checks if the given command-line arguments specify a CLI subcommand or diagnostic flag.
// If so, it executes the command and returns (true, exitCode).
// Otherwise it returns (false, 0) indicating that standard server operation should proceed.
func Dispatch(args []string, stdout, stderr io.Writer) (bool, int) {
	if len(args) == 0 {
		return false, 0
	}

	cmd := args[0]
	switch cmd {
	case "link":
		return true, RunLink(args[1:], stdout, stderr)
	case "logs":
		return true, RunLogs(args[1:], stdout, stderr)
	case "test":
		return true, RunTest(args[1:], stdout, stderr)
	case "-t":
		return true, RunTest(args[1:], stdout, stderr)
	case "help":
		PrintHelp(stdout)
		return true, 0
	case "-h", "--help":
		PrintHelp(stdout)
		return true, 0
	default:
		return false, 0
	}
}
