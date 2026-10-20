package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/telegramdesktop/tproxy-server/internal/version"
)

// RunVersion executes the "version" subcommand or -v / --version flags.
func RunVersion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)

	short := fs.Bool("short", false, "print only the version string (e.g. v0.2.1)")

	fs.Usage = func() {
		fmt.Fprintln(stdout, "Usage of version:")
		fmt.Fprintln(stdout, "  tproxy-server version [flags]")
		fmt.Fprintln(stdout, "  tproxy-server -v")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Display application version and build information.")
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

	if *short {
		fmt.Fprintln(stdout, version.String())
	} else {
		fmt.Fprintln(stdout, version.Info())
	}
	return 0
}
