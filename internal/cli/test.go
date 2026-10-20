package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/telegramdesktop/tproxy-server/internal/config"
	appserver "github.com/telegramdesktop/tproxy-server/internal/server"
	"github.com/telegramdesktop/tproxy-server/internal/session"
)

// ValidateConfig validates the configuration file, profiles, budget, and server initialization.
func ValidateConfig(configPath, profilesPath string) error {
	val, err := config.Load(configPath, profilesPath)
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	val.LegacyTokenDrain = os.Getenv("TPROXY_LEGACY_TOKEN_DRAIN") == "1"
	if err := session.ValidateBudget(val); err != nil {
		return fmt.Errorf("budget validation error: %w", err)
	}

	app, err := appserver.New(val)
	if err != nil {
		return fmt.Errorf("server initialization error: %w", err)
	}
	app.Shutdown()

	return nil
}

// RunTest executes the "test" subcommand or the -t / -check flag.
func RunTest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(stderr)

	configPath := fs.String("config", "config.json", "path to server configuration")
	profilesPath := fs.String("profiles-file", "", "override profiles file path")

	fs.Usage = func() {
		fmt.Fprintln(stdout, "Usage of test:")
		fmt.Fprintln(stdout, "  tproxy-server test [flags]")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Validate configuration and profiles without starting the server.")
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

	if err := ValidateConfig(*configPath, *profilesPath); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "configuration is valid")
	return 0
}
