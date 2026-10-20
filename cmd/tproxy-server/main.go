package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/telegramdesktop/tproxy-server/internal/config"
	appserver "github.com/telegramdesktop/tproxy-server/internal/server"
	"github.com/telegramdesktop/tproxy-server/internal/session"
	"github.com/telegramdesktop/tproxy-server/internal/cli"
	"github.com/telegramdesktop/tproxy-server/internal/logger"
)

func main() {
	if handled, exitCode := cli.Dispatch(os.Args[1:], os.Stdout, os.Stderr); handled {
		os.Exit(exitCode)
	}

	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		fmt.Fprintf(os.Stderr, "unknown command %q\nRun 'tproxy-server -h' for usage.\n", os.Args[1])
		os.Exit(1)
	}

	configPath := flag.String("config", "config.json", "path to server configuration")
	profilesPath := flag.String("profiles-file", "", "override profiles file path")
	check := flag.Bool("check", false, "validate configuration and exit")
	testFlag := flag.Bool("t", false, "validate configuration and exit (alias for test)")
	flag.Usage = func() {
		cli.PrintHelp(os.Stdout)
	}
	flag.Parse()

	value, err := config.Load(*configPath, *profilesPath)
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}

	_, logCloser, err := logger.Setup(value.Logging.ToLoggerOptions())
	if err != nil {
		log.Fatalf("logger initialization error: %v", err)
	}
	defer logCloser.Close()

	value.LegacyTokenDrain = os.Getenv("TPROXY_LEGACY_TOKEN_DRAIN") == "1"
	if err := session.ValidateBudget(value); err != nil {
		logger.Error("budget validation failed", "err", err)
		log.Fatalf("configuration error: %v", err)
	}
	application, err := appserver.New(value)
	if err != nil {
		logger.Error("server initialization failed", "err", err)
		log.Fatalf("server initialization error: %v", err)
	}
	if *check || *testFlag {
		application.Shutdown()
		fmt.Println("configuration is valid")
		return
	}

	publicListener, err := net.Listen("tcp", value.Listen)
	if err != nil {
		logger.Error("public listener failed", "listen", value.Listen, "err", err)
		log.Fatalf("public listener error: %v", err)
	}
	adminListener, err := net.Listen("tcp", value.AdminListen)
	if err != nil {
		logger.Error("admin listener failed", "listen", value.AdminListen, "err", err)
		log.Fatalf("admin listener error: %v", err)
	}

	// ReadTimeout covers the whole request including a slow body; it must stay
	// well above long_poll because the server's background read would
	// otherwise cancel every parked long poll's context.
	readTimeout := 60 * time.Second
	if minimum := 2 * value.Timeouts.LongPoll.Value(); minimum > readTimeout {
		readTimeout = minimum
	}
	publicHTTP := &http.Server{
		Handler:           application.Handler(),
		ReadHeaderTimeout: value.Timeouts.ReadHeader.Value(),
		ReadTimeout:       readTimeout,
		IdleTimeout:       value.Timeouts.Idle.Value(),
		MaxHeaderBytes:    value.Limits.MaxHeaderBytes,
	}
	adminHTTP := &http.Server{
		Handler:           application.AdminHandler(),
		ReadHeaderTimeout: value.Timeouts.ReadHeader.Value(),
		IdleTimeout:       value.Timeouts.Idle.Value(),
		MaxHeaderBytes:    value.Limits.MaxHeaderBytes,
	}
	errors := make(chan error, 2)
	go func() { errors <- publicHTTP.Serve(publicListener) }()
	go func() { errors <- adminHTTP.Serve(adminListener) }()
	logger.Info("server started", "public", value.Listen, "admin", value.AdminListen, "profiles", len(value.Profiles), "legacy_token_drain", value.LegacyTokenDrain)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errors:
		logger.Error("server error", "err", err)
		log.Fatalf("server error: %v", err)
	case sig := <-signals:
		logger.Info("shutting down on signal", "signal", sig.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), value.Timeouts.Shutdown.Value())
	defer cancel()
	_ = publicHTTP.Shutdown(ctx)
	_ = adminHTTP.Shutdown(ctx)
	application.Shutdown()
	logger.Info("server stopped")
}
