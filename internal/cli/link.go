package cli

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/telegramdesktop/tproxy-server/internal/config"
)

// FormatServerParam formats the hostname and optional base path for proxy links.
// If basePath is present, slashes are escaped as %2F.
func FormatServerParam(host, basePath string) string {
	host = strings.TrimSpace(host)
	basePath = strings.Trim(strings.TrimSpace(basePath), "/")
	if basePath == "" {
		return host
	}
	combined := host + "/" + basePath
	return strings.ReplaceAll(combined, "/", "%2F")
}

// DeriveLinkSecret computes the secret to be used in client-facing proxy links.
// For a root deployment (empty basePath), it returns the hex secret unchanged.
// For a base path deployment, it prepends 0x70 to the raw secret bytes
// and encodes the result as unpadded base64url.
func DeriveLinkSecret(secretHex, basePath string) (string, error) {
	secretHex = strings.TrimSpace(secretHex)
	basePath = strings.Trim(strings.TrimSpace(basePath), "/")
	if basePath == "" {
		return secretHex, nil
	}

	rawSecret, err := config.DecodeSecret(secretHex)
	if err != nil {
		return "", fmt.Errorf("invalid secret: %w", err)
	}

	buf := append([]byte{0x70}, rawSecret...)
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// BuildTGProxyLink builds a tg://proxy?server=...&port=...&secret=... link.
func BuildTGProxyLink(serverParam string, port int, secret string) string {
	return fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=%s", serverParam, port, secret)
}

// BuildTGWebProxyLink builds a tg://webproxy?server=...&secret=... link.
func BuildTGWebProxyLink(serverParam string, secret string) string {
	return fmt.Sprintf("tg://webproxy?server=%s&secret=%s", serverParam, secret)
}

// BuildHTTPSWebProxyLink builds an https://t.me/webproxy?server=...&secret=... link.
func BuildHTTPSWebProxyLink(serverParam string, secret string) string {
	return fmt.Sprintf("https://t.me/webproxy?server=%s&secret=%s", serverParam, secret)
}

// RunLink executes the "link" subcommand.
func RunLink(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("link", flag.ContinueOnError)
	fs.SetOutput(stderr)

	configPath := fs.String("config", "config.json", "path to server configuration")
	profilesPath := fs.String("profiles-file", "", "override profiles file path")
	profileName := fs.String("profile", "", "profile name to use (default: first profile)")
	hostOverride := fs.String("host", "", "override public hostname")
	portOverride := fs.Int("port", 443, "proxy port for tg:// link")
	typeOverride := fs.String("type", "proxy", "link type: proxy, webproxy, https, or all")
	basePathOverride := fs.String("base-path", "", "override base path")
	secretOverride := fs.String("secret", "", "override MTProxy secret")

	fs.Usage = func() {
		fmt.Fprintln(stdout, "Usage of link:")
		fmt.Fprintln(stdout, "  tproxy-server link [flags]")
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

	hostname := *hostOverride
	basePath := *basePathOverride
	secret := *secretOverride

	// If secret or host are not fully provided, attempt to load from configuration file
	if secret == "" || hostname == "" {
		if _, err := os.Stat(*configPath); err == nil {
			cfg, err := config.Load(*configPath, *profilesPath)
			if err != nil {
				fmt.Fprintf(stderr, "error loading config %q: %v\n", *configPath, err)
				return 1
			}
			if hostname == "" {
				hostname = cfg.PublicHostname
			}
			if basePath == "" && *basePathOverride == "" {
				basePath = cfg.BasePath
			}
			if secret == "" {
				if len(cfg.Profiles) == 0 {
					fmt.Fprintf(stderr, "no profiles found in configuration\n")
					return 1
				}
				var selected *config.Profile
				if *profileName != "" {
					for i := range cfg.Profiles {
						if cfg.Profiles[i].Name == *profileName {
							selected = &cfg.Profiles[i]
							break
						}
					}
					if selected == nil {
						fmt.Fprintf(stderr, "profile %q not found\n", *profileName)
						return 1
					}
				} else {
					selected = &cfg.Profiles[0]
				}
				secret = selected.Secret
			}
		} else if secret == "" {
			fmt.Fprintf(stderr, "secret not specified and config file %q not found\n", *configPath)
			return 1
		}
	}

	if hostname == "" {
		hostname = "127.0.0.1"
	}
	port := *portOverride
	if port <= 0 {
		port = 443
	}

	derivedSecret, err := DeriveLinkSecret(secret, basePath)
	if err != nil {
		fmt.Fprintf(stderr, "error deriving secret: %v\n", err)
		return 1
	}

	serverParam := FormatServerParam(hostname, basePath)

	tgProxy := BuildTGProxyLink(serverParam, port, derivedSecret)
	tgWeb := BuildTGWebProxyLink(serverParam, derivedSecret)
	httpsWeb := BuildHTTPSWebProxyLink(serverParam, derivedSecret)

	switch strings.ToLower(strings.TrimSpace(*typeOverride)) {
	case "proxy":
		fmt.Fprintln(stdout, tgProxy)
	case "webproxy":
		fmt.Fprintln(stdout, tgWeb)
	case "https":
		fmt.Fprintln(stdout, httpsWeb)
	case "all":
		fmt.Fprintf(stdout, "tg://proxy:    %s\n", tgProxy)
		fmt.Fprintf(stdout, "tg://webproxy: %s\n", tgWeb)
		fmt.Fprintf(stdout, "https:         %s\n", httpsWeb)
	default:
		fmt.Fprintf(stderr, "unknown link type %q (expected: proxy, webproxy, https, all)\n", *typeOverride)
		return 1
	}

	return 0
}
