package cli

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/telegramdesktop/tproxy-server/internal/version"
)

// DefaultRepo is the default GitHub repository for releases.
const DefaultRepo = "bloodlordik/lordik-server"

// ReleaseInfo represents GitHub release metadata.
type ReleaseInfo struct {
	TagName     string         `json:"tag_name"`
	HTMLURL     string         `json:"html_url"`
	PublishedAt string         `json:"published_at"`
	Assets      []ReleaseAsset `json:"assets"`
}

// ReleaseAsset represents an asset in a GitHub release.
type ReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// UpdateOptions holds configuration for the update operation.
type UpdateOptions struct {
	Repo        string
	CheckOnly   bool
	Force       bool
	Timeout     time.Duration
	HTTPClient  *http.Client
	ExecPath    string // override for testing
	TargetOS    string // override for testing, default runtime.GOOS
	TargetArch  string // override for testing, default runtime.GOARCH
}

// RunUpdate executes the "update" subcommand.
func RunUpdate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(stderr)

	checkOnly := fs.Bool("check", false, "check for updates without downloading or installing")
	force := fs.Bool("force", false, "force update even if current version is up to date")
	fs.BoolVar(force, "f", false, "force update (alias for -force)")
	repo := fs.String("repo", DefaultRepo, "GitHub repository (owner/repo)")
	timeout := fs.Duration("timeout", 30*time.Second, "network timeout for release check and download")

	fs.Usage = func() {
		fmt.Fprintln(stdout, "Usage of update:")
		fmt.Fprintln(stdout, "  tproxy-server update [flags]")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Check GitHub Releases and upgrade the tproxy-server binary.")
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

	opts := UpdateOptions{
		Repo:       *repo,
		CheckOnly:  *checkOnly,
		Force:      *force,
		Timeout:    *timeout,
		TargetOS:   runtime.GOOS,
		TargetArch: runtime.GOARCH,
	}

	if err := DoUpdate(opts, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "update error: %v\n", err)
		return 1
	}

	return 0
}

// DoUpdate performs the release check, asset download, checksum validation, and atomic binary replacement.
func DoUpdate(opts UpdateOptions, stdout, stderr io.Writer) error {
	if opts.Repo == "" {
		opts.Repo = DefaultRepo
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.TargetOS == "" {
		opts.TargetOS = runtime.GOOS
	}
	if opts.TargetArch == "" {
		opts.TargetArch = runtime.GOARCH
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{
			Timeout: opts.Timeout,
		}
	}

	client := opts.HTTPClient
	currentVer := version.String()

	// 1. Fetch latest release info
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", opts.Repo)
	if strings.HasPrefix(opts.Repo, "http://") || strings.HasPrefix(opts.Repo, "https://") {
		apiURL = opts.Repo
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, apiURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create release request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "tproxy-server-updater/"+currentVer)

	resp, err := client.Do(req)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) {
			return fmt.Errorf("failed to connect to GitHub releases: %w. Please check your internet connection", err)
		}
		return fmt.Errorf("failed to connect to GitHub releases: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("GitHub API rate limit exceeded or access forbidden (HTTP 403). Please try again later")
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("no releases found for repository %q (HTTP 404)", opts.Repo)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub API returned unexpected status %d", resp.StatusCode)
	}

	var release ReleaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return fmt.Errorf("failed to parse release metadata: %w", err)
	}

	latestVer := release.TagName
	if latestVer == "" {
		return fmt.Errorf("release tag name is empty")
	}

	// 2. Version comparison
	cmp := version.Compare(latestVer, currentVer)
	if cmp <= 0 && !opts.Force {
		fmt.Fprintf(stdout, "tproxy-server is already up to date (current: %s, latest: %s)\n", currentVer, latestVer)
		return nil
	}

	if opts.CheckOnly {
		if cmp > 0 {
			fmt.Fprintf(stdout, "a new version is available: %s (current: %s)\nRun 'tproxy-server update' to upgrade.\n", latestVer, currentVer)
		} else {
			fmt.Fprintf(stdout, "tproxy-server is up to date (current: %s, latest: %s)\n", currentVer, latestVer)
		}
		return nil
	}

	fmt.Fprintf(stdout, "found new version: %s (current: %s)\n", latestVer, currentVer)

	// 3. Find compatible asset and sha256 asset
	expectedSuffix := fmt.Sprintf("%s-%s.tar.gz", opts.TargetOS, opts.TargetArch)
	var archiveAsset *ReleaseAsset
	var sha256Asset *ReleaseAsset

	for i := range release.Assets {
		a := &release.Assets[i]
		if strings.HasSuffix(a.Name, expectedSuffix) {
			archiveAsset = a
		}
	}

	if archiveAsset == nil {
		return fmt.Errorf("no compatible release asset found for platform %s/%s", opts.TargetOS, opts.TargetArch)
	}

	// Find corresponding .sha256 asset
	sha256Name := archiveAsset.Name + ".sha256"
	for i := range release.Assets {
		a := &release.Assets[i]
		if a.Name == sha256Name {
			sha256Asset = a
			break
		}
	}

	// 4. Download and parse SHA-256 checksum if available
	var expectedSHA256 string
	if sha256Asset != nil {
		fmt.Fprintf(stdout, "fetching checksum from %s...\n", sha256Asset.Name)
		shaReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, sha256Asset.BrowserDownloadURL, nil)
		if err != nil {
			return fmt.Errorf("failed to create checksum request: %w", err)
		}
		shaReq.Header.Set("User-Agent", "tproxy-server-updater/"+currentVer)

		shaResp, err := client.Do(shaReq)
		if err != nil {
			return fmt.Errorf("failed to download checksum file: %w", err)
		}
		defer shaResp.Body.Close()

		if shaResp.StatusCode == http.StatusOK {
			shaBytes, err := io.ReadAll(io.LimitReader(shaResp.Body, 1024))
			if err != nil {
				return fmt.Errorf("failed to read checksum file: %w", err)
			}
			parts := strings.Fields(string(shaBytes))
			if len(parts) > 0 {
				expectedSHA256 = strings.ToLower(parts[0])
			}
		}
	}

	// 5. Download archive
	fmt.Fprintf(stdout, "downloading %s...\n", archiveAsset.Name)
	archReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, archiveAsset.BrowserDownloadURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create download request: %w", err)
	}
	archReq.Header.Set("User-Agent", "tproxy-server-updater/"+currentVer)

	archResp, err := client.Do(archReq)
	if err != nil {
		return fmt.Errorf("failed to download release asset: %w", err)
	}
	defer archResp.Body.Close()

	if archResp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download release asset (HTTP %d)", archResp.StatusCode)
	}

	tempArchive, err := os.CreateTemp("", "tproxy-update-*.tar.gz")
	if err != nil {
		return fmt.Errorf("failed to create temporary download file: %w", err)
	}
	tempArchiveName := tempArchive.Name()
	defer os.Remove(tempArchiveName)

	hasher := sha256.New()
	tee := io.TeeReader(archResp.Body, hasher)

	if _, err := io.Copy(tempArchive, tee); err != nil {
		tempArchive.Close()
		return fmt.Errorf("failed to write downloaded asset: %w", err)
	}
	tempArchive.Close()

	// Verify SHA-256
	if expectedSHA256 != "" {
		calculatedSHA256 := hex.EncodeToString(hasher.Sum(nil))
		if !strings.EqualFold(calculatedSHA256, expectedSHA256) {
			return fmt.Errorf("checksum verification failed (expected %s, got %s). Aborting update", expectedSHA256, calculatedSHA256)
		}
		fmt.Fprintln(stdout, "checksum verification passed")
	}

	// 6. Extract binary from archive
	binaryName := "tproxy-server"
	if opts.TargetOS == "windows" {
		binaryName = "tproxy-server.exe"
	}

	extractedBinary, err := extractBinaryFromTarGz(tempArchiveName, binaryName)
	if err != nil {
		return fmt.Errorf("failed to extract binary from release archive: %w", err)
	}
	defer os.Remove(extractedBinary)

	// 7. Atomic binary replacement with rollback protection
	execPath := opts.ExecPath
	if execPath == "" {
		execPath, err = os.Executable()
		if err != nil {
			return fmt.Errorf("failed to locate running executable path: %w", err)
		}
		execPath, err = filepath.EvalSymlinks(execPath)
		if err != nil {
			return fmt.Errorf("failed to resolve executable symlinks: %w", err)
		}
	}

	execDir := filepath.Dir(execPath)

	// Test write access to executable directory
	newBinaryPath := filepath.Join(execDir, fmt.Sprintf(".tproxy-new-%d", os.Getpid()))
	if err := copyFile(extractedBinary, newBinaryPath, 0755); err != nil {
		if os.IsPermission(err) || strings.Contains(strings.ToLower(err.Error()), "permission") || strings.Contains(strings.ToLower(err.Error()), "access is denied") {
			return fmt.Errorf("permission denied: cannot write to directory %s. Please run with sudo or appropriate privileges", execDir)
		}
		return fmt.Errorf("failed to stage new binary: %w", err)
	}
	defer os.Remove(newBinaryPath) // clean up if still exists

	bakBinaryPath := filepath.Join(execDir, fmt.Sprintf(".tproxy-bak-%d", os.Getpid()))

	// Step A: Backup existing binary
	if err := os.Rename(execPath, bakBinaryPath); err != nil {
		if os.IsPermission(err) || strings.Contains(strings.ToLower(err.Error()), "permission") || strings.Contains(strings.ToLower(err.Error()), "access is denied") {
			return fmt.Errorf("permission denied: cannot backup current executable at %s. Please run with sudo or appropriate privileges", execPath)
		}
		return fmt.Errorf("failed to backup current binary: %w", err)
	}

	// Step B: Move staged binary to target executable path
	if err := os.Rename(newBinaryPath, execPath); err != nil {
		// Rollback immediately
		rollbackErr := os.Rename(bakBinaryPath, execPath)
		if rollbackErr != nil {
			return fmt.Errorf("critical: update failed (%v) and rollback failed (%v). Backup remains at %s", err, rollbackErr, bakBinaryPath)
		}
		return fmt.Errorf("atomic replacement failed (%v); successfully rolled back to previous version", err)
	}

	// Step C: Remove backup file
	_ = os.Remove(bakBinaryPath)

	fmt.Fprintf(stdout, "successfully updated tproxy-server from %s to %s\n", currentVer, latestVer)
	return nil
}

// extractBinaryFromTarGz extracts a single binary file from a .tar.gz archive into a temp file.
func extractBinaryFromTarGz(archivePath, targetName string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("gzip reader error: %w", err)
	}
	defer gz.Close()

	tarReader := tar.NewReader(gz)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("tar read error: %w", err)
		}

		// Match binary name (handle potential archive directory prefix)
		baseName := filepath.Base(header.Name)
		if baseName == targetName && (header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA) {
			tempFile, err := os.CreateTemp("", "tproxy-binary-*")
			if err != nil {
				return "", fmt.Errorf("failed to create temp binary file: %w", err)
			}
			defer tempFile.Close()

			if _, err := io.Copy(tempFile, tarReader); err != nil {
				os.Remove(tempFile.Name())
				return "", fmt.Errorf("failed to extract binary contents: %w", err)
			}

			if err := tempFile.Chmod(0755); err != nil && runtime.GOOS != "windows" {
				os.Remove(tempFile.Name())
				return "", fmt.Errorf("failed to set binary permissions: %w", err)
			}

			return tempFile.Name(), nil
		}
	}

	return "", fmt.Errorf("binary %q not found in archive", targetName)
}

// copyFile copies a file from src to dst with the given permissions.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
