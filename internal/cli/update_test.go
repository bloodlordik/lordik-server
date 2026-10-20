package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/telegramdesktop/tproxy-server/internal/version"
)

func TestDispatchVersion(t *testing.T) {
	for _, arg := range []string{"version", "-v", "--version", "-version"} {
		var stdout, stderr bytes.Buffer
		handled, code := Dispatch([]string{arg}, &stdout, &stderr)
		if !handled {
			t.Errorf("expected Dispatch(%q) to be handled", arg)
		}
		if code != 0 {
			t.Errorf("expected exit code 0 for %q, got %d", arg, code)
		}
		if !strings.Contains(stdout.String(), version.String()) {
			t.Errorf("expected output for %q to contain version %q, got %q", arg, version.String(), stdout.String())
		}
	}
}

func TestRunVersionShort(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := RunVersion([]string{"-short"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected code 0, got %d", code)
	}
	if strings.TrimSpace(stdout.String()) != version.String() {
		t.Fatalf("expected short output %q, got %q", version.String(), stdout.String())
	}
}

// helper to create a valid .tar.gz archive in memory with a mock tproxy-server binary
func makeMockTarGz(t *testing.T, binaryName, content string) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	data := []byte(content)
	hdr := &tar.Header{
		Name:     binaryName,
		Mode:     0755,
		Size:     int64(len(data)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("WriteHeader error: %v", err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatalf("tar Write error: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close error: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close error: %v", err)
	}
	return buf.Bytes()
}

func TestUpdateAlreadyUpToDate(t *testing.T) {
	// Serve a release whose TagName matches or is older than version.Version
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResp := fmt.Sprintf(`{
			"tag_name": "%s",
			"html_url": "https://github.com/bloodlordik/lordik-server/releases/tag/%s",
			"assets": []
		}`, version.Version, version.Version)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, jsonResp)
	}))
	defer ts.Close()

	var stdout, stderr bytes.Buffer
	opts := UpdateOptions{
		Repo:       ts.URL,
		HTTPClient: ts.Client(),
	}

	err := DoUpdate(opts, &stdout, &stderr)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !strings.Contains(stdout.String(), "already up to date") {
		t.Fatalf("expected 'already up to date', got %q", stdout.String())
	}
}

func TestUpdateCheckOnly(t *testing.T) {
	newTag := "v99.0.0"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResp := fmt.Sprintf(`{
			"tag_name": "%s",
			"html_url": "https://github.com/bloodlordik/lordik-server/releases/tag/%s",
			"assets": []
		}`, newTag, newTag)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, jsonResp)
	}))
	defer ts.Close()

	var stdout, stderr bytes.Buffer
	opts := UpdateOptions{
		Repo:       ts.URL,
		CheckOnly:  true,
		HTTPClient: ts.Client(),
	}

	err := DoUpdate(opts, &stdout, &stderr)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !strings.Contains(stdout.String(), "a new version is available: "+newTag) {
		t.Fatalf("expected notice for new version %s, got %q", newTag, stdout.String())
	}
}

func TestUpdateNetworkError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	opts := UpdateOptions{
		Repo:    "http://127.0.0.1:59999/releases/latest",
		Timeout: 200 * time.Millisecond,
		HTTPClient: &http.Client{
			Timeout: 200 * time.Millisecond,
		},
	}

	err := DoUpdate(opts, &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected network error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to connect to GitHub releases") {
		t.Fatalf("expected network connection error message, got %v", err)
	}
}

func TestUpdateRateLimit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message": "API rate limit exceeded"}`)
	}))
	defer ts.Close()

	var stdout, stderr bytes.Buffer
	opts := UpdateOptions{
		Repo:       ts.URL,
		HTTPClient: ts.Client(),
	}

	err := DoUpdate(opts, &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected error on 403 rate limit, got nil")
	}
	if !strings.Contains(err.Error(), "rate limit exceeded") {
		t.Fatalf("expected rate limit message, got %v", err)
	}
}

func TestUpdateChecksumMismatch(t *testing.T) {
	newTag := "v99.0.0"
	targetOS := runtime.GOOS
	targetArch := runtime.GOARCH

	binaryName := "tproxy-server"
	if targetOS == "windows" {
		binaryName = "tproxy-server.exe"
	}
	archiveName := fmt.Sprintf("tproxy-server-%s-%s-%s.tar.gz", newTag, targetOS, targetArch)
	archiveBytes := makeMockTarGz(t, binaryName, "new-binary-content")

	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/releases/latest":
			jsonResp := fmt.Sprintf(`{
				"tag_name": "%s",
				"assets": [
					{
						"name": "%s",
						"browser_download_url": "%s/download/%s"
					},
					{
						"name": "%s.sha256",
						"browser_download_url": "%s/download/%s.sha256"
					}
				]
			}`, newTag, archiveName, ts.URL, archiveName, archiveName, ts.URL, archiveName)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, jsonResp)
		case "/download/" + archiveName:
			w.Write(archiveBytes)
		case "/download/" + archiveName + ".sha256":
			// Return a mismatched checksum
			fmt.Fprintln(w, "0000000000000000000000000000000000000000000000000000000000000000  "+archiveName)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	tmpDir := t.TempDir()
	mockExec := filepath.Join(tmpDir, binaryName)
	if err := os.WriteFile(mockExec, []byte("original-binary"), 0755); err != nil {
		t.Fatalf("failed to create mock executable: %v", err)
	}

	var stdout, stderr bytes.Buffer
	opts := UpdateOptions{
		Repo:       ts.URL + "/releases/latest",
		HTTPClient: ts.Client(),
		ExecPath:   mockExec,
		TargetOS:   targetOS,
		TargetArch: targetArch,
	}

	err := DoUpdate(opts, &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected checksum verification error, got nil")
	}
	if !strings.Contains(err.Error(), "checksum verification failed") {
		t.Fatalf("expected checksum verification error message, got %v", err)
	}

	// Verify original file remained intact
	origContent, err := os.ReadFile(mockExec)
	if err != nil {
		t.Fatalf("failed to read mock executable after failed update: %v", err)
	}
	if string(origContent) != "original-binary" {
		t.Fatalf("original binary was overwritten despite checksum failure: %q", string(origContent))
	}
}

func TestUpdateSuccessfulReplacement(t *testing.T) {
	newTag := "v99.0.0"
	targetOS := runtime.GOOS
	targetArch := runtime.GOARCH

	binaryName := "tproxy-server"
	if targetOS == "windows" {
		binaryName = "tproxy-server.exe"
	}
	archiveName := fmt.Sprintf("tproxy-server-%s-%s-%s.tar.gz", newTag, targetOS, targetArch)
	newBinaryData := "newly-installed-binary-data"
	archiveBytes := makeMockTarGz(t, binaryName, newBinaryData)

	h := sha256.New()
	h.Write(archiveBytes)
	correctSHA256 := hex.EncodeToString(h.Sum(nil))

	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/releases/latest":
			jsonResp := fmt.Sprintf(`{
				"tag_name": "%s",
				"assets": [
					{
						"name": "%s",
						"browser_download_url": "%s/download/%s"
					},
					{
						"name": "%s.sha256",
						"browser_download_url": "%s/download/%s.sha256"
					}
				]
			}`, newTag, archiveName, ts.URL, archiveName, archiveName, ts.URL, archiveName)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, jsonResp)
		case "/download/" + archiveName:
			w.Write(archiveBytes)
		case "/download/" + archiveName + ".sha256":
			fmt.Fprintf(w, "%s  %s\n", correctSHA256, archiveName)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	tmpDir := t.TempDir()
	mockExec := filepath.Join(tmpDir, binaryName)
	if err := os.WriteFile(mockExec, []byte("original-binary"), 0755); err != nil {
		t.Fatalf("failed to create mock executable: %v", err)
	}

	var stdout, stderr bytes.Buffer
	opts := UpdateOptions{
		Repo:       ts.URL + "/releases/latest",
		HTTPClient: ts.Client(),
		ExecPath:   mockExec,
		TargetOS:   targetOS,
		TargetArch: targetArch,
	}

	err := DoUpdate(opts, &stdout, &stderr)
	if err != nil {
		t.Fatalf("DoUpdate failed: %v, stderr: %s", err, stderr.String())
	}

	if !strings.Contains(stdout.String(), "successfully updated") {
		t.Fatalf("expected success message, got stdout: %s", stdout.String())
	}

	updatedContent, err := os.ReadFile(mockExec)
	if err != nil {
		t.Fatalf("failed to read updated executable: %v", err)
	}
	if string(updatedContent) != newBinaryData {
		t.Fatalf("expected binary content %q, got %q", newBinaryData, string(updatedContent))
	}
}

func TestUpdateHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := RunUpdate([]string{"-h"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0 on -h, got %d", code)
	}
	if !strings.Contains(stdout.String(), "Usage of update:") {
		t.Fatalf("expected usage text, got %q", stdout.String())
	}
}
