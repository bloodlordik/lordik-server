package version

import (
	"strings"
	"testing"
)

func TestVersionInfo(t *testing.T) {
	info := Info()
	if !strings.HasPrefix(info, "tproxy-server ") {
		t.Fatalf("expected prefix 'tproxy-server ', got %q", info)
	}
	if !strings.Contains(info, Version) {
		t.Fatalf("expected version info to contain %q, got %q", Version, info)
	}
	if String() != Version {
		t.Fatalf("expected String() == %q, got %q", Version, String())
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		v1   string
		v2   string
		want int
	}{
		// Equal
		{"v0.2.1", "v0.2.1", 0},
		{"0.2.1", "v0.2.1", 0},
		{"V1.0.0", "1.0.0", 0},
		{"v0.2.1-beta", "v0.2.1-beta", 0},

		// Major difference
		{"v1.0.0", "v0.9.9", 1},
		{"v0.2.1", "v1.0.0", -1},

		// Minor difference
		{"v0.3.0", "v0.2.1", 1},
		{"v0.2.1", "v0.3.0", -1},

		// Patch difference
		{"v0.2.2", "v0.2.1", 1},
		{"v0.2.1", "v0.2.2", -1},

		// Pre-release vs Release (release is higher than prerelease)
		{"v0.2.1", "v0.2.1-rc1", 1},
		{"v0.2.1-rc1", "v0.2.1", -1},
		{"v0.2.1-alpha", "v0.2.1-beta", -1},
		{"v0.2.1-beta", "v0.2.1-alpha", 1},

		// Incomplete / short versions
		{"1", "1.0.0", 0},
		{"1.1", "1.1.0", 0},
		{"1.2", "1.1.9", 1},

		// Fallback for non-semver strings
		{"xyz", "abc", 1},
		{"abc", "xyz", -1},
		{"unknown", "unknown", 0},
	}

	for _, tc := range tests {
		got := Compare(tc.v1, tc.v2)
		if got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.v1, tc.v2, got, tc.want)
		}
	}
}
