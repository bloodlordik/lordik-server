package version

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

// Version is the current application version.
// It can be overridden at build time via -ldflags="-X github.com/telegramdesktop/tproxy-server/internal/version.Version=vX.Y.Z".
var Version = "v0.2.1"

// String returns the bare version string (e.g. "v0.2.1").
func String() string {
	return Version
}

// Info returns detailed build and runtime version information.
func Info() string {
	return fmt.Sprintf("tproxy-server %s (%s/%s, %s)", Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

// semver represents parsed semantic version components.
type semver struct {
	major      int
	minor      int
	patch      int
	prerelease string
}

func parseSemver(v string) (semver, error) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")

	var prerelease string
	if idx := strings.Index(v, "-"); idx != -1 {
		prerelease = v[idx+1:]
		v = v[:idx]
	}

	parts := strings.Split(v, ".")
	if len(parts) == 0 || parts[0] == "" {
		return semver{}, fmt.Errorf("empty version string")
	}

	var nums [3]int
	for i := 0; i < len(parts) && i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return semver{}, fmt.Errorf("invalid version component %q: %w", parts[i], err)
		}
		nums[i] = n
	}

	return semver{
		major:      nums[0],
		minor:      nums[1],
		patch:      nums[2],
		prerelease: prerelease,
	}, nil
}

// Compare compares two semantic version strings.
// Returns:
//   -1 if v1 < v2
//    0 if v1 == v2
//    1 if v1 > v2
//
// If one or both version strings cannot be parsed as semver, fallback string comparison is used.
func Compare(v1, v2 string) int {
	s1, err1 := parseSemver(v1)
	s2, err2 := parseSemver(v2)

	if err1 != nil || err2 != nil {
		switch {
		case v1 < v2:
			return -1
		case v1 > v2:
			return 1
		default:
			return 0
		}
	}

	if s1.major != s2.major {
		if s1.major < s2.major {
			return -1
		}
		return 1
	}

	if s1.minor != s2.minor {
		if s1.minor < s2.minor {
			return -1
		}
		return 1
	}

	if s1.patch != s2.patch {
		if s1.patch < s2.patch {
			return -1
		}
		return 1
	}

	// When major, minor, patch match:
	// A version without prerelease has higher precedence than one with prerelease (e.g. 1.0.0 > 1.0.0-rc1).
	if s1.prerelease == "" && s2.prerelease != "" {
		return 1
	}
	if s1.prerelease != "" && s2.prerelease == "" {
		return -1
	}

	if s1.prerelease != s2.prerelease {
		if s1.prerelease < s2.prerelease {
			return -1
		}
		return 1
	}

	return 0
}
