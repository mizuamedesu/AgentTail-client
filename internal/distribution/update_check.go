// SPDX-License-Identifier: GPL-3.0-or-later

package distribution

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const updateCheckInterval = time.Hour
const updateRetryInterval = 15 * time.Minute

type updateCache struct {
	Source    string `json:"source"`
	CheckedAt int64  `json:"checked_at"`
	Raw       []byte `json:"manifest,omitempty"`
	Signature []byte `json:"signature,omitempty"`
	Failed    bool   `json:"failed,omitempty"`
}

// AvailableUpdate is advisory only. Cached metadata is signature-verified again
// before use; the installed sequence and running version prevent downgrade tips.
// Callers should bound the context and ignore errors without affecting their work.
func AvailableUpdate(ctx context.Context, source, version string, sequence uint64, cachePath string) (string, error) {
	return availableUpdate(ctx, source, version, sequence, cachePath, time.Now(), LatestManifest, Verify)
}

func availableUpdate(ctx context.Context, source, version string, sequence uint64, cachePath string, now time.Time,
	fetch func(context.Context, string) (Manifest, error), verify func([]byte, []byte, time.Time) (Manifest, error)) (string, error) {
	if _, ok := compareVersions(version, version); !ok {
		return "", nil // Unversioned development binaries are not releasable.
	}
	if err := ValidateSource(source); err != nil {
		return "", err
	}
	var cache updateCache
	if file, err := os.Open(cachePath); err == nil {
		data, err := readLimited(file, 128*1024)
		file.Close()
		if err == nil {
			_ = json.Unmarshal(data, &cache)
		}
	}
	if cache.Source != source {
		cache = updateCache{Source: source}
	}
	latest, cachedErr := verify(cache.Raw, cache.Signature, now)
	interval := updateCheckInterval
	if cache.Failed {
		interval = updateRetryInterval
	}
	age := now.Sub(time.Unix(cache.CheckedAt, 0))
	fresh := cache.CheckedAt > 0 && age >= 0 && age < interval
	if !fresh || cachedErr != nil && !cache.Failed {
		var err error
		latest, err = fetch(ctx, source)
		// Recheck at this boundary even if a fetch implementation returns a
		// parsed Manifest: neither a cache nor a parser is a release authority.
		if err == nil {
			latest, err = verify(latest.Raw, latest.Signature, now)
		}
		if ctx.Err() == context.Canceled {
			return "", ctx.Err()
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		cache.CheckedAt, cache.Failed = now.Unix(), err != nil
		if err == nil {
			cache.Raw, cache.Signature = latest.Raw, latest.Signature
		}
		if cachePath != "" {
			if data, e := json.Marshal(cache); e == nil && os.MkdirAll(filepath.Dir(cachePath), 0700) == nil {
				_ = atomicFile(cachePath, data, 0600)
			}
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if err != nil {
			// Keep a previously verified, unexpired tip during an outage, while
			// rate-limiting retries. Corrupt or expired metadata stays silent.
			latest, cachedErr = verify(cache.Raw, cache.Signature, now)
			if cachedErr != nil {
				return "", err
			}
		}
	} else if cachedErr != nil {
		return "", nil
	}
	if _, err := latest.Platform(runtime.GOOS, runtime.GOARCH); err != nil {
		return "", err
	}
	comparison, valid := compareVersions(latest.Version, version)
	if !valid || comparison <= 0 || sequence > 0 && latest.Sequence <= sequence {
		return "", nil
	}
	return latest.Version, nil
}

// Compare the numeric release fields and SemVer prerelease identifiers, including
// dev.9 < dev.10. Arbitrarily long numbers are compared without integer overflow.
func compareVersions(left, right string) (int, bool) {
	parse := func(version string) ([]string, []string, bool) {
		if !safeVersion.MatchString(version) {
			return nil, nil, false
		}
		parts := strings.SplitN(version, "-", 2)
		core := strings.Split(parts[0], ".")
		var pre []string
		if len(parts) == 2 {
			pre = strings.Split(parts[1], ".")
		}
		for _, identifier := range append(append([]string{}, core...), pre...) {
			if numericIdentifier(identifier) && len(identifier) > 1 && identifier[0] == '0' {
				return nil, nil, false
			}
		}
		return core, pre, true
	}
	lcore, lpre, lok := parse(left)
	rcore, rpre, rok := parse(right)
	if !lok || !rok {
		return 0, false
	}
	number := func(l, r string) int {
		if len(l) != len(r) {
			if len(l) < len(r) {
				return -1
			}
			return 1
		}
		return strings.Compare(l, r)
	}
	for i := range lcore {
		if c := number(lcore[i], rcore[i]); c != 0 {
			return c, true
		}
	}
	if len(lpre) == 0 || len(rpre) == 0 {
		if len(lpre) == len(rpre) {
			return 0, true
		}
		if len(lpre) == 0 {
			return 1, true
		}
		return -1, true
	}
	for i := 0; i < len(lpre) && i < len(rpre); i++ {
		ln, rn := numericIdentifier(lpre[i]), numericIdentifier(rpre[i])
		var c int
		switch {
		case ln && rn:
			c = number(lpre[i], rpre[i])
		case ln:
			c = -1
		case rn:
			c = 1
		default:
			c = strings.Compare(lpre[i], rpre[i])
		}
		if c != 0 {
			return c, true
		}
	}
	if len(lpre) < len(rpre) {
		return -1, true
	}
	if len(lpre) > len(rpre) {
		return 1, true
	}
	return 0, true
}

func numericIdentifier(value string) bool {
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return value != ""
}
