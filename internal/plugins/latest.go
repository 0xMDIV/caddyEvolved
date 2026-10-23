package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// EscapePath encodes a module path the way the Go module proxy expects it:
// every upper-case letter becomes "!" plus its lower-case form.
func EscapePath(path string) string {
	var b strings.Builder
	for _, r := range path {
		if unicode.IsUpper(r) {
			b.WriteByte('!')
			r = unicode.ToLower(r)
		}
		b.WriteRune(r)
	}
	return b.String()
}

// LatestVersion asks the Go module proxy which version `go get path` would pick
// today – the version xcaddy compiles in when the module carries no @version.
func LatestVersion(ctx context.Context, path string) (string, error) {
	path, _, _ = strings.Cut(path, "@")
	httpc := &http.Client{Timeout: 12 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ProxyBase+"/"+EscapePath(path)+"/@latest", nil)
	if err != nil {
		return "", err
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return "", fmt.Errorf("Proxy nicht erreichbar: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Proxy antwortete %s", resp.Status)
	}
	var v struct {
		Version string `json:"Version"`
	}
	if err := json.Unmarshal(body, &v); err != nil || v.Version == "" {
		return "", fmt.Errorf("Proxy-Antwort ohne Version")
	}
	return v.Version, nil
}

// CompareVersions orders two semantic versions ("v1.2.3", "v0.0.0-2024…-abc"
// pseudo-versions included) like Go does: -1, 0 or +1. ok is false when either
// side is not a version, e.g. "(devel)".
func CompareVersions(a, b string) (cmp int, ok bool) {
	pa, okA := parseSemver(a)
	pb, okB := parseSemver(b)
	if !okA || !okB {
		return 0, false
	}
	for i := 0; i < 3; i++ {
		if pa.num[i] != pb.num[i] {
			if pa.num[i] < pb.num[i] {
				return -1, true
			}
			return 1, true
		}
	}
	return comparePre(pa.pre, pb.pre), true
}

type semver struct {
	num [3]int
	pre string
}

func parseSemver(v string) (semver, bool) {
	var s semver
	v, ok := strings.CutPrefix(strings.TrimSpace(v), "v")
	if !ok {
		return s, false
	}
	v, _, _ = strings.Cut(v, "+")
	core, pre, _ := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return s, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return s, false
		}
		s.num[i] = n
	}
	s.pre = pre
	return s, true
}

// comparePre follows semver: no prerelease beats any prerelease, numeric
// identifiers compare as numbers, the rest in ASCII order.
func comparePre(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "":
		return 1
	case b == "":
		return -1
	}
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, y := as[i], bs[i]
		if x == y {
			continue
		}
		nx, ex := strconv.Atoi(x)
		ny, ey := strconv.Atoi(y)
		switch {
		case ex == nil && ey == nil:
			if nx < ny {
				return -1
			}
			return 1
		case ex == nil:
			return -1
		case ey == nil:
			return 1
		case x < y:
			return -1
		default:
			return 1
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}
