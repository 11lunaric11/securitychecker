package scanner

import (
	"net/url"
	"strings"

	"github.com/11lunaric11/securitychecker/internal/model"
)

// Normalize turns a raw user string ("example.com", "https://x.com/path",
// "  # comment") into a base target. ok is false for blank/comment lines or
// input that cannot be parsed into a host.
func Normalize(raw string) (t model.Target, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "#") {
		return model.Target{}, false
	}
	// Drop a trailing inline comment, but not a URL fragment ("#foo" in a path).
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return model.Target{}, false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return model.Target{}, false
	}
	base := u.Scheme + "://" + u.Host
	return model.Target{Input: raw, BaseURL: base, Host: u.Host}, true
}

// BuildTargets normalizes and de-duplicates a list of raw strings, preserving
// first-seen order.
func BuildTargets(raw []string) []model.Target {
	seen := make(map[string]struct{}, len(raw))
	out := make([]model.Target, 0, len(raw))
	for _, r := range raw {
		t, ok := Normalize(r)
		if !ok {
			continue
		}
		if _, dup := seen[t.BaseURL]; dup {
			continue
		}
		seen[t.BaseURL] = struct{}{}
		out = append(out, t)
	}
	return out
}
