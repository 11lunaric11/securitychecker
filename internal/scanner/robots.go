package scanner

import (
	"context"
	"strings"

	"github.com/11lunaric11/securitychecker/internal/model"
)

// fetchRobots retrieves and parses /robots.txt. It is also the per-target
// connectivity probe: on a transport-level failure over https it retries once
// over http and returns the base URL that actually worked so the remaining
// checks reuse the right scheme.
func (s *Scanner) fetchRobots(ctx context.Context, base, host string) (*model.RobotsInfo, string, error) {
	fr, err := s.fetch(ctx, base+"/robots.txt")
	if err != nil && strings.HasPrefix(base, "https://") {
		altBase := "http://" + host
		if fr2, err2 := s.fetch(ctx, altBase+"/robots.txt"); err2 == nil {
			fr, err, base = fr2, nil, altBase
		}
	}
	if err != nil {
		return nil, base, err
	}
	info := &model.RobotsInfo{URL: base + "/robots.txt", Status: fr.status}
	if fr.status == 200 && !looksLikeHTML(fr.body) {
		info.Found = true
		parseRobots(info, fr.body)
	}
	return info, base, nil
}

// parseRobots extracts user-agents, disallow/allow rules and sitemaps. It is
// deliberately lenient — malformed lines are skipped, never fatal.
func parseRobots(info *model.RobotsInfo, body []byte) {
	uaSet := map[string]struct{}{}
	for _, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if c := strings.IndexByte(line, '#'); c >= 0 { // trailing comment
			line = strings.TrimSpace(line[:c])
		}
		key, val, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		switch key {
		case "user-agent":
			if val != "" {
				if _, dup := uaSet[val]; !dup {
					uaSet[val] = struct{}{}
					info.UserAgents = append(info.UserAgents, val)
				}
			}
		case "disallow":
			if val != "" {
				info.Disallow = append(info.Disallow, val)
			}
		case "allow":
			if val != "" {
				info.Allow = append(info.Allow, val)
			}
		case "sitemap":
			if val != "" {
				info.Sitemaps = append(info.Sitemaps, val)
			}
		case "crawl-delay":
			if val != "" && info.CrawlDelay == "" {
				info.CrawlDelay = val
			}
		}
	}
	info.Disallow = dedupe(info.Disallow)
	info.Allow = dedupe(info.Allow)
	info.Sitemaps = dedupe(info.Sitemaps)
}

func dedupe(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// looksLikeHTML guards against servers that answer 200 with an HTML page (a
// "soft 404") instead of a real text file.
func looksLikeHTML(body []byte) bool {
	head := strings.ToLower(strings.TrimSpace(string(body)))
	if len(head) > 512 {
		head = head[:512]
	}
	return strings.HasPrefix(head, "<!doctype html") ||
		strings.HasPrefix(head, "<html") ||
		strings.Contains(head, "<head>") ||
		strings.Contains(head, "<body")
}
