package scanner

import (
	"testing"

	"github.com/11lunaric11/securitychecker/internal/model"
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		in      string
		wantURL string
		wantOK  bool
	}{
		{"example.com", "https://example.com", true},
		{"https://x.com/path?q=1", "https://x.com", true},
		{"http://y.com:8080", "http://y.com:8080", true},
		{"  # comment", "", false},
		{"", "", false},
		{"not a url", "", false},
		{"ftp://z.com", "", false},
	}
	for _, c := range cases {
		got, ok := Normalize(c.in)
		if ok != c.wantOK {
			t.Errorf("Normalize(%q) ok=%v, want %v", c.in, ok, c.wantOK)
			continue
		}
		if ok && got.BaseURL != c.wantURL {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got.BaseURL, c.wantURL)
		}
	}
}

func TestBuildTargetsDedupes(t *testing.T) {
	got := BuildTargets([]string{"example.com", "https://example.com", "other.com"})
	if len(got) != 2 {
		t.Fatalf("want 2 unique targets, got %d: %+v", len(got), got)
	}
}

func TestParseSecurityTxt(t *testing.T) {
	body := []byte(`# a comment
Contact: mailto:security@example.com
Contact: https://example.com/report
Expires: 2030-01-01T00:00:00z
Encryption: https://example.com/pgp.txt
Policy: https://example.com/policy
Preferred-Languages: en, de
`)
	s := &model.SecurityTxt{}
	parseSecurityTxt(s, body)
	if len(s.Contact) != 2 {
		t.Errorf("want 2 contacts, got %d", len(s.Contact))
	}
	if len(s.Emails) != 1 || s.Emails[0] != "security@example.com" {
		t.Errorf("want email security@example.com, got %v", s.Emails)
	}
	// lowercase "z" timezone must still be recognized as valid (RFC 3339 allows it).
	if s.ExpiryState != "valid" {
		t.Errorf("want expiry valid, got %q", s.ExpiryState)
	}
	if len(s.Policy) != 1 {
		t.Errorf("want 1 policy, got %v", s.Policy)
	}
}

func TestExpiryState(t *testing.T) {
	cases := map[string]string{
		"":                     "missing",
		"2020-01-01T00:00:00Z": "expired",
		"2035-01-01T00:00:00Z": "valid",
		"2035-01-01T00:00:00z": "valid",
		"garbage":              "invalid",
	}
	for in, want := range cases {
		if got := expiryState(in); got != want {
			t.Errorf("expiryState(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseRobots(t *testing.T) {
	body := []byte(`User-agent: *
Disallow: /admin
Disallow: /admin
Allow: /public
Sitemap: https://x.com/sitemap.xml
# comment line
Crawl-delay: 10
`)
	r := &model.RobotsInfo{}
	parseRobots(r, body)
	if len(r.Disallow) != 1 { // duplicate removed
		t.Errorf("want 1 deduped disallow, got %v", r.Disallow)
	}
	if len(r.Sitemaps) != 1 || r.Sitemaps[0] != "https://x.com/sitemap.xml" {
		t.Errorf("want sitemap, got %v", r.Sitemaps)
	}
	if r.CrawlDelay != "10" {
		t.Errorf("want crawl-delay 10, got %q", r.CrawlDelay)
	}
}

func TestLooksLikeSecurityTxt(t *testing.T) {
	if looksLikeSecurityTxt([]byte("<html><body>404</body></html>")) {
		t.Error("HTML page should not look like security.txt")
	}
	if !looksLikeSecurityTxt([]byte("Contact: mailto:a@b.com")) {
		t.Error("real security.txt should be recognized")
	}
}
