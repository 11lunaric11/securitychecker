// Package model holds the data structures shared by the scanner, the CLI
// output formatters and the web server. Keeping them in one dependency-free
// package avoids import cycles between scanner/input/output/web.
package model

// Target is a single normalized scan target.
type Target struct {
	Input   string `json:"input"`    // the raw string the user provided
	BaseURL string `json:"base_url"` // normalized scheme://host[:port]
	Host    string `json:"host"`     // host[:port]
}

// Result is everything discovered for one target.
type Result struct {
	Target      string         `json:"target"`
	BaseURL     string         `json:"base_url"`
	Error       string         `json:"error,omitempty"`
	Robots      *RobotsInfo    `json:"robots,omitempty"`
	SecurityTxt *SecurityTxt   `json:"security_txt,omitempty"`
	WellKnown   []WellKnownHit `json:"well_known,omitempty"`
	DurationMS  int64          `json:"duration_ms"`
}

// RobotsInfo captures the recon-relevant parts of a robots.txt file.
type RobotsInfo struct {
	Found      bool     `json:"found"`
	Status     int      `json:"status"`
	URL        string   `json:"url"`
	UserAgents []string `json:"user_agents,omitempty"`
	Disallow   []string `json:"disallow,omitempty"`
	Allow      []string `json:"allow,omitempty"`
	Sitemaps   []string `json:"sitemaps,omitempty"`
	CrawlDelay string   `json:"crawl_delay,omitempty"`
}

// SecurityTxt captures the RFC 9116 fields of a security.txt file.
type SecurityTxt struct {
	Found              bool     `json:"found"`
	Status             int      `json:"status"`
	URL                string   `json:"url"`                    // where it was actually found
	Location           string   `json:"location,omitempty"`     // "well-known" | "legacy-root"
	Signed             bool     `json:"signed"`                 // wrapped in a PGP signature
	Contact            []string `json:"contact,omitempty"`      // raw Contact: values
	Emails             []string `json:"emails,omitempty"`       // e-mails extracted from contacts
	Expires            string   `json:"expires,omitempty"`      // raw Expires: value
	ExpiryState        string   `json:"expiry_state,omitempty"` // valid | expired | invalid | missing
	Encryption         []string `json:"encryption,omitempty"`
	Acknowledgments    []string `json:"acknowledgments,omitempty"`
	PreferredLanguages []string `json:"preferred_languages,omitempty"`
	Canonical          []string `json:"canonical,omitempty"`
	Policy             []string `json:"policy,omitempty"`
	Hiring             []string `json:"hiring,omitempty"`
	CSAF               []string `json:"csaf,omitempty"`
}

// WellKnownHit is one probed /.well-known/ path that responded.
type WellKnownHit struct {
	Path        string `json:"path"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	Found       bool   `json:"found"` // true when status == 200
}
