package scanner

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/11lunaric11/securitychecker/internal/model"
)

// securityTxtLocations are tried in order: the RFC 9116 well-known path first,
// then the legacy root path.
var securityTxtLocations = []struct{ path, loc string }{
	{"/.well-known/security.txt", "well-known"},
	{"/security.txt", "legacy-root"},
}

var emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

// fetchSecurityTxt tries each known location and returns the first one that
// actually contains a security.txt. If none do, it returns the last observed
// status (so the caller can tell "404 everywhere" from "found").
func (s *Scanner) fetchSecurityTxt(ctx context.Context, base string) *model.SecurityTxt {
	var last *model.SecurityTxt
	for _, l := range securityTxtLocations {
		fr, err := s.fetch(ctx, base+l.path)
		if err != nil {
			continue
		}
		st := &model.SecurityTxt{URL: base + l.path, Status: fr.status, Location: l.loc}
		if fr.status == 200 && looksLikeSecurityTxt(fr.body) {
			st.Found = true
			parseSecurityTxt(st, fr.body)
			return st
		}
		last = st
	}
	if last == nil {
		return &model.SecurityTxt{Found: false}
	}
	return last
}

// looksLikeSecurityTxt confirms a 200 body is a real security.txt rather than a
// soft-404 HTML page, by requiring at least one recognised field or PGP header.
func looksLikeSecurityTxt(body []byte) bool {
	if looksLikeHTML(body) {
		return false
	}
	lower := strings.ToLower(string(body))
	if strings.Contains(lower, "-----begin pgp signed message-----") {
		return true
	}
	for _, k := range []string{"contact:", "expires:", "encryption:", "policy:", "acknowledgments:", "canonical:"} {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}

// parseSecurityTxt fills the struct from an RFC 9116 body. Keys are
// case-insensitive; a field may appear multiple times.
func parseSecurityTxt(st *model.SecurityTxt, body []byte) {
	text := string(body)
	if strings.Contains(text, "-----BEGIN PGP SIGNED MESSAGE-----") {
		st.Signed = true
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-----") ||
			strings.HasPrefix(line, "Hash:") || strings.HasPrefix(line, "Version:") {
			continue
		}
		key, val, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "contact":
			st.Contact = append(st.Contact, val)
			if e := extractEmail(val); e != "" {
				st.Emails = appendUnique(st.Emails, e)
			}
		case "expires":
			if st.Expires == "" {
				st.Expires = val
			}
		case "encryption":
			st.Encryption = append(st.Encryption, val)
		case "acknowledgments", "acknowledgements":
			st.Acknowledgments = append(st.Acknowledgments, val)
		case "preferred-languages":
			st.PreferredLanguages = append(st.PreferredLanguages, val)
		case "canonical":
			st.Canonical = append(st.Canonical, val)
		case "policy":
			st.Policy = append(st.Policy, val)
		case "hiring":
			st.Hiring = append(st.Hiring, val)
		case "csaf":
			st.CSAF = append(st.CSAF, val)
		}
	}
	st.ExpiryState = expiryState(st.Expires)
}

func extractEmail(v string) string {
	v = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(v), "mailto:"))
	return emailRe.FindString(v)
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// expiryState classifies the RFC 9116 Expires field (which is required).
// RFC 3339 permits a lowercase "t"/"z", which Go's canonical layouts reject, so
// the value is upper-cased before parsing.
func expiryState(raw string) string {
	if raw == "" {
		return "missing"
	}
	norm := strings.ToUpper(strings.TrimSpace(raw))
	for _, layout := range []string{time.RFC3339, time.RFC3339Nano} {
		if t, err := time.Parse(layout, norm); err == nil {
			if t.Before(time.Now()) {
				return "expired"
			}
			return "valid"
		}
	}
	return "invalid"
}
