package output

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"

	"github.com/11lunaric11/securitychecker/internal/model"
)

// csvHeader defines the flattened columns used for spreadsheet/report export.
var csvHeader = []string{
	"target", "base_url", "error",
	"robots_found", "robots_disallow_count", "robots_sitemaps",
	"securitytxt_found", "securitytxt_location", "securitytxt_url",
	"securitytxt_expires", "securitytxt_expiry_state", "securitytxt_signed",
	"emails", "policy", "wellknown_hits",
}

// RenderCSV writes one row per result with list fields joined by " | ".
func RenderCSV(w io.Writer, results []model.Result) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, r := range results {
		row := []string{
			r.Target,
			r.BaseURL,
			r.Error,
			boolStr(r.Robots != nil && r.Robots.Found),
			robotsDisallowCount(r),
			joinRobotsSitemaps(r),
			boolStr(r.SecurityTxt != nil && r.SecurityTxt.Found),
			secField(r, func(s *model.SecurityTxt) string { return s.Location }),
			secField(r, func(s *model.SecurityTxt) string { return s.URL }),
			secField(r, func(s *model.SecurityTxt) string { return s.Expires }),
			secField(r, func(s *model.SecurityTxt) string { return s.ExpiryState }),
			boolStr(r.SecurityTxt != nil && r.SecurityTxt.Signed),
			secList(r, func(s *model.SecurityTxt) []string { return s.Emails }),
			secList(r, func(s *model.SecurityTxt) []string { return s.Policy }),
			joinWellKnown(r),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func robotsDisallowCount(r model.Result) string {
	if r.Robots == nil {
		return "0"
	}
	return strconv.Itoa(len(r.Robots.Disallow))
}

func joinRobotsSitemaps(r model.Result) string {
	if r.Robots == nil {
		return ""
	}
	return strings.Join(r.Robots.Sitemaps, " | ")
}

func secField(r model.Result, f func(*model.SecurityTxt) string) string {
	if r.SecurityTxt == nil || !r.SecurityTxt.Found {
		return ""
	}
	return f(r.SecurityTxt)
}

func secList(r model.Result, f func(*model.SecurityTxt) []string) string {
	if r.SecurityTxt == nil || !r.SecurityTxt.Found {
		return ""
	}
	return strings.Join(f(r.SecurityTxt), " | ")
}

func joinWellKnown(r model.Result) string {
	var parts []string
	for _, h := range r.WellKnown {
		if h.Found {
			parts = append(parts, strings.TrimPrefix(h.Path, "/.well-known/"))
		}
	}
	return strings.Join(parts, " | ")
}
