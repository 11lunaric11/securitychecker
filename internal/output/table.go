// Package output renders scan results as a terminal table, JSON, or CSV.
package output

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/11lunaric11/securitychecker/internal/model"
)

// maxDisallowList caps how many robots Disallow paths the detail view prints.
const maxDisallowList = 20

// RenderTable writes a summary table followed by a per-target detail section.
func RenderTable(w io.Writer, results []model.Result) {
	renderSummary(w, results)
	fmt.Fprintln(w)
	for _, r := range results {
		renderDetail(w, r)
	}
	renderFooter(w, results)
}

func renderSummary(w io.Writer, results []model.Result) {
	headers := []string{"TARGET", "ROBOTS", "SEC.TXT", "EXPIRES", "CONTACT", "WELL-KNOWN"}
	rows := make([][]string, 0, len(results))
	for _, r := range results {
		rows = append(rows, []string{
			colorize(bold, truncate(hostOf(r), 32)),
			robotsCell(r),
			secTxtCell(r),
			expiresCell(r),
			contactCell(r),
			wellKnownCell(r),
		})
	}

	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = vlen(h)
	}
	for _, row := range rows {
		for i, c := range row {
			if vlen(c) > widths[i] {
				widths[i] = vlen(c)
			}
		}
	}

	var b strings.Builder
	for i, h := range headers {
		b.WriteString(padRight(colorize(bold, h), widths[i]))
		if i < len(headers)-1 {
			b.WriteString("  ")
		}
	}
	fmt.Fprintln(w, b.String())

	sep := make([]string, len(headers))
	for i := range sep {
		sep[i] = strings.Repeat("─", widths[i])
	}
	fmt.Fprintln(w, colorize(gray, strings.Join(sep, "  ")))

	for _, row := range rows {
		b.Reset()
		for i, c := range row {
			b.WriteString(padRight(c, widths[i]))
			if i < len(row)-1 {
				b.WriteString("  ")
			}
		}
		fmt.Fprintln(w, b.String())
	}
}

func hostOf(r model.Result) string {
	if r.BaseURL != "" {
		return strings.TrimPrefix(strings.TrimPrefix(r.BaseURL, "https://"), "http://")
	}
	return r.Target
}

func robotsCell(r model.Result) string {
	if r.Error != "" {
		return colorize(red, "error")
	}
	if r.Robots != nil && r.Robots.Found {
		return colorize(green, fmt.Sprintf("yes (%d)", len(r.Robots.Disallow)))
	}
	return colorize(gray, "no")
}

func secTxtCell(r model.Result) string {
	if r.Error != "" || r.SecurityTxt == nil {
		return colorize(gray, "—")
	}
	if r.SecurityTxt.Found {
		loc := "wk"
		if r.SecurityTxt.Location == "legacy-root" {
			loc = "root"
		}
		return colorize(green, "yes") + colorize(dim, " ("+loc+")")
	}
	return colorize(gray, "no")
}

func expiresCell(r model.Result) string {
	if r.SecurityTxt == nil || !r.SecurityTxt.Found {
		return colorize(gray, "—")
	}
	switch r.SecurityTxt.ExpiryState {
	case "valid":
		return colorize(green, "valid")
	case "expired":
		return colorize(red, "EXPIRED")
	case "invalid":
		return colorize(yellow, "invalid")
	default:
		return colorize(yellow, "missing")
	}
}

func contactCell(r model.Result) string {
	if r.SecurityTxt == nil || !r.SecurityTxt.Found {
		return colorize(gray, "—")
	}
	var first string
	extra := 0
	switch {
	case len(r.SecurityTxt.Emails) > 0:
		first = r.SecurityTxt.Emails[0]
		extra = len(r.SecurityTxt.Emails) - 1
	case len(r.SecurityTxt.Contact) > 0:
		first = r.SecurityTxt.Contact[0]
		extra = len(r.SecurityTxt.Contact) - 1
	default:
		return colorize(gray, "—")
	}
	cell := colorize(cyan, truncate(first, 34))
	if extra > 0 {
		cell += colorize(dim, " +"+strconv.Itoa(extra))
	}
	return cell
}

func wellKnownCell(r model.Result) string {
	n := 0
	for _, h := range r.WellKnown {
		if h.Found {
			n++
		}
	}
	if n == 0 {
		return colorize(gray, "0")
	}
	return colorize(green, strconv.Itoa(n))
}

func renderDetail(w io.Writer, r model.Result) {
	// Only print a detail block when there is something worth showing.
	interesting := r.Error != "" ||
		(r.Robots != nil && r.Robots.Found && (len(r.Robots.Disallow) > 0 || len(r.Robots.Sitemaps) > 0)) ||
		(r.SecurityTxt != nil && r.SecurityTxt.Found) ||
		hasWellKnownHit(r)
	if !interesting {
		return
	}

	fmt.Fprintln(w, colorize(bold+blue, "▸ "+hostOf(r)))

	if r.Error != "" {
		fmt.Fprintln(w, "  "+colorize(red, "✗ error: ")+r.Error)
		fmt.Fprintln(w)
		return
	}

	if r.Robots != nil && r.Robots.Found && (len(r.Robots.Disallow) > 0 || len(r.Robots.Sitemaps) > 0) {
		fmt.Fprintf(w, "  %s %s\n", colorize(cyan, "robots.txt"),
			colorize(dim, fmt.Sprintf("(%d disallow, %d sitemaps)", len(r.Robots.Disallow), len(r.Robots.Sitemaps))))
		for i, d := range r.Robots.Disallow {
			if i >= maxDisallowList {
				fmt.Fprintf(w, "    %s\n", colorize(dim, fmt.Sprintf("… %d more", len(r.Robots.Disallow)-maxDisallowList)))
				break
			}
			fmt.Fprintf(w, "    Disallow: %s\n", d)
		}
		for _, sm := range r.Robots.Sitemaps {
			fmt.Fprintf(w, "    %s %s\n", colorize(yellow, "Sitemap:"), sm)
		}
	}

	if st := r.SecurityTxt; st != nil && st.Found {
		signed := ""
		if st.Signed {
			signed = colorize(dim, " [PGP-signed]")
		}
		fmt.Fprintf(w, "  %s %s%s\n", colorize(cyan, "security.txt"), colorize(dim, st.URL), signed)
		field(w, "Contact", st.Contact)
		if st.Expires != "" {
			fmt.Fprintf(w, "    %-20s %s %s\n", "Expires:", st.Expires, expiryTag(st.ExpiryState))
		}
		field(w, "Policy", st.Policy)
		field(w, "Encryption", st.Encryption)
		field(w, "Acknowledgments", st.Acknowledgments)
		field(w, "Preferred-Languages", st.PreferredLanguages)
		field(w, "Canonical", st.Canonical)
		field(w, "Hiring", st.Hiring)
		field(w, "CSAF", st.CSAF)
	}

	if hasWellKnownHit(r) {
		fmt.Fprintf(w, "  %s\n", colorize(cyan, ".well-known"))
		for _, h := range r.WellKnown {
			tag := colorize(green, strconv.Itoa(h.Status))
			if !h.Found {
				tag = colorize(yellow, strconv.Itoa(h.Status))
			}
			ct := ""
			if h.ContentType != "" {
				ct = colorize(dim, " "+truncate(h.ContentType, 30))
			}
			fmt.Fprintf(w, "    [%s] %s%s\n", tag, strings.TrimPrefix(h.Path, "/.well-known/"), ct)
		}
	}
	fmt.Fprintln(w)
}

func field(w io.Writer, name string, vals []string) {
	for _, v := range vals {
		fmt.Fprintf(w, "    %-20s %s\n", name+":", v)
	}
}

func expiryTag(state string) string {
	switch state {
	case "valid":
		return colorize(green, "(valid)")
	case "expired":
		return colorize(red, "(EXPIRED)")
	case "invalid":
		return colorize(yellow, "(unparseable)")
	default:
		return ""
	}
}

func hasWellKnownHit(r model.Result) bool {
	return len(r.WellKnown) > 0
}

func renderFooter(w io.Writer, results []model.Result) {
	var withSec, withRobots, errs int
	for _, r := range results {
		if r.Error != "" {
			errs++
			continue
		}
		if r.Robots != nil && r.Robots.Found {
			withRobots++
		}
		if r.SecurityTxt != nil && r.SecurityTxt.Found {
			withSec++
		}
	}
	fmt.Fprintln(w, colorize(gray, strings.Repeat("─", 50)))
	fmt.Fprintf(w, "%s scanned  ·  %s security.txt  ·  %s robots.txt  ·  %s errors\n",
		colorize(bold, strconv.Itoa(len(results))),
		colorize(green, strconv.Itoa(withSec)),
		colorize(green, strconv.Itoa(withRobots)),
		colorize(red, strconv.Itoa(errs)),
	)
}
