package output

import (
	"os"
	"strings"
)

// ANSI helpers. Color is disabled when stdout is not a TTY or NO_COLOR is set.
const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	dim    = "\x1b[2m"
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	blue   = "\x1b[34m"
	cyan   = "\x1b[36m"
	gray   = "\x1b[90m"
)

var colorEnabled = detectColor()

// detectColor enables color only when stdout is a character device (a TTY) and
// NO_COLOR is not set. Uses stdlib only — no x/sys dependency.
func detectColor() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// SetColor lets callers (e.g. tests, or the --no-color flag) force color on/off.
func SetColor(on bool) { colorEnabled = on }

func colorize(code, s string) string {
	if !colorEnabled || code == "" {
		return s
	}
	return code + s + reset
}

// vlen is the visible width of s, ignoring ANSI escape sequences.
func vlen(s string) int {
	n, inEsc := 0, false
	for _, r := range s {
		switch {
		case r == '\x1b':
			inEsc = true
		case inEsc:
			if r == 'm' {
				inEsc = false
			}
		default:
			n++
		}
	}
	return n
}

// padRight pads s with spaces to visible width w.
func padRight(s string, w int) string {
	if d := w - vlen(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// truncate shortens plain text to max runes, adding an ellipsis.
func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 1 {
		return string(r[:max])
	}
	return string(r[:max-1]) + "…"
}
