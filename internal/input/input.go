// Package input gathers raw target strings from CLI args, files (.txt/.csv) and
// piped stdin. Normalization and de-duplication happen later in the scanner.
package input

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
)

// headerAliases are column names that mark the target column in a CSV header.
var headerAliases = map[string]bool{
	"url": true, "domain": true, "host": true, "target": true, "asset": true, "scope": true,
}

// Collect returns raw target strings from positional args, each file path, and
// stdin (only when stdin is non-nil, i.e. the caller detected a pipe).
func Collect(args []string, files []string, stdin io.Reader) ([]string, error) {
	var raw []string
	raw = append(raw, args...)

	for _, f := range files {
		lines, err := readFile(f)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f, err)
		}
		raw = append(raw, lines...)
	}

	if stdin != nil {
		lines, err := readLines(stdin)
		if err != nil {
			return nil, fmt.Errorf("reading stdin: %w", err)
		}
		raw = append(raw, lines...)
	}
	return raw, nil
}

func readFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if strings.HasSuffix(strings.ToLower(path), ".csv") {
		return readCSV(f)
	}
	return readLines(f)
}

// readLines returns non-blank, non-comment lines.
func readLines(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// readCSV extracts the target column: a header alias column if present,
// otherwise the first column.
func readCSV(r io.Reader) ([]string, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1 // tolerate ragged rows
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}

	col, hasHeader := 0, false
	for i, cell := range rows[0] {
		if headerAliases[strings.ToLower(strings.TrimSpace(cell))] {
			col, hasHeader = i, true
			break
		}
	}

	start := 0
	if hasHeader {
		start = 1
	}
	var out []string
	for _, row := range rows[start:] {
		if col >= len(row) {
			continue
		}
		v := strings.TrimSpace(row[col])
		if v == "" || strings.HasPrefix(v, "#") {
			continue
		}
		out = append(out, v)
	}
	return out, nil
}
