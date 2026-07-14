// SecurityChecker — paste or upload a list of URLs and check each one for
// robots.txt, security.txt (RFC 9116) and a curated set of /.well-known/ paths.
//
// Usage:
//
//	securitychecker scan example.com github.com
//	securitychecker scan -f targets.txt --json | jq .
//	cat urls.csv | securitychecker scan --csv -o report.csv
//	securitychecker serve --port 8080
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/11lunaric11/securitychecker/internal/input"
	"github.com/11lunaric11/securitychecker/internal/output"
	"github.com/11lunaric11/securitychecker/internal/scanner"
	"github.com/11lunaric11/securitychecker/internal/web"
)

// version is overridden at release time via -ldflags "-X main.version=...".
var version = "1.0.0"

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	switch args[0] {
	case "-h", "--help", "help":
		usage()
	case "-v", "--version", "version":
		fmt.Println("securitychecker " + version)
	case "serve":
		if err := runServe(args[1:]); err != nil {
			fatal(err)
		}
	case "scan":
		if err := runScan(args[1:]); err != nil {
			fatal(err)
		}
	default:
		// No subcommand: treat everything as scan arguments.
		if err := runScan(args); err != nil {
			fatal(err)
		}
	}
}

// stringSlice is a flag.Value that accumulates repeated -f flags.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func runScan(argv []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	var files stringSlice
	fs.Var(&files, "f", "target list file (.txt or .csv); repeatable")
	asJSON := fs.Bool("json", false, "output JSON")
	asCSV := fs.Bool("csv", false, "output CSV")
	outPath := fs.String("o", "", "write output to file instead of stdout")
	concurrency := fs.Int("concurrency", 10, "max concurrent targets")
	timeout := fs.Duration("timeout", 10*time.Second, "per-request timeout")
	delay := fs.Duration("delay", 0, "pause between requests to one host")
	wellKnown := fs.Bool("wellknown", true, "probe the /.well-known/ path list")
	userAgent := fs.String("user-agent", scanner.DefaultUserAgent, "User-Agent header")
	noColor := fs.Bool("no-color", false, "disable colored output")
	targetArgs, err := parseArgs(fs, argv)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *noColor {
		output.SetColor(false)
	}

	// Read stdin only as a fallback when no targets were given as args or files.
	// Keep it a true nil io.Reader interface (not a typed nil *os.File) so the
	// nil check inside Collect works.
	var stdin io.Reader
	if len(targetArgs) == 0 && len(files) == 0 {
		if f := stdinIfPiped(); f != nil {
			stdin = f
		}
	}
	raw, err := input.Collect(targetArgs, files, stdin)
	if err != nil {
		return err
	}
	targets := scanner.BuildTargets(raw)
	if len(targets) == 0 {
		return fmt.Errorf("no valid targets — pass URLs as arguments, with -f <file>, or via stdin")
	}

	fmt.Fprintf(os.Stderr, "Scanning %d target(s)…\n", len(targets))
	sc := scanner.New(scanner.Options{
		Concurrency:    *concurrency,
		Timeout:        *timeout,
		Delay:          *delay,
		UserAgent:      *userAgent,
		ProbeWellKnown: *wellKnown,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	results := sc.ScanAll(ctx, targets)

	w := os.Stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	switch {
	case *asJSON:
		return output.RenderJSON(w, results)
	case *asCSV:
		return output.RenderCSV(w, results)
	default:
		output.RenderTable(w, results)
		return nil
	}
}

func runServe(argv []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	port := fs.Int("port", 8080, "port to listen on")
	concurrency := fs.Int("concurrency", 10, "max concurrent targets per request")
	timeout := fs.Duration("timeout", 10*time.Second, "per-request timeout")
	wellKnown := fs.Bool("wellknown", true, "probe the /.well-known/ path list")
	userAgent := fs.String("user-agent", scanner.DefaultUserAgent, "User-Agent header")
	if _, err := parseArgs(fs, argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	srv := web.NewServer(scanner.Options{
		Concurrency:    *concurrency,
		Timeout:        *timeout,
		UserAgent:      *userAgent,
		ProbeWellKnown: *wellKnown,
	})
	addr := fmt.Sprintf(":%d", *port)
	fmt.Fprintln(os.Stderr, web.Banner(addr))
	return srv.ListenAndServe(addr)
}

// stdinIfPiped returns os.Stdin only when it is a real pipe ("cat x | tool") or
// a redirected file ("tool < list.txt"). For an interactive terminal, /dev/null
// or any other fd type it returns nil, so the scanner never blocks or errors on
// an unreadable stdin.
func stdinIfPiped() *os.File {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return nil
	}
	m := fi.Mode()
	if m&os.ModeNamedPipe != 0 || m.IsRegular() {
		return os.Stdin
	}
	return nil
}

// parseArgs parses flags that may be interspersed with positional arguments,
// which Go's flag package does not support out of the box (it stops at the first
// non-flag). Returns the collected positional arguments (targets).
func parseArgs(fs *flag.FlagSet, argv []string) ([]string, error) {
	var positionals []string
	for {
		if err := fs.Parse(argv); err != nil {
			return nil, err
		}
		rem := fs.Args()
		if len(rem) == 0 {
			break
		}
		positionals = append(positionals, rem[0])
		argv = rem[1:]
	}
	return positionals, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error: "+err.Error())
	os.Exit(1)
}

func usage() {
	fmt.Print(`SecurityChecker ` + version + ` — robots.txt / security.txt / .well-known recon

USAGE
  securitychecker scan  [flags] [targets...]
  securitychecker serve [flags]

SCAN FLAGS
  -f <file>          target list (.txt or .csv), repeatable
  --json             output JSON
  --csv              output CSV
  -o <file>          write output to a file
  --concurrency N    max concurrent targets (default 10)
  --timeout D        per-request timeout (default 10s)
  --delay D          pause between requests to one host
  --wellknown        probe /.well-known/ list (default true; use --wellknown=false to skip)
  --user-agent S     custom User-Agent
  --no-color         disable colored output

SERVE FLAGS
  --port N           listen port (default 8080)
  --concurrency N    max concurrent targets per request
  --timeout D        per-request timeout

EXAMPLES
  securitychecker scan example.com github.com
  securitychecker scan -f targets.txt --json | jq .
  cat urls.csv | securitychecker scan --csv -o report.csv
  securitychecker serve --port 8080

Only run this against systems you are authorized to test.
`)
}
