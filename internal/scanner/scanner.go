// Package scanner fetches and parses robots.txt, security.txt (RFC 9116) and a
// curated set of /.well-known/ paths for a list of targets. Every request is a
// plain GET of a standardized, publicly served file — no fuzzing, no
// exploitation. It is safe to run against authorized targets.
package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/11lunaric11/securitychecker/internal/model"
)

// Options configures a Scanner.
type Options struct {
	Concurrency    int           // max targets scanned at once
	Timeout        time.Duration // per-request timeout
	Delay          time.Duration // optional pause between requests to one host
	UserAgent      string        // User-Agent header sent on every request
	MaxBody        int64         // cap on bytes read per response
	ProbeWellKnown bool          // whether to probe the /.well-known/ list
}

// DefaultUserAgent is used when Options.UserAgent is empty.
const DefaultUserAgent = "SecurityChecker/1.0 (+https://github.com/11lunaric11/securitychecker)"

// Scanner performs the scans. Create one with New and reuse it.
type Scanner struct {
	client *http.Client
	opts   Options
}

// New builds a Scanner with a shared, redirect-capped HTTP client.
func New(opts Options) *Scanner {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 10
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.MaxBody <= 0 {
		opts.MaxBody = 512 * 1024
	}
	if opts.UserAgent == "" {
		opts.UserAgent = DefaultUserAgent
	}
	client := &http.Client{
		Timeout: opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	return &Scanner{client: client, opts: opts}
}

// fetchResult is the trimmed-down response the parsers work with.
type fetchResult struct {
	status      int
	body        []byte
	contentType string
}

// fetch performs a single GET, reading at most MaxBody bytes of the body.
func (s *Scanner) fetch(ctx context.Context, rawurl string) (*fetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.opts.UserAgent)
	req.Header.Set("Accept", "*/*")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, s.opts.MaxBody))
	return &fetchResult{
		status:      resp.StatusCode,
		body:        body,
		contentType: resp.Header.Get("Content-Type"),
	}, nil
}

// ScanAll scans every target concurrently and returns results in input order.
func (s *Scanner) ScanAll(ctx context.Context, targets []model.Target) []model.Result {
	results := make([]model.Result, len(targets))
	sem := make(chan struct{}, s.opts.Concurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t model.Target) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = s.scanTarget(ctx, t)
		}(i, t)
	}
	wg.Wait()
	return results
}

func (s *Scanner) scanTarget(ctx context.Context, t model.Target) model.Result {
	start := time.Now()
	res := model.Result{Target: t.Input, BaseURL: t.BaseURL}

	// robots.txt doubles as the connectivity probe: if https fails at the
	// transport level we retry once over http and switch the base for the rest.
	robots, base, err := s.fetchRobots(ctx, t.BaseURL, t.Host)
	if err != nil {
		res.Error = cleanErr(err)
		res.DurationMS = time.Since(start).Milliseconds()
		return res
	}
	res.BaseURL = base
	res.Robots = robots

	s.pause()
	res.SecurityTxt = s.fetchSecurityTxt(ctx, base)

	if s.opts.ProbeWellKnown {
		s.pause()
		res.WellKnown = s.probeWellKnown(ctx, base)
	}

	res.DurationMS = time.Since(start).Milliseconds()
	return res
}

func (s *Scanner) pause() {
	if s.opts.Delay > 0 {
		time.Sleep(s.opts.Delay)
	}
}

// cleanErr shortens the noisy url.Error wrapper to just the underlying cause.
func cleanErr(err error) string {
	msg := err.Error()
	// "Get \"https://x/robots.txt\": dial tcp ...: no such host"
	if i := strings.Index(msg, "\": "); i >= 0 {
		msg = msg[i+3:]
	}
	return strings.TrimSpace(msg)
}
