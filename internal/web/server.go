// Package web serves a small self-contained UI that reuses the scanner engine.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/11lunaric11/securitychecker/internal/model"
	"github.com/11lunaric11/securitychecker/internal/scanner"
)

//go:embed static/index.html
var staticFS embed.FS

// maxTargets caps how many targets a single web request may scan, so the public
// endpoint can't be turned into a bulk relay.
const maxTargets = 200

// Server wraps an *http.Server plus the scanner options used per request.
type Server struct {
	opts scanner.Options
}

// NewServer builds a web server that scans with the given options.
func NewServer(opts scanner.Options) *Server {
	return &Server{opts: opts}
}

type scanRequest struct {
	Input     string `json:"input"`
	WellKnown *bool  `json:"wellknown"`
}

type scanResponse struct {
	Count     int            `json:"count"`
	Truncated bool           `json:"truncated"`
	Results   []model.Result `json:"results"`
}

// Handler returns the HTTP router (exposed for testing / custom hosting).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/scan", s.handleScan)
	return mux
}

// ListenAndServe starts the server on addr (e.g. ":8080").
func (s *Server) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	page, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "index unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(page)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req scanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	raw := splitLines(req.Input)
	targets := scanner.BuildTargets(raw)
	truncated := false
	if len(targets) > maxTargets {
		targets = targets[:maxTargets]
		truncated = true
	}

	opts := s.opts
	if req.WellKnown != nil {
		opts.ProbeWellKnown = *req.WellKnown
	}
	sc := scanner.New(opts)

	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	results := sc.ScanAll(ctx, targets)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(scanResponse{
		Count:     len(results),
		Truncated: truncated,
		Results:   results,
	}); err != nil {
		log.Printf("web: encode response: %v", err)
	}
}

// splitLines breaks pasted textarea content into candidate target strings.
func splitLines(s string) []string {
	var out []string
	line := make([]rune, 0, 64)
	flush := func() {
		if len(line) > 0 {
			out = append(out, string(line))
			line = line[:0]
		}
	}
	for _, r := range s {
		switch r {
		case '\n', '\r', ',', ' ', '\t':
			flush()
		default:
			line = append(line, r)
		}
	}
	flush()
	return out
}

// Banner is the human-readable startup line printed by the CLI.
func Banner(addr string) string {
	return fmt.Sprintf("SecurityChecker web UI → http://localhost%s", addr)
}
