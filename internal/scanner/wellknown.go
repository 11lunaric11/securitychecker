package scanner

import (
	"context"

	"github.com/11lunaric11/securitychecker/internal/model"
)

// wellKnownPaths is a curated list of standardized /.well-known/ URIs that are
// useful for fingerprinting a target's stack (auth, mobile apps, mail policy,
// federation). security.txt is intentionally omitted here — it has its own
// dedicated check.
var wellKnownPaths = []string{
	"/.well-known/change-password",
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
	"/.well-known/assetlinks.json",
	"/.well-known/apple-app-site-association",
	"/.well-known/mta-sts.txt",
	"/.well-known/host-meta",
	"/.well-known/webfinger",
	"/.well-known/dnt-policy.txt",
	"/.well-known/gpc.json",
	"/.well-known/nodeinfo",
	"/.well-known/ai-plugin.json",
	"/.well-known/traffic-advice",
}

// probeWellKnown requests each curated path and records the ones that respond
// with a 200 or a redirect. 404s and transport errors are dropped to keep the
// output focused on what actually exists.
func (s *Scanner) probeWellKnown(ctx context.Context, base string) []model.WellKnownHit {
	var hits []model.WellKnownHit
	for _, p := range wellKnownPaths {
		fr, err := s.fetch(ctx, base+p)
		if err != nil {
			continue
		}
		if fr.status == 200 || (fr.status >= 300 && fr.status < 400) {
			hits = append(hits, model.WellKnownHit{
				Path:        p,
				URL:         base + p,
				Status:      fr.status,
				ContentType: fr.contentType,
				Found:       fr.status == 200,
			})
		}
		s.pause()
	}
	return hits
}
