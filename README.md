# SecurityChecker

A fast recon helper for pentesters and bug bounty hunters. Paste or upload a list
of targets and, for each one, it checks the three standardized files worth looking
at first:

- **`/robots.txt`** — surfaces `Disallow` paths (often hidden endpoints / admin
  panels) and `Sitemap` URLs.
- **`security.txt`** (RFC 9116, at `/.well-known/security.txt` and the legacy
  `/security.txt`) — the security **Contact**, **Policy** link, **Expires**
  validity, encryption key, and more.
- **`/.well-known/`** — probes a curated list of registered URIs that fingerprint
  the stack (OIDC, mobile app links, mail security posture, federation, …).

It runs as a **CLI** (table / JSON / CSV) and ships an optional **local web UI**
(paste box + file upload) — both use the same engine and it's a single static Go
binary with **no third-party dependencies**.

> ⚠️ **Authorized use only.** Every request is a plain `GET` of a public,
> standardized file — no fuzzing, no exploitation. Only run it against systems you
> are permitted to test.

---

## Install

```bash
# from source (Go 1.23+)
git clone https://github.com/11lunaric11/securitychecker
cd securitychecker
go build -o securitychecker .

# or install straight from the module
go install github.com/11lunaric11/securitychecker@latest
```

## CLI usage

```bash
# scan a few targets
securitychecker scan example.com github.com cloudflare.com

# from a file (.txt one-per-line, or .csv with a url/domain column)
securitychecker scan -f targets.txt
securitychecker scan -f scope.csv --concurrency 20

# machine-readable output
securitychecker scan -f targets.txt --json | jq .
securitychecker scan -f targets.txt --csv -o report.csv

# from stdin
cat targets.txt | securitychecker scan
```

Example output:

```
TARGET       ROBOTS     SEC.TXT   EXPIRES  CONTACT                       WELL-KNOWN
github.com   yes (57)   yes (wk)  valid    https://hackerone.com/github  2
google.com   yes (173)  yes (wk)  valid    security@google.com           1
example.com  no         no        —        —                             0

▸ github.com
  robots.txt (57 disallow, 0 sitemaps)
    Disallow: /account-login
    Disallow: */tarball/
    …
  security.txt https://github.com/.well-known/security.txt
    Contact:  https://hackerone.com/github
    Expires:  2026-08-13T09:04:15Z (valid)
    Policy:   https://bounty.github.com
```

### Scan flags

| Flag              | Default | Description                                          |
|-------------------|---------|------------------------------------------------------|
| `-f <file>`       | —       | target list (`.txt`/`.csv`), repeatable              |
| `--json`          | false   | output JSON                                          |
| `--csv`           | false   | output CSV                                           |
| `-o <file>`       | stdout  | write output to a file                               |
| `--concurrency N` | 10      | max targets scanned at once                          |
| `--timeout D`     | 10s     | per-request timeout                                  |
| `--delay D`       | 0       | pause between requests to one host                   |
| `--wellknown`     | true    | probe the `/.well-known/` list (`--wellknown=false`) |
| `--user-agent S`  | —       | custom `User-Agent`                                  |
| `--no-color`      | false   | disable colored output                               |

## Web UI

```bash
securitychecker serve --port 8080
# open http://localhost:8080
```

Paste targets or upload a `.txt`/`.csv`, hit **Scan**, and get a sortable table
with expandable per-target detail plus **Copy JSON** / **Download CSV**.

## What gets reported

- **robots.txt** — found?, `Disallow`/`Allow` rules, `Sitemap` URLs, `Crawl-delay`.
- **security.txt** — all RFC 9116 fields (`Contact`, `Expires`, `Encryption`,
  `Acknowledgments`, `Preferred-Languages`, `Canonical`, `Policy`, `Hiring`,
  `CSAF`), extracted contact e-mails, `Expires` validity (valid / expired /
  invalid / **missing** — a common RFC violation), and whether the file is
  PGP-signed.
- **/.well-known/** — `change-password`, `openid-configuration`,
  `oauth-authorization-server`, `assetlinks.json`, `apple-app-site-association`,
  `mta-sts.txt`, `host-meta`, `webfinger`, `dnt-policy.txt`, `gpc.json`,
  `nodeinfo`, `ai-plugin.json`, `traffic-advice`.

## Development

```bash
go test ./...
go vet ./...
```

## Publishing your own fork

Before pushing, point the module path at your account:

```bash
go mod edit -module github.com/<your-username>/securitychecker
grep -rl 11lunaric11/securitychecker . | xargs sed -i 's#11lunaric11/securitychecker#<your-username>/securitychecker#g'
go build ./...
```

## License

MIT — see [LICENSE](LICENSE).
