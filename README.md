# Narmol

All-in-one security reconnaissance engine. One binary, 9 tools compiled as Go libraries, scope-enforced workflows.

Narmol is the core engine of **Marmol** — everything runs in-process as native Go function calls, no subprocesses.

## Install

```bash
git clone https://github.com/FOUEN/narmol.git
cd narmol
go run . update
```

This clones all 9 tool repositories, patches them into importable Go packages, and builds a single `narmol` binary.

> **Requirements**: Go 1.24+ and Git.

## Update

```bash
narmol update
```

Pulls latest tool sources, re-patches, and recompiles in-place.

---

## Tools (9)

Every tool is compiled into the binary and can be used directly with its native CLI flags:

```
narmol subfinder -d example.com
narmol httpx -l hosts.txt
narmol nuclei -u https://example.com
narmol katana -u https://example.com
narmol dnsx -l domains.txt
narmol naabu -host 10.0.0.1
narmol gau example.com
narmol trufflehog git https://github.com/org/repo
```

| Tool | Purpose |
|------|---------|
| **subfinder** | Passive subdomain enumeration |
| **httpx** | HTTP probing, tech detection, alive check |
| **nuclei** | Vulnerability scanning with templates |
| **katana** | Web crawling (robots.txt, sitemap, JS) |
| **dnsx** | DNS resolution and brute-force |
| **naabu** | Port scanning (SYN/CONNECT) |
| **gau** | Historical URL collection (Wayback, CommonCrawl, OTX, URLScan) |
| **trufflehog** | Secret scanning (800+ detectors for API keys, tokens, passwords) |
| **wappalyzergo** | Technology fingerprinting (library, used by httpx) |

---

## Workflows

Automated tool chains with mandatory scope enforcement. Each workflow receives a scope file and orchestrates multiple tools as Go library calls.

```
narmol workflow <name> -s <scope.txt> [-o [file]] [-oj [file]]
```

- `-s` — scope file (required)
- `-o` — text output file (optional, defaults to `<workflow>.txt`)
- `-oj` — JSON output file (optional, defaults to `<workflow>.json`)

### `recon` — Passive Reconnaissance

Discovers subdomains and historical URLs **without touching the target**. Only queries external data sources.

Recursive subfinder and gau run **in parallel** for faster results.

```
narmol workflow recon -s scope.txt -oj recon.json
```

**Pipeline:**

1. **Subfinder** — passive subdomain enumeration (only if scope has wildcard `*.example.com`)
2. **Recursive subfinder** — feeds discovered subdomains back to find deeper levels (e.g. `sub.sub.example.com`)
3. **Gau** — collects historical URLs from Wayback Machine, Common Crawl, OTX, URLScan

**Behavior:**
- Wildcard scope (`*.example.com`): runs all 3 steps
- Exact scope (`example.com`): skips subfinder, only runs gau
- Global deduplication across all steps
- Every result is scope-filtered before output

**JSON output:**
```json
{"type":"subdomain","value":"api.example.com","source":"subfinder","domain":"example.com"}
{"type":"url","value":"https://api.example.com/v1/users","source":"gau","domain":"example.com"}
```

### `active` — Subdomain Discovery + Alive Check

Finds all subdomains and probes which ones have an active web service.

```
narmol workflow active -s scope.txt -oj active.json
```

**Pipeline:**

1. **Subfinder** — discovers subdomains, filters through scope
2. **httpx** — probes all in-scope hosts (follow redirects, tech detection, CDN detection)

**Requirements:** Wildcard scope (`*.example.com`) — exact domains won't trigger subdomain enumeration.

**JSON output:**
```json
{"url":"https://api.example.com","host":"api.example.com","status_code":200,"title":"API","tech":["nginx","React"],"cdn":false}
```

### `web` — Full Web Audit

Complete web audit using a Nessus-style approach: fingerprint first, then run only relevant vulnerability checks.

```
narmol workflow web -s scope.txt -oj web.json
```

**Pipeline:**

1. **Subfinder** — discovers subdomains (only if scope has wildcard `*.example.com`)
2. **httpx** — probes all hosts for live web services + **fingerprints the tech stack**
3. **In parallel (goroutines):**
   - **Nuclei** — targeted vulnerability scan (only templates matching detected tech)
   - **TruffleHog** — checks for exposed `.git/HEAD` → if found, scans for leaked secrets
   - **Security headers** — checks missing HSTS, CSP, X-Frame-Options, CORS misconfig, insecure cookies (stdlib)
   - **SSL/TLS audit** — protocol version (flags TLS 1.0/1.1), weak ciphers, cert expiry, self-signed, hostname mismatch (stdlib)
   - **Open redirect** — tests 18 common redirect parameters with canary URL (stdlib)
   - **HTTP smuggling** — CL.TE and TE.CL detection via raw TCP sockets + timing (stdlib)

**Nessus-style optimization:**
- httpx detects technologies via wappalyzer → mapped to nuclei template tags
- Generic checks always run: `exposure`, `misconfig`, `default-login`, `takeover`, `config`
- Instead of running all 10,000+ nuclei templates, only relevant ones are loaded

**JSON output:**
```json
{"phase":"probe","value":"https://api.example.com","host":"api.example.com","status_code":200,"title":"API","tech":["nginx","PHP"],"cdn":false}
{"phase":"vuln","value":"https://api.example.com","template_id":"cve-2024-1234","vuln_name":"RCE","severity":"critical"}
{"phase":"secret","value":"https://api.example.com","severity":"critical","detail":"[AWS] AKIA****"}
{"phase":"header","value":"https://api.example.com","severity":"medium","detail":"Missing Strict-Transport-Security"}
{"phase":"tls","value":"https://api.example.com","severity":"high","detail":"TLS 1.0 supported (deprecated, vulnerable to BEAST/POODLE)"}
{"phase":"redirect","value":"https://api.example.com","severity":"medium","detail":"Open redirect via ?next= → https://evil.com/pwned (HTTP 302)"}
{"phase":"smuggling","value":"https://api.example.com","severity":"critical","detail":"Potential CL.TE HTTP request smuggling"}
```

### `secrets` — Secret Scanning

Scans for leaked secrets using TruffleHog's 800+ detectors (API keys, tokens, passwords, AWS credentials, etc.).

```
narmol workflow secrets -s scope.txt -oj secrets.json
```

**Supports:**
- Git repositories (by URL) — scans full commit history
- Filesystem paths — local directory scanning

**Auto-detection:** The target is classified automatically:
- URLs (`https://...`, `git@...`, `*.git`) → git scan
- Paths (`/`, `./`, `C:\`, `~`) → filesystem scan

**Public API** for use by other workflows:
- `secrets.ScanGitRepo(url)` — returns `[]secretResult`
- `secrets.ScanPath(path)` — returns `[]secretResult`

**JSON output:**
```json
{"type":"secret","detector_type":"AWS","verified":false,"redacted":"AKIA****","source":"git","target":"https://github.com/org/repo"}
```

---

## Scope

All workflows require a scope file. Exclusions always take priority over inclusions.

```
# scope.txt
*.example.com              # all subdomains + root
api.other.com              # exact domain
10.0.0.1                   # single IP
192.168.1.0/24             # CIDR range
-admin.example.com         # exclude specific subdomain
-*.staging.example.com     # exclude all staging subdomains
-10.0.0.5                  # exclude specific IP
```

**Rules:**
- `*.example.com` matches `example.com` + any subdomain at any depth
- Exclusions (prefixed with `-`) always win over inclusions
- URLs are stripped to their hostname before matching (protocol, port, path removed)
- IPs and CIDRs are supported natively
- Lines starting with `#` are comments
- Inline comments with ` #` are supported

---

## Architecture

```
narmol (single Go binary)
├── CLI dispatcher (tool passthrough / workflow / update)
├── Scope engine (wildcards, exclusions, IPs, CIDRs)
├── Workflow registry (init pattern, Run interface)
├── Tool registry (8 CLI passthroughs via Main())
└── Updater (git clone/pull + patch + go build)
    └── Only place where os/exec is used (git + go build)
```

**Key design principles:**
- All tools run as Go library calls — zero subprocesses
- Go workspace (`go.work`) unites 9 tool modules
- Tools are patched: `package main` → `package <name>`, `func main()` → `func Main()`
- Workflows use programmatic APIs (runners, callbacks, channels) not CLI wrapping
- Scope is enforced at every step of every workflow
