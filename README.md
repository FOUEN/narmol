# Narmol

Security recon engine. One Go binary, 9 tools as libraries, scope-enforced workflows. Core engine of Marmol.

## Install

```
git clone https://github.com/FOUEN/narmol.git
cd narmol
go run . update
```

Requires Go 1.24+ and Git.

## Update

```
narmol update
```

## Tools

Run any tool directly with its native flags:

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

## Workflows

```
narmol workflow <name> -s scope.txt [-o [file]] [-oj [file]]
```

**recon** — Passive recon: subfinder (recursive) + gau. No target contact.

**active** — Subdomain discovery + httpx alive check with tech detection.

**web** — Full web audit (Nessus-style). Fingerprint → targeted nuclei + header/TLS/redirect/smuggling checks in parallel. Report-style output by phases.

**secrets** — TruffleHog secret scanning (git repos or filesystem).

**subdomains** — Recursive subfinder + dnsx resolution.

**alive** — httpx probe (status, title, webserver).

**techdetect** — Wappalyzergo fingerprinting per host.

**crawl** — Katana crawl (robots, sitemap, JS, depth 3).

**urls** — gau + katana in parallel.

**headers** — Missing security headers, CORS, cookies, TLS config.

**takeover** — CNAME check against 45+ vulnerable services.

**gitexpose** — .git exposure check + TruffleHog secret scan.

## Scope

```
*.example.com
api.other.com
192.168.1.0/24
-admin.example.com
```

Wildcards, exact domains, IPs, CIDRs. Exclusions (`-`) always win. All workflows enforce scope at every step.
