# Narmol

All-in-one security toolkit. One binary, multiple tools, scope-enforced workflows.

## Install

```bash
git clone https://github.com/FOUEN/narmol.git
cd narmol
CGO_ENABLED=0 go run . update
```

This downloads all tools, patches them, and builds the `narmol` binary. Done.

> **Requirements**: Go 1.24+ and Git.

## Update

```bash
narmol update
```

## Tools

Run any tool directly:

```
narmol subfinder -d example.com
narmol nuclei -u https://example.com
narmol httpx -l hosts.txt
narmol katana -u https://example.com
narmol dnsx -l domains.txt
narmol amass enum -d example.com
narmol gau example.com
```

## Workflows

Automated tool chains with mandatory scope enforcement.

```
narmol workflow <name> -s <scope.txt> [-o [file]] [-oj [file]]
```

### active

Finds subdomains (subfinder) and probes which are alive (httpx).

```
narmol workflow active -s scope.txt -oj results.json
```

## Scope

All workflows require a scope file. Exclusions always take priority.

```
# scope.txt
*.example.com
api.other.com
-admin.example.com
-*.staging.example.com
```
