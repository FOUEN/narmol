# Narmol

Narmol is a wrapper tool written in Go that bundles multiple security tools into a single binary. It provides a unified interface for running tools like nuclei, httpx, subfinder, amass, and others, as well as executing custom workflows with mandatory scope enforcement.

## Installation

### Option A: From source (recommended)

```bash
git clone https://github.com/FOUEN/narmol.git
cd narmol
go run . update
```

This clones all tool repos, patches them, and builds the final binary automatically.

### Option B: `go install`

```bash
go install -tags bootstrap github.com/FOUEN/narmol@v0.1.0
narmol update
```

The first command installs a **bootstrap binary** (without tools compiled in — only the `update` command works). Then `narmol update`:
1. Clones the narmol source to `~/.narmol/src/`
2. Downloads and patches all tool repos
3. Rebuilds the binary with all tools compiled in
4. Replaces the bootstrap binary automatically

### Updating

To update all tools to their latest versions later:

```bash
narmol update
```

> **Requirements**: Go 1.24+ and Git must be installed.

## Project Structure

- main.go: Entry point of the application.
- go.work: Go workspace configuration.
- tools/: Contains the source code for bundled tools (amass, dnsx, gau, httpx, katana, nuclei, subfinder, wappalyzergo).
- workflows/: Contains the workflow registry and implementations.
  - registry.go: Interface and registry for workflows.
  - active/: Implementation of the "active" workflow.
- scope/: Middleware package for handling scope parsing and matching.

## Tools

You can run individual tools directly using the narmol binary:

- amass
- nuclei
- httpx
- katana
- dnsx
- subfinder
- gau

Example:
narmol subfinder -d example.com

## Workflows

Workflows are predefined sequences of tools that automate specific tasks. All workflows require a scope file to be defined.

Usage:
narmol workflow <name> --scope <scope_file> [-o <output_dir>]

Available workflows:
- active: Finds all subdomains using subfinder and checks which are active (alive) using httpx. output is in JSON format.

## Scope System

The scope system enforces which targets can be audited. It supports wildcards and exclusions. Exclusions always take priority over inclusions.

Flag: --scope (or -s)

Scope File Format Example (scope.txt):
# Wildcard: all subdomains of example.com
*.example.com

# Explicit domain
api.otherdomain.com

# Exclusions (prefixed with -)
-admin.example.com
-*.staging.example.com

## Building

To build the project, run:
go build -o narmol.exe .
