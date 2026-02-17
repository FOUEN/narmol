# Narmol

Narmol is a wrapper tool written in Go that bundles multiple security tools into a single binary. It provides a unified interface for running tools like nuclei, httpx, subfinder, and others, as well as executing custom workflows with mandatory scope enforcement.

## Project Structure

- main.go: Entry point of the application.
- go.work: Go workspace configuration.
- tools/: Contains the source code for bundled tools (dnsx, gau, httpx, katana, nuclei, subfinder, wappalyzergo).
- workflows/: Contains the workflow registry and implementations.
  - registry.go: Interface and registry for workflows.
  - active/: Implementation of the "active" workflow.
- scope/: Middleware package for handling scope parsing and matching.

## Tools

You can run individual tools directly using the narmol binary:

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
