# Narmol - Project Context & Architecture

This document provides a comprehensive overview of the **Narmol** project, its architecture, and the recent structural changes made to improve its robustness and usability.

---

## 1. Project Overview
**Narmol** is a Go-based wrapper and orchestrator for various security and reconnaissance tools (primarily from ProjectDiscovery and the broader community). It allows running complex workflows, managing dependencies locally, and enforcing scope constraints.

### Core Goals:
- **Orchestration**: Run tools like `subfinder`, `httpx`, and `nuclei` in a sequence (workflows).
- **Scope Enforcement**: Ensure no targets outside of the predefined scope are touched.
- **Dependency Management**: Maintain local copies of tools and keep them updated/patched.
- **Flexible Output**: Support text, JSON, and terminal output.

---

## 2. Project Structure
```text
.
├── go.mod / go.sum          # Go module definitions
├── go.work                  # Go Workspace (manages local /tools/ as modules)
├── main.go                  # Entry point (CLI parsing, Command dispatch)
├── scope/                   # Scope parsing and enforcement logic
│   ├── scope.go
│   └── scope_test.go
├── workflows/               # Workflow registry and interface
│   ├── registry.go          # Workflow interface and registration
│   └── active/              # 'active' workflow implementation
│       └── active.go
└── tools/                   # Local tool repositories (cloned/patched)
    ├── dnsx, httpx, nuclei, subfinder, katana, gau, wappalyzergo...
```

---

## 3. Key Components

### A. The `main.go` (The Brain)
Handles three primary modes:
1.  **Tool Passthrough**: Runs a specific tool with raw arguments (e.g., `narmol nuclei -t ...`). It imports the tool's `Main()` function directly.
2.  **`update` Command**: Updates all local tools in `tools/` using Git (fetch/reset or clone). It then automatically **patches** the tools to make them importable as libraries.
3.  **`workflow` Command**: Orchestrates a series of steps (e.g., `active` workflow). It parses `-s` (scope), `-o` (text output), and `-oj` (JSON output).

### B. Scope Management (`/scope`)
The scope determines what domains and subdomains are allowed.
- **Rules**: Supports inclusion (default) and exclusion (prefix with `-`).
- **Wildcards**: Supports `*.example.com` (covers the root and all subdomains).
- **Parsing**: Can load rules from a file **or** directly from the CLI argument (comma-separated).
- **Validation**: Enforces that enumeration workflows (like `active`) **must** have a wildcard scope to prevent accidental scanning of unrelated hosts.

### C. Workflows (`/workflows`)
Workflows implement the `Workflow` interface:
```go
type Workflow interface {
    Name() string
    Description() string
    Run(domain string, s *scope.Scope, opts OutputOptions) error
}
```
The **`active` workflow** is currently the primary implementation:
1.  Verifies the domain is in scope and has a wildcard rule.
2.  Runs `subfinder` to discover subdomains (in a temp directory).
3.  Filters discovered subdomains against the global scope.
4.  Runs `httpx` on the filtered list to find alive hosts.
5.  Outputs results to Text, JSON, or Stdout as requested.

---

## 4. Special Features

### The Patching System
Since most tool CLI entry points are defined as `package main`, they cannot be imported in Go. The `narmol update` command fixes this by:
- Modifying the tool's `main.go` to use `package <toolname>`.
- Renaming `func main()` to `func Main()`.
- Stripping conflicting test files (e.g., `nuclei` benchmark tests) that would break the build.

### Flexible Output Logic
The output system is designed for both human readability and automation:
- **Default**: Results go to Stdout for quick inspection.
- **File Output**: Using `-o` or `-oj` creates files. If no domain is provided after the flag, it uses the workflow name (e.g., `active.txt`).
- **Append Mode**: When running for multiple target domains in a single scope, the results are appended to the output files instead of overwriting, allowing for consolidated reports.

---

## 5. Usage Lifecycle
1.  **Initialize/Update**: `narmol update` (Ensures tools are present and patched).
2.  **Build**: `go build .` (Compiles the orchestrator with tools inside).
3.  **Run**:
    - `narmol workflow active -s example.com,*.example.com` (Direct scope).
    - `narmol workflow active -s scope.txt -o results.txt` (File-based scope and output).
