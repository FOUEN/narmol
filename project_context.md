# Narmol — Contexto para edición de código

Este documento da contexto completo a un modelo de IA para editar código de narmol con confianza.

---

## 1. Qué es narmol

Un binario Go que compila 8 herramientas de seguridad externas dentro de sí mismo (no las llama via exec.Command), les añade scope enforcement y permite ejecutar workflows que encadenan herramientas.

---

## 2. Reglas absolutas

1. **NUNCA `exec.Command` para ejecutar una tool.** Las tools son repos clonados en `tools/`, parcheados para exponer `func Main()`, e importados como paquetes Go.
2. **Go Workspace obligatorio.** Cada tool en `tools/` tiene su propio `go.mod`. El fichero `go.work` los une.
3. **Patrón init() para registros.** Tools y workflows se registran en `init()` y se importan en `main.go` con `_`.
4. **Module path = `github.com/FOUEN/narmol`.** Paquetes internos bajo `internal/`.
5. **Build tags `bootstrap` / `!bootstrap`.** Ficheros que importan tools externas llevan `//go:build !bootstrap`.
6. **Scope siempre filtra.** Todo workflow recibe `*scope.Scope` y filtra antes de tocar la red.
7. **Output en modo append.** `os.O_APPEND|os.O_CREATE|os.O_WRONLY`.

---

## 3. Estructura del proyecto

```
narmol/
├── main.go                     # Entrypoint
├── go.mod                      # module github.com/FOUEN/narmol
├── go.work                     # Go Workspace (. + 8 tools)
├── README.md
├── project_context.md          # ESTE FICHERO
│
├── internal/                   # Paquetes internos (no importables externamente)
│   ├── cli/
│   │   ├── cli.go              # Run() dispatcher: "workflow", "update", o tool passthrough
│   │   ├── update.go           # RunUpdate() → updater.SelfUpdate()
│   │   ├── usage.go            # PrintUsage()
│   │   └── workflow.go         # RunWorkflow() — parsea flags -s, -o, -oj
│   │
│   ├── runner/
│   │   ├── registry.go         # Tool struct, Register(), Get(), List()
│   │   ├── tools.go            # [!bootstrap] init() registra 7 tools
│   │   └── tools_bootstrap.go  # [bootstrap] stub vacío
│   │
│   ├── scope/
│   │   └── scope.go            # Scope struct, Load(), IsInScope(), FilterHosts(), Domains()
│   │
│   ├── updater/
│   │   ├── updater.go          # ToolSource, DefaultTools(), UpdateAll(), fetchOrClone()
│   │   ├── patcher.go          # PatchTool(), PatchFile()
│   │   └── selfupdate.go       # SelfUpdate(), resolveSourceDir(), rebuildAndReplace()
│   │
│   └── workflows/
│       ├── registry.go         # Workflow interface, OutputOptions, Register(), Get(), List()
│       └── active/
│           ├── active.go           # [!bootstrap] ActiveWorkflow — subfinder→httpx via FIFO
│           └── active_bootstrap.go # [bootstrap] stub vacío
│
└── tools/                      # Repos clonados y parcheados (gestionados por narmol update)
    ├── amass/
    ├── dnsx/
    ├── gau/
    ├── httpx/
    ├── katana/
    ├── nuclei/
    ├── subfinder/
    └── wappalyzergo/
```

---

## 4. Sistema de build tags (bootstrap)

`go install` no soporta `go.work`. Sin workspace, los imports de tools resuelven al upstream sin parchear y falla.

| Modo | Tag | Qué incluye | Uso |
|---|---|---|---|
| **Full** | ninguno | Todo: tools + workflows + updater | `go build .` desde source |
| **Bootstrap** | `-tags bootstrap` | Solo CLI + updater (sin tools) | `go install -tags bootstrap github.com/FOUEN/narmol@latest` |

Ficheros con `//go:build !bootstrap`: `internal/runner/tools.go`, `internal/workflows/active/active.go`
Ficheros con `//go:build bootstrap`: `internal/runner/tools_bootstrap.go`, `internal/workflows/active/active_bootstrap.go`

Tras `go install -tags bootstrap`, ejecutar `narmol update` rebuilda el binario completo (sin tag bootstrap).

---

## 5. Código fuente — fichero por fichero

### 5.1 `main.go`

```go
package main

import (
	"github.com/FOUEN/narmol/internal/cli"
	_ "github.com/FOUEN/narmol/internal/runner"
	_ "github.com/FOUEN/narmol/internal/workflows/active"
)

func main() { cli.Run() }
```

---

### 5.2 `internal/cli/cli.go`

```go
package cli

import (
	"fmt"
	"os"
	"strings"
	"github.com/FOUEN/narmol/internal/runner"
)

func Run() {
	if len(os.Args) < 2 { PrintUsage(); return }
	command := os.Args[1]
	switch command {
	case "workflow": RunWorkflow(os.Args[2:])
	case "update":   RunUpdate()
	default:         RunTool(command)
	}
}

func RunTool(name string) {
	os.Args = append([]string{name}, os.Args[2:]...)
	tool := strings.TrimPrefix(name, "-")
	t, err := runner.Get(tool)
	if err != nil { fmt.Printf("Unknown command: %s\n", name); PrintUsage(); os.Exit(1) }
	t.Main()
}
```

---

### 5.3 `internal/cli/update.go`

```go
package cli

import "github.com/FOUEN/narmol/internal/updater"

func RunUpdate() { updater.SelfUpdate() }
```

---

### 5.4 `internal/cli/usage.go`

```go
package cli

import (
	"fmt"
	"github.com/FOUEN/narmol/internal/runner"
)

func PrintUsage() {
	// Prints tool list + commands
}
```

---

### 5.5 `internal/cli/workflow.go`

```go
package cli

import (
	"fmt"
	"os"
	"strings"
	"github.com/FOUEN/narmol/internal/scope"
	"github.com/FOUEN/narmol/internal/workflows"
)

func RunWorkflow(args []string) {
	// Parsea: name, -s scope, -o file, -oj file
	// scope.Load(scopeFile)
	// workflows.Get(name)
	// Para cada s.Domains(): w.Run(domain, s, outputOpts)
}

type workflowFlags struct { scopeFile, textFile, jsonFile string }

func parseWorkflowFlags(workflowName string, args []string) workflowFlags {
	// Manual parsing. -o/-oj soportan valores opcionales (default: <workflow>.txt/.json)
}
```

---

### 5.6 `internal/runner/registry.go`

```go
package runner

import "fmt"

type Tool struct {
	Name        string
	Description string
	Main        func()
}

var registry = map[string]Tool{}

func Register(t Tool) { registry[t.Name] = t }
func Get(name string) (Tool, error) { ... }
func List() []Tool { ... }
```

---

### 5.7 `internal/runner/tools.go` — `//go:build !bootstrap`

```go
//go:build !bootstrap

package runner

import (
	gau_cmd "github.com/lc/gau/v2/cmd/gau"
	amass_cmd "github.com/owasp-amass/amass/v5/cmd/amass"
	dnsx_cmd "github.com/projectdiscovery/dnsx/cmd/dnsx"
	httpx_cmd "github.com/projectdiscovery/httpx/cmd/httpx"
	katana_cmd "github.com/projectdiscovery/katana/cmd/katana"
	nuclei_cmd "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
	subfinder_cmd "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
)

func init() {
	Register(Tool{Name: "amass", Description: "Run amass OSINT recon tool", Main: amass_cmd.Main})
	Register(Tool{Name: "nuclei", Description: "Run nuclei scanner", Main: nuclei_cmd.Main})
	Register(Tool{Name: "httpx", Description: "Run httpx prober", Main: httpx_cmd.Main})
	Register(Tool{Name: "katana", Description: "Run katana crawler", Main: katana_cmd.Main})
	Register(Tool{Name: "dnsx", Description: "Run dnsx resolver", Main: dnsx_cmd.Main})
	Register(Tool{Name: "subfinder", Description: "Run subfinder enumerator", Main: subfinder_cmd.Main})
	Register(Tool{Name: "gau", Description: "Run gau URL fetcher", Main: gau_cmd.Main})
}
```

---

### 5.8 `internal/runner/tools_bootstrap.go` — `//go:build bootstrap`

```go
//go:build bootstrap

package runner
```

---

### 5.9 `internal/scope/scope.go`

API pública:
- `Load(input string) (*Scope, error)` — fichero o string comma-separated
- `IsInScope(target string) bool` — strip proto/port/path, exclusiones ganan
- `FilterHosts(hosts []string) []string` — filtro batch
- `Domains() []string` — `*.example.com` → `example.com`
- `HasWildcard(target string) bool` — necesario para enumeración
- `String() string`

Matching: `*.example.com` matchea root + cualquier subdomain. Case-insensitive.

---

### 5.10 `internal/updater/updater.go`

```go
type ToolSource struct {
	Name       string
	URL        string
	PkgName    string
	MainFile   string
	ExtraFiles []string
}

func DefaultTools() []ToolSource { /* 8 entries */ }
func UpdateAll(baseDir string)   { /* clone/pull + patch */ }
```

---

### 5.11 `internal/updater/patcher.go`

- `PatchTool(baseDir, pkgName, relPath)` — `package main` → `package X` + `func main()` → `func Main()`
- `PatchFile(baseDir, pkgName, relPath)` — solo `package main` → `package X`

---

### 5.12 `internal/updater/selfupdate.go`

```go
const NarmolRepo = "https://github.com/FOUEN/narmol"

func SelfUpdate()           { resolveSourceDir() → UpdateAll() → rebuildAndReplace() }
func resolveSourceDir()     { CWD si tiene go.mod narmol, sino ~/.narmol/src/ }
func rebuildAndReplace()    { go build -o tmp → swap atómico }
func isNarmolSource(dir)    { busca "module github.com/FOUEN/narmol" en go.mod }
```

---

### 5.13 `internal/workflows/registry.go`

```go
type OutputOptions struct { TextFile, JSONFile string }

type Workflow interface {
	Name() string
	Description() string
	Run(domain string, s *scope.Scope, opts OutputOptions) error
}

func Register(w Workflow) { ... }
func Get(name string) (Workflow, error) { ... }
func List() []Workflow { ... }
```

---

### 5.14 `internal/workflows/active/active.go` — `//go:build !bootstrap`

Pipeline subfinder → httpx via FIFO UNIX (`syscall.Mkfifo`).

Imports clave:
- `httpx_runner "github.com/projectdiscovery/httpx/runner"`
- `subfinder_runner "github.com/projectdiscovery/subfinder/v2/pkg/runner"`

Struct `activeResult`: URL, Input, Host, Port, Scheme, StatusCode, Title, Webserver, Tech, CDN, CDNName.

**Problema conocido**: `syscall.Mkfifo` no funciona en Windows.

---

## 6. Grafo de dependencias

```
main.go
  ├── internal/cli
  ├── internal/runner          (_)
  └── internal/workflows/active (_)

internal/cli
  ├── internal/runner
  ├── internal/scope
  ├── internal/workflows
  └── internal/updater

internal/workflows/active
  ├── internal/scope
  ├── internal/workflows
  └── httpx/subfinder runners (external)

internal/updater → solo stdlib + exec(git, go build)
internal/scope   → solo stdlib
```

---

## 7. Guías para cambios comunes

### Añadir tool (5 ficheros)

1. `internal/updater/updater.go` → `DefaultTools()` nueva entrada
2. `go.work` → `./tools/newtool`
3. `go.mod` → `require github.com/org/newtool vX.Y.Z`
4. `internal/runner/tools.go` → import + `Register(Tool{...})`
5. `narmol update`

### Añadir workflow (2-3 ficheros)

1. Crear `internal/workflows/<nombre>/<nombre>.go` (con `//go:build !bootstrap` si importa tools externas)
2. Si tiene `!bootstrap`, crear stub `<nombre>_bootstrap.go`
3. `main.go` → `_ "github.com/FOUEN/narmol/internal/workflows/<nombre>"`

### Añadir subcomando CLI

1. `internal/cli/cli.go` → nuevo `case` en el switch
2. Crear `internal/cli/<nombre>.go` con la función

---

## 8. Build

```bash
go build .                                  # full (desde source, tras narmol update)
go build -tags bootstrap .                  # bootstrap (sin tools)
go install -tags bootstrap github.com/FOUEN/narmol@latest  # instalar bootstrap
narmol update                               # rebuilda binario completo
```
