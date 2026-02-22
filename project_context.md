# Narmol — Contexto para edición de código

Este documento da contexto completo a un modelo de IA para editar código de narmol con confianza.

---

## 1. Qué es narmol

Un binario Go que compila 7 herramientas de seguridad externas dentro de sí mismo (no las llama via exec.Command), les añade scope enforcement y permite ejecutar workflows que encadenan herramientas.

---

## 2. Reglas absolutas

1. **NUNCA `exec.Command` para ejecutar una tool.** Las tools son repos clonados en `tools/`, parcheados para exponer `func Main()`, e importados como paquetes Go.
2. **Go Workspace obligatorio.** Cada tool en `tools/` tiene su propio `go.mod`. El fichero `go.work` los une.
3. **Patrón init() para registros.** Tools y workflows se registran en `init()` y se importan en `main.go` con `_`.
4. **Module path = `github.com/FOUEN/narmol`.** Paquetes internos bajo `internal/`.
5. **Scope siempre filtra.** Todo workflow recibe `*scope.Scope` y filtra antes de tocar la red.
6. **Output en modo append.** `os.O_APPEND|os.O_CREATE|os.O_WRONLY`.
7. **CGO habilitado**, pero la dependencia libpostal de amass se parchea con build tag `ignore` para que no requiera la librería C.

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
│   │   ├── usage.go            # PrintUsage() — lista tools y commands
│   │   └── workflow.go         # RunWorkflow() — parsea flags -s, -o, -oj
│   │
│   ├── runner/
│   │   ├── registry.go         # Tool struct, Register(), Get(), List() (sorted)
│   │   └── tools.go            # init() registra 7 tools
│   │
│   ├── scope/
│   │   └── scope.go            # Scope struct, Load(), IsInScope(), FilterHosts(), Domains()
│   │
│   ├── updater/
│   │   ├── updater.go          # ToolSource, DefaultTools(), UpdateAll(), patchLibpostal()
│   │   ├── patcher.go          # PatchTool(), PatchFile()
│   │   └── selfupdate.go       # SelfUpdate(), resolveSourceDir(), rebuildAndReplace(), resolveInstallPath()
│   │
│   └── workflows/
│       ├── registry.go         # Workflow interface, OutputOptions, Register(), Get(), List() (sorted)
│       └── active/
│           └── active.go       # ActiveWorkflow — subfinder→httpx (InputTargetHost, cross-platform)
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

## 4. Instalación y build

Un solo método de instalación:

```bash
git clone https://github.com/FOUEN/narmol.git
cd narmol
go run . update
```

`go run . update` ejecuta:
1. Detecta que estamos en el source dir
2. `UpdateAll()`: clona/actualiza los 8 repos en `tools/`, parchea main→Main, parchea libpostal
3. `rebuildAndReplace()`: compila el binario completo
4. Detecta que se ejecutó via `go run` (path temporal) → instala en `$GOBIN` o `~/go/bin`

Actualizaciones posteriores: `narmol update` (recompila in-place).

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
func Run() {
	command := os.Args[1]
	switch command {
	case "workflow": RunWorkflow(os.Args[2:])
	case "update":   RunUpdate()
	default:         RunTool(command)
	}
}

func RunTool(name string) {
	os.Args = append([]string{name}, os.Args[2:]...)
	t, err := runner.Get(strings.TrimPrefix(name, "-"))
	if err != nil { PrintUsage(); os.Exit(1) }
	t.Main()
}
```

---

### 5.3 `internal/cli/update.go`

```go
func RunUpdate() { updater.SelfUpdate() }
```

---

### 5.4 `internal/cli/usage.go`

Imprime tools (sorted) + commands. Usa `runner.List()`.

---

### 5.5 `internal/cli/workflow.go`

```go
func RunWorkflow(args []string) {
	// Parsea: name, -s scope, -o [file], -oj [file]
	// scope.Load(scopeFile)
	// workflows.Get(name)
	// Para cada s.Domains(): w.Run(domain, s, outputOpts)
}

type workflowFlags struct { scopeFile, textFile, jsonFile string }
```

`-o` y `-oj` soportan valores opcionales (default: `<workflow>.txt/.json`).

---

### 5.6 `internal/runner/registry.go`

```go
type Tool struct { Name, Description string; Main func() }

var registry = map[string]Tool{}

func Register(t Tool)              // add to registry
func Get(name string) (Tool, error) // lookup
func List() []Tool                  // sorted alphabetically
```

---

### 5.7 `internal/runner/tools.go`

```go
package runner

import (
	amass_cmd "github.com/owasp-amass/amass/v5/cmd/amass"
	// ... 6 more
)

func init() {
	Register(Tool{Name: "amass", Main: amass_cmd.Main})
	// ... 6 more (dnsx, gau, httpx, katana, nuclei, subfinder)
}
```

---

### 5.8 `internal/scope/scope.go`

API pública:
- `Load(input string) (*Scope, error)` — fichero o string comma-separated
- `IsInScope(target string) bool` — strip proto/port/path, exclusiones ganan
- `FilterHosts(hosts []string) []string` — filtro batch
- `Domains() []string` — `*.example.com` → `example.com`
- `HasWildcard(target string) bool` — necesario para enumeración
- `String() string`

Matching: `*.example.com` matchea root + cualquier subdomain. Case-insensitive.

---

### 5.9 `internal/updater/updater.go`

```go
type ToolSource struct {
	Name       string
	URL        string
	PkgName    string
	MainFile   string
	ExtraFiles []string
}

func DefaultTools() []ToolSource { /* 8 entries */ }
func UpdateAll(baseDir string)   { /* clone/pull + patch + patchLibpostal + nuclei test cleanup */ }
func patchLibpostal(amassDir string) {
	// cgo_specific.go: "//go:build cgo" → "//go:build ignore"
	// pure_go.go: "//go:build !cgo" → "//go:build !ignore"
}
```

---

### 5.10 `internal/updater/patcher.go`

- `PatchTool(baseDir, pkgName, relPath)` — `package main` → `package X` + `func main()` → `func Main()`
- `PatchFile(baseDir, pkgName, relPath)` — solo `package main` → `package X`

---

### 5.11 `internal/updater/selfupdate.go`

```go
const NarmolRepo = "https://github.com/FOUEN/narmol"

func SelfUpdate()            // resolveSourceDir() → UpdateAll() → rebuildAndReplace()
func resolveSourceDir()      // CWD si tiene go.mod narmol, sino ~/.narmol/src/ (clone/pull)
func rebuildAndReplace()     // go build → resolveInstallPath() → swap atómico
func resolveInstallPath()    // Si está en /tmp (go run) → $GOBIN/~/go/bin. Si no → replace in-place.
func isTempPath(p string)    // Detecta /tmp/, /go-build, appdata/local/temp
func isNarmolSource(dir)     // busca "module github.com/FOUEN/narmol" en go.mod
```

---

### 5.12 `internal/workflows/registry.go`

```go
type OutputOptions struct { TextFile, JSONFile string }

type Workflow interface {
	Name() string
	Description() string
	Run(domain string, s *scope.Scope, opts OutputOptions) error
}

func Register(w Workflow)
func Get(name string) (Workflow, error)
func List() []Workflow  // sorted alphabetically
```

---

### 5.13 `internal/workflows/active/active.go`

Workflow en 2 pasos (cross-platform, no usa FIFO):

1. **Subfinder**: descubre subdominios usando `ResultCallback`, filtra por scope, acumula hosts en slice
2. **httpx**: recibe hosts via `InputTargetHost` (goflags.StringSlice), probes con OnResult callback

Imports clave:
- `httpx_runner "github.com/projectdiscovery/httpx/runner"`
- `subfinder_runner "github.com/projectdiscovery/subfinder/v2/pkg/runner"`

Struct `activeResult`: URL, Input, Host, Port, Scheme, StatusCode, Title, Webserver, Tech, CDN, CDNName.

Funciones auxiliares: `compactFromResult()`, `compactResult()`, `jsonGetString()`.

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

### Añadir tool (5 pasos)

1. `internal/updater/updater.go` → `DefaultTools()` nueva entrada con Name, URL, PkgName, MainFile
2. `go.work` → añadir `./tools/newtool`
3. `go.mod` → `require github.com/org/newtool vX.Y.Z`
4. `internal/runner/tools.go` → import alias + `Register(Tool{...})`
5. Ejecutar `narmol update` para clonar y parchear

### Añadir workflow (2 pasos)

1. Crear `internal/workflows/<nombre>/<nombre>.go` con `init()` que llame `workflows.Register()`
2. `main.go` → `_ "github.com/FOUEN/narmol/internal/workflows/<nombre>"`

### Añadir subcomando CLI

1. `internal/cli/cli.go` → nuevo `case` en el switch
2. Crear `internal/cli/<nombre>.go` con la función handler

---

## 8. Build

```bash
# Desde source (tras git clone)
go run . update              # clona tools, parchea, compila e instala en ~/go/bin

# Desde el binario instalado
narmol update                # actualiza tools y recompila in-place

# Build manual
go build -o narmol .         # requiere que tools/ esté parcheado
```
