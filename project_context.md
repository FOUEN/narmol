# Narmol — Contexto para edición de código

Este documento da contexto completo a un modelo de IA para editar código de narmol con confianza.

---

## 1. Qué es narmol

**Narmol** (la "n" de núcleo) es el motor CLI de **Marmol**, un producto de recon web con interfaz gráfica. 

- **Narmol** = binario Go que compila herramientas de seguridad como librerías, gestiona scope, ejecuta workflows de recon y exporta resultados en JSON/texto. Todo in-process, sin subprocesos.
- **Marmol** (futuro) = interfaz web que usa narmol como backend para lanzar reconocimientos, mostrar progreso en tiempo real y generar reports a partir del JSON de narmol.

Narmol debe funcionar tanto como CLI standalone para power users como motor headless para Marmol.

### Cobertura de recon objetivo

1. **Definición de scope** — activos in/out-of-scope
2. **Descubrimiento de superficie** — subdominios (pasivo: subfinder, crt.sh; activo: dnsx brute + permutaciones), dorking
3. **Depuración de superficie** — DNS takeover check, httpx alive, tech detection (wappalyzergo), wayback URLs (gau), git exposure
4. **Fuzzing** — crawling (katana), JS endpoints/params extraction
5. **Vulnerability assessment** — nuclei, WAF detection, SSL/TLS config ✅, CORS misconfig, security headers ✅, cookie flags, HTTP request smuggling ✅, open redirect ✅

### Principio de diseño: librerías Go > CLI wrapping

Las herramientas externas se usan preferentemente como **librerías Go** (sus APIs programáticas: `subfinder/v2/pkg/runner`, `httpx/runner`, `katana/pkg/engine`, `nuclei/lib`, `naabu/v2/pkg/runner`, etc.), no como wrappers de su CLI. Esto da:
- Resultados tipados (structs Go, no parsing de stdout)
- Callbacks para progress (futuro: WebSocket a Marmol)
- Control de concurrencia y error handling real
- JSON output nativo sin serialización intermedia

Los checks que no necesitan tool externa (git exposure, SSL/TLS, CORS, headers, cookies, HTTP smuggling) se implementan con stdlib Go.

---

## 2. Reglas absolutas

1. **NUNCA `exec.Command` / `os/exec` para ejecutar una tool ni componentes internos.** Las tools son repos clonados en `tools/`, parcheados para exponer `func Main()`, e importados como paquetes Go. Todo se ejecuta en el mismo proceso como código Go nativo — llamadas a funciones, goroutines, etc. **El único uso válido de `os/exec` en todo narmol es para invocar `git` y `go build` en el módulo `updater`.**
2. **Go Workspace obligatorio.** Cada tool en `tools/` tiene su propio `go.mod`. El fichero `go.work` los une.
3. **Patrón init() para registros.** Tools y workflows se registran en `init()` y se importan en `main.go` con `_`.
4. **Module path = `github.com/FOUEN/narmol`.** Paquetes internos bajo `internal/`.
5. **Scope siempre filtra.** Todo workflow recibe `*scope.Scope` y filtra antes de tocar la red.
6. **Output en modo append.** `os.O_APPEND|os.O_CREATE|os.O_WRONLY`.
7. **Máxima eficiencia nativa.** Al compilar todo en un solo binario Go sin subprocesos, se evita overhead de IPC, serialización y context-switching entre procesos. Cada herramienta corre como una llamada a función Go directa dentro del mismo address space.

---

## 3. Estructura del proyecto

```
narmol/
├── main.go                     # Entrypoint
├── go.mod                      # module github.com/FOUEN/narmol
├── go.work                     # Go Workspace (. + 9 tools)
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
│   │   └── tools.go            # init() registra 8 tools
│   │
│   ├── scope/
│   │   └── scope.go            # Scope struct, Load(), IsInScope(), FilterHosts(), Domains()
│   │
│   ├── updater/
│   │   ├── updater.go          # ToolSource, DefaultTools(), UpdateAll()
│   │   ├── patcher.go          # PatchTool(), PatchFile()
│   │   └── selfupdate.go       # SelfUpdate(), resolveSourceDir(), rebuildAndReplace(), resolveInstallPath()
│   │
│   └── workflows/
│       ├── registry.go         # Workflow interface, OutputOptions, Register(), Get(), List() (sorted)
│       ├── active/
│       │   └── active.go       # ActiveWorkflow — subfinder→httpx (InputTargetHost, cross-platform)
│       ├── alive/
│       │   └── alive.go        # AliveWorkflow — httpx probe only
│       ├── crawl/
│       │   └── crawl.go        # CrawlWorkflow — katana crawling
│       ├── gitexpose/
│       │   └── gitexpose.go    # GitExposeWorkflow — .git exposure + TruffleHog secrets
│       ├── headers/
│       │   └── headers.go      # HeadersWorkflow — security headers + CORS + cookies + TLS
│       ├── recon/
│       │   └── recon.go        # ReconWorkflow — subfinder(+recursive)+gau, pasivo
│       ├── secrets/
│       │   └── secrets.go      # SecretsWorkflow — TruffleHog secret scanning (git repos, filesystem)
│       ├── subdomains/
│       │   └── subdomains.go   # SubdomainsWorkflow — subfinder recursive + dnsx resolution
│       ├── takeover/
│       │   └── takeover.go     # TakeoverWorkflow — CNAME takeover detection (45+ services)
│       ├── techdetect/
│       │   └── techdetect.go   # TechDetectWorkflow — wappalyzergo fingerprinting
│       ├── urls/
│       │   └── urls.go         # URLsWorkflow — gau + katana en paralelo
│       └── web/
│           └── web.go          # WebWorkflow — subfinder→httpx→nuclei+checks, full web audit
│
└── tools/                      # Repos clonados y parcheados (gestionados por narmol update)
    ├── dnsx/
    ├── gau/
    ├── httpx/
    ├── katana/
    ├── naabu/
    ├── nuclei/
    ├── subfinder/
    ├── trufflehog/
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
2. `UpdateAll()`: clona/actualiza los 9 repos en `tools/`, parchea main→Main
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
	_ "github.com/FOUEN/narmol/internal/workflows/alive"
	_ "github.com/FOUEN/narmol/internal/workflows/crawl"
	_ "github.com/FOUEN/narmol/internal/workflows/gitexpose"
	_ "github.com/FOUEN/narmol/internal/workflows/headers"
	_ "github.com/FOUEN/narmol/internal/workflows/recon"
	_ "github.com/FOUEN/narmol/internal/workflows/secrets"
	_ "github.com/FOUEN/narmol/internal/workflows/subdomains"
	_ "github.com/FOUEN/narmol/internal/workflows/takeover"
	_ "github.com/FOUEN/narmol/internal/workflows/techdetect"
	_ "github.com/FOUEN/narmol/internal/workflows/urls"
	_ "github.com/FOUEN/narmol/internal/workflows/web"
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
	// ... 8 tool imports (dnsx, gau, httpx, katana, naabu, nuclei, subfinder, trufflehog)
)

func init() {
	Register(Tool{Name: "nuclei", Main: nuclei_cmd.Main})
	// ... 7 more (dnsx, gau, httpx, katana, naabu, subfinder, trufflehog)
}
```

---

### 5.8 `internal/scope/scope.go`

API pública:
- `Load(input string) (*Scope, error)` — fichero o string comma-separated
- `IsInScope(target string) bool` — strip proto/port/path, exclusiones ganan. Soporta dominios, IPs, CIDRs
- `FilterHosts(hosts []string) []string` — filtro batch
- `Domains() []string` — `*.example.com` → `example.com` (excluye IPs/CIDRs)
- `IPs() []string` — devuelve todas las IPs y CIDRs del scope
- `HasWildcard(target string) bool` — necesario para decidir si ejecutar subfinder
- `HasIPs() bool` — indica si hay IPs/CIDRs en scope
- `String() string` — representación legible con labels (domain/ip/cidr)

Struct `rule` interno:
```go
type rule struct {
    pattern string     // "*.example.com", "10.0.0.1", "192.168.1.0/24"
    exclude bool       // true si prefijo "-"
    ip      net.IP     // non-nil si es IP individual
    cidr    *net.IPNet // non-nil si es rango CIDR
}
```

Matching:
- `*.example.com` matchea root + cualquier subdomain a cualquier profundidad
- IPs: comparación exacta con `net.IP.Equal()`
- CIDRs: `net.IPNet.Contains()` comprueba si el target IP cae en el rango
- URLs: se stripea protocolo, puerto y path antes de matchear
- Exclusiones SIEMPRE ganan sobre inclusiones
- Case-insensitive para dominios

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

func DefaultTools() []ToolSource { /* 9 entries (incl. naabu, trufflehog) */ }
func UpdateAll(baseDir string)   { /* clone/pull + patch + nuclei test cleanup */ }
```

---

### 5.10 `internal/updater/patcher.go`

- `PatchTool(baseDir, pkgName, relPath)` — `package main` → `package X` + `func main()` → `func Main()`
- `PatchFile(baseDir, pkgName, relPath)` — solo `package main` → `package X`
- `PatchTrufflehogInit()` — mueve init() interceptor de CLI args a Main()
- `PatchNucleiGitlab()` — int → int64 en campo gitlab
- `PatchGauCommoncrawl()` — commoncrawl error fatal → logrus.Warnf+continue (non-fatal)
- `RemoveTestFiles()` — elimina ficheros de test que causan problemas de build (e.g. GitHub Push Protection)

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

Workflow en 2 pasos (cross-platform, no usa FIFO). **Requiere wildcard scope.**

**Pipeline:**
1. **Subfinder**: descubre subdominios usando `ResultCallback`, filtra cada host contra scope, acumula hosts en slice
2. **httpx**: recibe hosts via `InputTargetHost` (goflags.StringSlice), probes con `OnResult` callback

**Comportamiento:**
- Si scope no tiene wildcard para el dominio → error (no tiene sentido enumerar un solo host)
- Subfinder: `MaxEnumerationTime: 10`, `Threads: 10`, `DisableUpdateCheck: true`, output a `io.Discard`
- httpx: `Threads: 50`, `Timeout: 10`, `FollowRedirects: true`, `MaxRedirects: 10`, `RateLimit: 150`, `RandomAgent: true`, `TechDetect: true`, `OutputCDN: true`, `ExtractTitle: true`
- Cada resultado httpx se compacta a `activeResult` con solo los campos relevantes

Imports clave:
- `httpx_runner "github.com/projectdiscovery/httpx/runner"`
- `subfinder_runner "github.com/projectdiscovery/subfinder/v2/pkg/runner"`

Struct `activeResult`:
```go
type activeResult struct {
    URL, Input, Host, Port, Scheme string
    StatusCode int
    Title, Webserver string
    Tech []string
    CDN bool
    CDNName string
}
```

---

### 5.14 `internal/workflows/recon/recon.go`

Workflow de reconocimiento pasivo — **NUNCA toca el target directamente**. Solo consulta fuentes externas.

**Pipeline:**
1. **Subfinder** (solo si wildcard scope) — enumeración pasiva de subdominios
2. **En paralelo (goroutines + sync.WaitGroup):**
   - **Subfinder recursivo** — alimenta los subdominios descubiertos de vuelta para encontrar niveles más profundos
   - **Gau** — recolecta URLs históricas de Wayback Machine, OTX, URLScan

**Comportamiento:**
- Si scope tiene wildcard (`*.example.com`): ejecuta los 3 pasos
- Si scope es exacto (`example.com`): skip subfinder, solo gau. Emite el dominio como subdomain result de tipo "scope".
- Dedup global: `sync.Map` evita duplicados entre todos los pasos
- Scope filter en cada callback antes de emitir resultado
- Contadores atómicos (`sync/atomic`) para subdomainCount y urlCount

**Configuración gau:**
```go
config := &gau_providers.Config{
    Threads: 5, Timeout: 45, MaxRetries: 3,
    IncludeSubdomains: true,
    Client: &fasthttp.Client{
        TLSConfig: &tls.Config{InsecureSkipVerify: true},
    },
    Blacklist: mapset.NewThreadUnsafeSet(""), // REQUERIDO — si nil, panic
}
```
**IMPORTANTE:** El `Client` de fasthttp y el `Blacklist` mapset DEBEN inicializarse explícitamente. Si `Client` es nil → nil pointer panic. Si `Blacklist` es nil → panic en provider.

Imports clave:
- `gau_providers "github.com/lc/gau/v2/pkg/providers"`
- `gau_runner "github.com/lc/gau/v2/runner"`
- `subfinder_runner "github.com/projectdiscovery/subfinder/v2/pkg/runner"`
- `"github.com/valyala/fasthttp"`, `mapset "github.com/deckarep/golang-set/v2"`

Struct `reconResult`:
```go
type reconResult struct {
    Type   string `json:"type"`    // "subdomain", "url"
    Value  string `json:"value"`   // el subdomain o URL
    Source string `json:"source"`  // "subfinder", "subfinder-recursive", "gau", "scope"
    Domain string `json:"domain"`  // dominio padre
}
```

Funciones internas: `runSubfinder()`, `runSubfinderRecursive()`, `runGau()`

---

### 5.15 `internal/workflows/secrets/secrets.go`

Workflow de escaneo de secretos usando TruffleHog — 800+ detectores para API keys, tokens, passwords, credenciales cloud, etc.

**Pipeline:**
1. **Auto-detección de tipo de scan** según el target:
   - URLs (`https://`, `git@`, `*.git`) → scan de repositorio git
   - Paths (`/`, `./`, `C:\`, `~`) → scan de filesystem
   - Otros → intenta como git por defecto
2. **TruffleHog engine** — crea `engine.Engine` con `sources.SourceManager`, ejecuta scan, recolecta resultados

**Configuración del engine:**
```go
sourceMgr := sources.NewManager(
    sources.WithConcurrentSources(1),
    sources.WithConcurrentTargets(4),
    sources.WithSourceUnits(),
)
eng, _ := engine.NewEngine(ctx, &engine.Config{
    Concurrency:   4,
    Verify:        false,  // no verificar contra APIs (más rápido)
    SourceManager: sourceMgr,
})
```

**Patrón de ejecución:**
1. `eng.Start(ctx)` — arranca workers (scanner, detector, notifier)
2. `eng.ScanGit(ctx, config)` o `eng.ScanFileSystem(ctx, config)` — inicia scan asíncrono
3. Goroutine consume `eng.ResultsChan()` — convierte `detectors.ResultWithMetadata` → `SecretResult`
4. `eng.Finish(ctx)` — espera a que terminen todos los workers

**API pública** (para uso desde otros workflows, e.g. web workflow):
- `ScanGitRepo(url string) ([]SecretResult, error)` — escanea repo git y devuelve resultados
- `ScanPath(path string) ([]SecretResult, error)` — escanea directorio local y devuelve resultados
- `SecretResult` — tipo exportado para uso cross-package

Imports clave:
- `"github.com/trufflesecurity/trufflehog/v3/pkg/engine"`
- `"github.com/trufflesecurity/trufflehog/v3/pkg/sources"`
- `"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"`
- `"github.com/trufflesecurity/trufflehog/v3/pkg/context"`

Struct `SecretResult` (exportado):
```go
type SecretResult struct {
    Type         string            `json:"type"`          // siempre "secret"
    DetectorType string            `json:"detector_type"` // "AWS", "GitHub", "Slack", etc.
    Verified     bool              `json:"verified"`
    Redacted     string            `json:"redacted"`      // versión redactada del secreto
    Source       string            `json:"source"`        // "git" o "filesystem"
    Target       string            `json:"target"`        // URL del repo o path
    SourceName   string            `json:"source_name"`
    ExtraData    map[string]string `json:"extra_data,omitempty"`
}
```

Funciones internas: `scanGit()`, `scanFilesystem()`, `resultToSecret()`, `determineScanType()`

---

### 5.16 `internal/workflows/web/web.go`

Workflow de auditoría web estilo Nessus — **fingerprint primero, scan después**. Post-httpx todo corre en paralelo con goroutines.

**Output: formato report profesional por fases.**
Los resultados se recopilan en memoria (`webReport`) y al final se generan:
- **Texto** — report organizado por secciones (Discovery, Vulnerabilities, Secrets, Headers, TLS, Redirects, Smuggling) con resumen al final.
- **JSON** — objeto estructurado con `target`, `date`, `summary` (contadores) y `phases` (arrays por fase). Listo para generar informes.

**Templates nuclei:** Se asegura su descarga automática antes del scan con `installer.TemplateManager{}.FreshInstallIfNotExists()`.

**Pipeline (3 pasos, paso 3 paralelo):**
1. **Subfinder** (solo si wildcard scope) — enumeración pasiva de subdominios
2. **httpx** — probing + fingerprinting: tech detection (wappalyzer), web server, CDN, title
3. **En paralelo (sync.WaitGroup):**
   - **Nuclei** — vulnerability scan filtrado por tags del fingerprint
   - **TruffleHog** — check `.git/HEAD` exposure → si expuesto, scan de secretos (usa API pública `secrets.ScanGitRepo()`)
   - **Security headers** — checks de stdlib: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORS misconfig, cookie flags
   - **TLS/SSL** — protocol version, weak ciphers, cert validity, hostname mismatch
   - **Open redirects** — parameter-based redirect testing (18 common params)
   - **HTTP smuggling** — CL.TE / TE.CL timing-based detection

**Struct de report JSON:**
```json
{
  "target": "example.com",
  "date": "2024-...",
  "summary": { "hosts_discovered": N, "hosts_live": N, "vulnerabilities": N, ... },
  "phases": {
    "discovery": [...],
    "vulnerabilities": [...],
    "secrets": [...],
    "header_issues": [...],
    "tls_issues": [...],
    "redirects": [...],
    "smuggling": [...]
  }
}
```

Imports clave:
- `httpx_runner "github.com/projectdiscovery/httpx/runner"`
- `nuclei "github.com/projectdiscovery/nuclei/v3/lib"`
- `"github.com/projectdiscovery/nuclei/v3/pkg/installer"` — template auto-download
- `nuclei_output "github.com/projectdiscovery/nuclei/v3/pkg/output"`
- `subfinder_runner "github.com/projectdiscovery/subfinder/v2/pkg/runner"`
- `"github.com/FOUEN/narmol/internal/workflows/secrets"` — para TruffleHog
- `"crypto/tls"`, `"net"`, `"net/http"`, `"time"` — para checks de stdlib

Structs: `webResult`, `webReport`, `reportJSON`, `reportSummary`, `reportPhases`

Funciones: `runSubfinder()`, `runHttpx()`, `runNuclei()`, `runGitExposureCheck()`, `runSecurityHeaderChecks()`, `runTLSChecks()`, `runOpenRedirectChecks()`, `runSmugglingChecks()`, `testSmuggling()`, `buildNucleiTags()`, `appendUnique()`, `severityOrder()`

Variables globales: `alwaysTags`, `techTagMap` (50+ entries), `requiredHeaders` (6 security headers), `weakCiphers` (8 insecure suites), `openRedirectParams` (18 common params)

---

## 6. Grafo de dependencias

```
main.go
  ├── internal/cli
  ├── internal/runner            (_)
  ├── internal/workflows/active   (_)
  ├── internal/workflows/alive    (_)
  ├── internal/workflows/crawl    (_)
  ├── internal/workflows/gitexpose(_)
  ├── internal/workflows/headers  (_)
  ├── internal/workflows/recon    (_)
  ├── internal/workflows/secrets  (_)
  ├── internal/workflows/subdomains(_)
  ├── internal/workflows/takeover (_)
  ├── internal/workflows/techdetect(_)
  ├── internal/workflows/urls     (_)
  └── internal/workflows/web      (_)

internal/cli
  ├── internal/runner
  ├── internal/scope
  ├── internal/workflows
  └── internal/updater

internal/workflows/active
  ├── internal/scope
  ├── internal/workflows
  └── httpx/subfinder runners (external)

internal/workflows/alive        → httpx runner
internal/workflows/crawl        → katana engine
internal/workflows/gitexpose    → internal/workflows/secrets + stdlib
internal/workflows/headers      → stdlib (crypto/tls, net/http)
internal/workflows/subdomains   → subfinder runner + dnsx library
internal/workflows/takeover     → stdlib (net.LookupCNAME)
internal/workflows/techdetect   → wappalyzergo + stdlib
internal/workflows/urls         → gau runner + katana engine

internal/workflows/recon
  ├── internal/scope
  ├── internal/workflows
  └── gau/subfinder runners (external)

internal/workflows/secrets
  ├── internal/scope
  ├── internal/workflows
  └── trufflehog engine/sources/detectors (external)

internal/workflows/web
  ├── internal/scope
  ├── internal/workflows
  └── subfinder/httpx/nuclei runners (external)

internal/updater → solo stdlib + exec(git, go build)  ← ÚNICO uso válido de os/exec en todo narmol
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

---

## 9. Workflows TODO

### Core workflows

Workflows principales que cubren el pipeline completo de recon → vuln assessment.

#### `recon` ✅ (implementado) — Descubrimiento pasivo

No toca el target directamente. Solo fuentes externas.

- [x] Subdomain enumeration pasiva (subfinder) — solo si scope tiene wildcard
- [x] Subdomain enumeration pasiva **recursiva** (subdominios descubiertos → input de nuevo)
- [x] Recolectar URLs históricas (gau: Wayback, Common Crawl, OTX, URLScan)
- [x] Soporte de scope exacto (`-s example.com`) — skip subfinder, solo gau
- [x] Soporte de IPs/CIDRs en scope
- [x] Scope filter en cada paso
- [x] Dedup global de resultados
- [x] Output JSON: subdominios + URLs históricas (tipo, valor, fuente, dominio)

#### `web` ✅ (implementado) — Full web audit (estilo Nessus)

Fingerprint first, scan after. Pipeline: subfinder→httpx(fingerprint)→nuclei(targeted).

- [x] Subdomain discovery (subfinder) — solo si scope tiene wildcard
- [x] Alive check + fingerprinting (httpx): tech detection, CDN, title, webserver
- [x] Tech → nuclei tag mapping (techTagMap: 50+ entries, wappalyzer → nuclei tags)
- [x] Targeted vulnerability scan (nuclei: solo templates del stack detectado)
- [x] Git exposure check (.git/HEAD) + TruffleHog secret scan si expuesto
- [x] Security header checks stdlib: HSTS, CSP, X-Frame, CORS, cookies
- [x] Nuclei + TruffleHog + headers corren en PARALELO (goroutines + sync.WaitGroup)
- [x] Generic checks siempre activos: exposure, misconfig, default-login, takeover, config
- [x] Scope filter en cada paso
- [x] Early stop si no hay live hosts
- [x] Dedup global por fase
- [x] Output JSON: probe (live hosts + tech) + vuln (vulnerabilidades) + secret (.git) + header (misconfig)

#### `vulnscan` — ~~Deprecado~~ → absorbido por `web`

Todo lo que iba a hacer `vulnscan` ya lo hace `web` directamente:
- Nuclei targeted scan ✅ (`web`), Security headers ✅ (`web` + `headers`), CORS ✅ (`web` + `headers`)
- Cookie flags ✅ (`web` + `headers`), SSL/TLS ✅ (`web` + `headers`), Open redirect ✅ (`web`)
- HTTP smuggling ✅ (`web`), Git secrets ✅ (`web` + `gitexpose`)

No se necesita un workflow separado.

#### `full` — Scan completo

Orquesta todos los core workflows + soporte de IPs/CIDR.

- [ ] Soporte de IPs individuales y CIDR en scope
- [ ] Ejecutar `recon`
- [ ] Ejecutar `web`
- [ ] Secret scanning con TruffleHog (git repos, filesystem, crawled content)
- [ ] Port scan en IPs/CIDR del scope (si aplica)
- [ ] Output JSON unificado: superficie completa + vulnerabilidades

---

### Mini-workflows

Workflows pequeños para tareas específicas. Se pueden usar standalone o como bloques reutilizables desde los core workflows.

#### `active` ✅ (implementado)

Subfinder → httpx. Descubre subdominios y comprueba cuáles tienen servicio web.

#### `subdomains` ✅ (implementado)

Subfinder recursivo (3 rounds) + resolución DNS con dnsx. Solo enumeración, sin probing.

- [x] Subfinder (pasivo)
- [x] Subfinder recursivo (3 rounds)
- [x] Resolución DNS (dnsx library — A + AAAA)
- [x] Dedup + scope filter
- [x] Output JSON: subdomain + IPs resueltas

#### `alive` ✅ (implementado)

httpx probe — comprueba qué hosts están activos.

- [x] httpx probe con follow redirects
- [x] Output: URL, status code, título, webserver

#### `techdetect` ✅ (implementado)

wappalyzergo fingerprinting directo sobre hosts alive.

- [x] HTTP GET + wappalyzergo Fingerprint()
- [x] Fallback HTTPS → HTTP
- [x] Concurrencia con semáforo (20 goroutines)
- [x] Output JSON: host → tecnologías detectadas

#### `crawl` ✅ (implementado)

Katana standard engine — crawling de endpoints, links, JS files.

- [x] Katana crawl (robots.txt, sitemap, links, JS via KnownFiles: "all")
- [x] MaxDepth 3, breadth-first, scope filter
- [x] Output JSON: URL + source + tag/attribute

#### `urls` ✅ (implementado)

gau (histórico) + katana (live crawl) en PARALELO.

- [x] gau (Wayback, OTX, URLScan)
- [x] katana crawl
- [x] Ambos en paralelo (goroutines)
- [x] Dedup + scope filter
- [x] Output JSON: URL + source

#### `headers` ✅ (implementado)

Auditoría completa de security headers, CORS, cookies, SSL/TLS. Pure stdlib.

- [x] Security headers (HSTS, CSP, X-Frame, X-Content-Type, Referrer-Policy, Permissions-Policy)
- [x] Cookie flags (HttpOnly, Secure, SameSite)
- [x] CORS misconfiguration (origin reflection, credentials)
- [x] SSL/TLS (protocol version, weak ciphers, cert expiry, self-signed, hostname mismatch)
- [x] Output JSON: findings por host con categoría

#### `takeover` ✅ (implementado)

Subdomain takeover via CNAME resolution + NXDOMAIN check.

- [x] Resolución CNAME (net.LookupCNAME)
- [x] 45+ servicios vulnerables (AWS S3, Azure, Heroku, GitHub Pages, Netlify, Vercel, etc.)
- [x] NXDOMAIN check = strong indicator
- [x] Output JSON: subdomain, CNAME, servicio, severidad

#### `secrets` ✅ (implementado)

Escaneo de secretos filtrados usando TruffleHog (800+ detectores).

- [x] Scan de repositorios git (por URL) para secretos
- [x] Scan de filesystem/directorio local para secretos
- [x] 800+ detectores (API keys, tokens, passwords, AWS, GCP, etc.)
- [x] Output JSON: tipo detector, verificado, redactado, fuente
- [x] API pública (`ScanGitRepo()`, `ScanPath()`) para uso desde otros workflows

#### `gitexpose` ✅ (implementado)

.git exposure check + TruffleHog secret scanning.

- [x] Check `/.git/HEAD`, `/.git/config` (HTTP 200 = exposed)
- [x] Si `.git` expuesto → scan con TruffleHog para secretos
- [x] Concurrencia con semáforo (20 goroutines)
- [x] Output JSON: phase (exposed/secret) + severity + detail
