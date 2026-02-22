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
5. **Vulnerability assessment** — nuclei, WAF detection, SSL/TLS config, CORS misconfig, security headers, cookie flags, HTTP request smuggling

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
│       ├── recon/
│       │   └── recon.go        # ReconWorkflow — subfinder(+recursive)+gau, pasivo
│       ├── secrets/
│       │   └── secrets.go      # SecretsWorkflow — TruffleHog secret scanning (git repos, filesystem)
│       └── web/
│           └── web.go          # WebWorkflow — subfinder→httpx→katana→nuclei, full web audit
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
	_ "github.com/FOUEN/narmol/internal/workflows/recon"
	_ "github.com/FOUEN/narmol/internal/workflows/secrets"
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
2. **Subfinder recursivo** — alimenta los subdominios descubiertos de vuelta para encontrar niveles más profundos (e.g. `sub.sub.example.com`). Solo recurre en subdominios con ≥2 puntos. Timeout más corto (`MaxEnumerationTime: 5`).
3. **Gau** — recolecta URLs históricas de Wayback Machine, Common Crawl, OTX, URLScan

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
3. Goroutine consume `eng.ResultsChan()` — convierte `detectors.ResultWithMetadata` → `secretResult`
4. `eng.Finish(ctx)` — espera a que terminen todos los workers

**API pública** (para uso desde otros workflows):
- `ScanGitRepo(url string) ([]secretResult, error)` — escanea repo git y devuelve resultados
- `ScanPath(path string) ([]secretResult, error)` — escanea directorio local y devuelve resultados

Imports clave:
- `"github.com/trufflesecurity/trufflehog/v3/pkg/engine"`
- `"github.com/trufflesecurity/trufflehog/v3/pkg/sources"`
- `"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"`
- `"github.com/trufflesecurity/trufflehog/v3/pkg/context"`

Struct `secretResult`:
```go
type secretResult struct {
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

Workflow de auditoría web completa — **Toca el target activamente**. Pipeline de 4 pasos.

**Pipeline:**
1. **Subfinder** (solo si wildcard scope) — enumeración pasiva de subdominios + siempre incluye el dominio raíz
2. **httpx** — probing de hosts vivos con tech detection, CDN, title extraction
3. **Katana** — crawling de hosts vivos (depth 3, JS scraping, ignora query params, field scope `rdn`)
4. **Nuclei** — vulnerabilities scan en la unión de hosts vivos + endpoints crawleados (severity: medium, high, critical)

**Comportamiento:**
- Si no hay live hosts tras httpx → early stop (no ejecuta katana ni nuclei)
- Nuclei recibe `mergeUnique(liveHosts, endpoints)` como targets
- Dedup global por fase con `sync.Map` (key = `phase:value`)
- Scope filter en subfinder callback y katana callback
- Contadores atómicos (`sync/atomic`) para estadísticas

**Configuración httpx:**
```go
Threads: 50, Timeout: 10, FollowRedirects: true, MaxRedirects: 10,
RateLimit: 150, RandomAgent: true, TechDetect: true, OutputCDN: "true", ExtractTitle: true
```

**Configuración katana (API pública, NO internal/runner):**
```go
katana_types.NewCrawlerOptions(opts) → katana_standard.New(crawlerOptions) → crawler.Crawl(host)
MaxDepth: 3, RateLimit: 150, Concurrency: 10, Parallelism: 10,
Strategy: katana_queue.DepthFirst.String(), FieldScope: "rdn",
ScrapeJSResponses: true, IgnoreQueryParams: true
```

**Configuración nuclei (SDK lib, NO cmd):**
```go
nuclei.NewNucleiEngineCtx(ctx, opts...) → ne.LoadAllTemplates() → ne.LoadTargets() → ne.ExecuteCallbackWithCtx()
Severity: "medium,high,critical", TemplateConcurrency: 25, HostConcurrency: 25, ProbeConcurrency: 50
```

Imports clave:
- `httpx_runner "github.com/projectdiscovery/httpx/runner"`
- `katana_standard "github.com/projectdiscovery/katana/pkg/engine/standard"`
- `katana_types "github.com/projectdiscovery/katana/pkg/types"`
- `katana_queue "github.com/projectdiscovery/katana/pkg/utils/queue"`
- `katana_output "github.com/projectdiscovery/katana/pkg/output"`
- `nuclei "github.com/projectdiscovery/nuclei/v3/lib"`
- `nuclei_output "github.com/projectdiscovery/nuclei/v3/pkg/output"`
- `subfinder_runner "github.com/projectdiscovery/subfinder/v2/pkg/runner"`

Struct `webResult`:
```go
type webResult struct {
    Phase      string   `json:"phase"`                 // "probe", "crawl", "vuln"
    Value      string   `json:"value"`                 // URL or matched-at
    Host       string   `json:"host,omitempty"`
    StatusCode int      `json:"status_code,omitempty"`
    Title      string   `json:"title,omitempty"`
    Tech       []string `json:"tech,omitempty"`
    Webserver  string   `json:"webserver,omitempty"`
    CDN        bool     `json:"cdn,omitempty"`
    CDNName    string   `json:"cdn_name,omitempty"`
    TemplateID string   `json:"template_id,omitempty"`
    VulnName   string   `json:"vuln_name,omitempty"`
    Severity   string   `json:"severity,omitempty"`
    VulnType   string   `json:"vuln_type,omitempty"`
}
```

Funciones internas: `runSubfinder()`, `runHttpx()`, `runKatana()`, `runNuclei()`, `appendUnique()`, `mergeUnique()`

---

## 6. Grafo de dependencias

```
main.go
  ├── internal/cli
  ├── internal/runner           (_)
  ├── internal/workflows/active  (_)
  ├── internal/workflows/recon   (_)
  ├── internal/workflows/secrets (_)
  └── internal/workflows/web     (_)

internal/cli
  ├── internal/runner
  ├── internal/scope
  ├── internal/workflows
  └── internal/updater

internal/workflows/active
  ├── internal/scope
  ├── internal/workflows
  └── httpx/subfinder runners (external)

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
  └── subfinder/httpx/katana/nuclei runners (external)

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

#### `web` ✅ (implementado) — Full web audit

Toca el target. Pipeline completo: subfinder→httpx→katana→nuclei.

- [x] Subdomain discovery (subfinder) — solo si scope tiene wildcard
- [x] Alive check — hosts con servicio web (httpx), tech detection, CDN, title
- [x] Crawling de hosts alive (katana: depth 3, JS scraping, query param dedup, field scope `rdn`)
- [x] Vulnerability scan (nuclei: severity medium,high,critical)
- [x] Scope filter en cada paso
- [x] Early stop si no hay live hosts
- [x] Dedup global por fase
- [x] Output JSON: probe (live hosts), crawl (endpoints), vuln (vulnerabilidades)

#### `vulnscan` — Assessment de vulnerabilidades

Input: output del workflow `web` (hosts alive + URLs).

- [ ] Nuclei scan (severidad configurable, por defecto medium+)
- [ ] Security headers check (X-Frame-Options, CSP, HSTS, X-Content-Type-Options, etc.)
- [ ] CORS misconfiguration check
- [ ] Cookie flags check (HttpOnly, Secure, SameSite)
- [ ] SSL/TLS config check (versión protocolo, ciphers, expiración certificado)
- [ ] Open redirect check básico
- [ ] Secret scanning con TruffleHog (git repos expuestos, respuestas)
- [ ] Scope filter en cada paso
- [ ] Output JSON: vulnerabilidades categorizadas por severidad

#### `full` — Scan completo

Orquesta todos los core workflows + soporte de IPs/CIDR.

- [ ] Soporte de IPs individuales y CIDR en scope
- [ ] Ejecutar `recon`
- [ ] Ejecutar `web`
- [ ] Ejecutar `vulnscan`
- [ ] Secret scanning con TruffleHog (git repos, filesystem, crawled content)
- [ ] Port scan en IPs/CIDR del scope (si aplica)
- [ ] Output JSON unificado: superficie completa + vulnerabilidades

---

### Mini-workflows

Workflows pequeños para tareas específicas. Se pueden usar standalone o como bloques reutilizables desde los core workflows.

#### `active` ✅ (ya implementado)

Subfinder → httpx. Descubre subdominios y comprueba cuáles tienen servicio web.

#### `subdomains`

Solo enumeración de subdominios (pasivo + activo), sin probing.

- [ ] Subfinder (pasivo)
- [ ] Subfinder recursivo
- [ ] Resolución DNS (dnsx)
- [ ] Dedup + scope filter
- [ ] Output: lista limpia de subdominios

#### `alive`

Solo comprobar qué hosts de una lista están activos.

- [ ] Input: lista de hosts (fichero o stdin)
- [ ] httpx probe
- [ ] Output: hosts alive con status code, título, server

#### `techdetect`

Detectar tecnologías en hosts alive.

- [ ] Input: lista de URLs/hosts alive
- [ ] wappalyzergo fingerprinting
- [ ] Output JSON: host → tecnologías detectadas

#### `crawl`

Crawling y extracción de endpoints.

- [ ] Input: lista de URLs alive
- [ ] Katana crawl (robots.txt, sitemap, links, JS)
- [ ] Extracción de endpoints JS
- [ ] Extracción de parámetros JS
- [ ] Output: URLs descubiertas

#### `urls`

Recolección de URLs históricas + crawling.

- [ ] gau (Wayback, Common Crawl, etc.)
- [ ] katana crawl
- [ ] Dedup + scope filter
- [ ] Output: lista unificada de URLs

#### `headers`

Auditoría de security headers y configuración.

- [ ] Input: lista de URLs alive
- [ ] Security headers check (CSP, HSTS, X-Frame, X-Content-Type, Referrer-Policy, Permissions-Policy)
- [ ] Cookie flags check (HttpOnly, Secure, SameSite)
- [ ] CORS misconfiguration check
- [ ] SSL/TLS check (versión, ciphers, cert expiry)
- [ ] Output JSON: findings por host

#### `takeover`

Detección de subdomain takeover.

- [ ] Input: lista de subdominios
- [ ] Resolución CNAME
- [ ] Check si el CNAME apunta a servicio abandonado (S3, GitHub Pages, Heroku, etc.)
- [ ] Output: subdominios vulnerables + servicio

#### `secrets` ✅ (implementado)

Escaneo de secretos filtrados usando TruffleHog (800+ detectores).

- [x] Scan de repositorios git (por URL) para secretos
- [x] Scan de filesystem/directorio local para secretos
- [x] 800+ detectores (API keys, tokens, passwords, AWS, GCP, etc.)
- [x] Output JSON: tipo detector, verificado, redactado, fuente
- [x] API pública (`ScanGitRepo()`, `ScanPath()`) para uso desde otros workflows

#### `gitexpose`

Detección de repositorios git expuestos + escaneo de secretos.

- [ ] Input: lista de URLs alive
- [ ] Check `/.git/HEAD`, `/.git/config`
- [ ] Si `.git` expuesto → scan con TruffleHog para secretos
- [ ] Output: hosts con git expuesto + secretos encontrados
