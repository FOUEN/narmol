package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/FOUEN/narmol/internal/scope"
	"github.com/FOUEN/narmol/internal/workflows"

	"github.com/projectdiscovery/goflags"
	httpx_runner "github.com/projectdiscovery/httpx/runner"
	katana_standard "github.com/projectdiscovery/katana/pkg/engine/standard"
	katana_output "github.com/projectdiscovery/katana/pkg/output"
	katana_types "github.com/projectdiscovery/katana/pkg/types"
	katana_queue "github.com/projectdiscovery/katana/pkg/utils/queue"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	nuclei_output "github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	subfinder_runner "github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

func init() {
	workflows.Register(&WebWorkflow{})
}

// WebWorkflow performs full web application reconnaissance and vulnerability scanning.
// Pipeline:
//  1. subfinder   — discover subdomains (if wildcard scope)
//  2. httpx       — probe live hosts, detect technologies, extract titles
//  3. katana      — crawl live hosts to find endpoints, forms, JS files
//  4. nuclei      — scan all discovered URLs for vulnerabilities
type WebWorkflow struct{}

func (w *WebWorkflow) Name() string { return "web" }

func (w *WebWorkflow) Description() string {
	return "Full web audit: subdomain discovery → live probe → crawling → vulnerability scan."
}

func (w *WebWorkflow) Run(domain string, s *scope.Scope, opts workflows.OutputOptions) error {
	if !s.IsInScope(domain) {
		return fmt.Errorf("domain %s is not in scope", domain)
	}

	// ── Output files ──────────────────────────────────────────────────
	var textFile, jsonFile *os.File
	var err error
	if opts.TextFile != "" {
		textFile, err = os.OpenFile(opts.TextFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open text output: %w", err)
		}
		defer textFile.Close()
	}
	if opts.JSONFile != "" {
		jsonFile, err = os.OpenFile(opts.JSONFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open JSON output: %w", err)
		}
		defer jsonFile.Close()
	}

	emit := func(r webResult) {
		if textFile == nil && jsonFile == nil {
			fmt.Println(r.summary())
		}
		if textFile != nil {
			fmt.Fprintln(textFile, r.summary())
		}
		if jsonFile != nil {
			if js, jErr := json.Marshal(r); jErr == nil {
				fmt.Fprintln(jsonFile, string(js))
			}
		}
	}

	seen := &sync.Map{}
	emitUnique := func(r webResult) bool {
		key := r.Phase + ":" + r.Value
		if _, loaded := seen.LoadOrStore(key, true); loaded {
			return false
		}
		emit(r)
		return true
	}

	// ── Step 1: Subfinder ─────────────────────────────────────────────
	var hosts []string
	if s.HasWildcard(domain) {
		hosts = w.runSubfinder(domain, s)
	}
	// Always include the domain itself
	hosts = appendUnique(hosts, domain)

	fmt.Printf("[+] %d hosts to probe\n", len(hosts))

	// ── Step 2: httpx — probe live hosts ──────────────────────────────
	liveHosts := w.runHttpx(hosts, s, emitUnique)

	if len(liveHosts) == 0 {
		fmt.Println("[!] No live hosts found — stopping workflow")
		return nil
	}
	fmt.Printf("[+] %d live hosts found\n", len(liveHosts))

	// ── Step 3: katana — crawl live hosts ─────────────────────────────
	endpoints := w.runKatana(liveHosts, s, emitUnique)
	_ = endpoints // crawled endpoints are emitted for output but nuclei only needs base hosts

	// Nuclei templates already contain the paths to probe (/.env, /wp-admin/, etc.)
	// Passing all crawled endpoints (JS, CSS, images, API paths) would multiply
	// scan time by orders of magnitude for no real gain.
	fmt.Printf("[+] %d live hosts as nuclei targets (crawled %d endpoints)\n", len(liveHosts), len(endpoints))

	// ── Step 4: nuclei — vulnerability scan ───────────────────────────
	vulnCount := w.runNuclei(liveHosts, emitUnique)

	// ── Summary ───────────────────────────────────────────────────────
	if opts.TextFile != "" {
		fmt.Printf("[+] Text results saved to: %s\n", opts.TextFile)
	}
	if opts.JSONFile != "" {
		fmt.Printf("[+] JSON results saved to: %s\n", opts.JSONFile)
	}
	fmt.Printf("[+] Workflow 'web' completed — %d live, %d endpoints, %d vulns\n",
		len(liveHosts), len(endpoints), vulnCount)
	return nil
}

// ─── Step 1: Subfinder ──────────────────────────────────────────────────

func (w *WebWorkflow) runSubfinder(domain string, s *scope.Scope) []string {
	fmt.Println("[*] Running subfinder...")

	var mu sync.Mutex
	var hosts []string
	var total, inScope int64

	sfOptions := &subfinder_runner.Options{
		Domain:             goflags.StringSlice{domain},
		Silent:             true,
		All:                false,
		Timeout:            30,
		MaxEnumerationTime: 10,
		Threads:            10,
		DisableUpdateCheck: true,
		Output:             io.Discard,
		ResultCallback: func(result *resolve.HostEntry) {
			atomic.AddInt64(&total, 1)
			host := strings.TrimSpace(result.Host)
			if host == "" || !s.IsInScope(host) {
				return
			}
			atomic.AddInt64(&inScope, 1)
			mu.Lock()
			hosts = append(hosts, host)
			mu.Unlock()
		},
	}

	sfRunner, err := subfinder_runner.NewRunner(sfOptions)
	if err != nil {
		fmt.Printf("[!] Could not create subfinder runner: %s\n", err)
		return nil
	}
	_ = sfRunner.RunEnumerationWithCtx(context.Background())

	fmt.Printf("[+] Subfinder found %d subdomains (%d in scope)\n", total, inScope)
	return hosts
}

// ─── Step 2: httpx ──────────────────────────────────────────────────────

func (w *WebWorkflow) runHttpx(hosts []string, s *scope.Scope, emitUnique func(webResult) bool) []string {
	fmt.Printf("[*] Probing %d hosts with httpx...\n", len(hosts))

	var mu sync.Mutex
	var liveHosts []string

	hxOptions := &httpx_runner.Options{
		InputTargetHost:    goflags.StringSlice(hosts),
		Silent:             true,
		DisableStdout:      true,
		Threads:            50,
		Timeout:            10,
		DisableUpdateCheck: true,
		DisableStdin:       true,
		NoColor:            true,
		FollowRedirects:    true,
		MaxRedirects:       10,
		RateLimit:          150,
		Retries:            0,
		HostMaxErrors:      30,
		RandomAgent:        true,
		TechDetect:         true,
		OutputCDN:          "true",
		ExtractTitle:       true,
		OnResult: func(r httpx_runner.Result) {
			if r.Err != nil {
				return
			}

			emitUnique(webResult{
				Phase:      "probe",
				Value:      r.URL,
				Host:       r.Host,
				StatusCode: r.StatusCode,
				Title:      r.Title,
				Tech:       r.Technologies,
				Webserver:  r.WebServer,
				CDN:        r.CDN,
				CDNName:    r.CDNName,
			})

			mu.Lock()
			liveHosts = append(liveHosts, r.URL)
			mu.Unlock()
		},
	}

	if err := hxOptions.ValidateOptions(); err != nil {
		fmt.Printf("[!] httpx options error: %s\n", err)
		return nil
	}

	hxRunner, err := httpx_runner.New(hxOptions)
	if err != nil {
		fmt.Printf("[!] Could not create httpx runner: %s\n", err)
		return nil
	}

	hxRunner.RunEnumeration()
	hxRunner.Close()

	return liveHosts
}

// ─── Step 3: Katana ─────────────────────────────────────────────────────

func (w *WebWorkflow) runKatana(liveHosts []string, s *scope.Scope, emitUnique func(webResult) bool) []string {
	fmt.Printf("[*] Crawling %d live hosts with katana...\n", len(liveHosts))

	var mu sync.Mutex
	var endpoints []string

	ktOptions := &katana_types.Options{
		MaxDepth:           3,
		BodyReadSize:       math.MaxInt,
		Timeout:            10,
		RateLimit:          150,
		Concurrency:        10,
		Parallelism:        10,
		Strategy:           katana_queue.DepthFirst.String(),
		FieldScope:         "rdn",
		Silent:             true,
		DisableUpdateCheck: true,
		ScrapeJSResponses:  true,
		IgnoreQueryParams:  true,
		OnResult: func(r katana_output.Result) {
			if r.Request == nil || r.Request.URL == "" {
				return
			}
			u := r.Request.URL
			if !s.IsInScope(u) {
				return
			}
			if emitUnique(webResult{
				Phase: "crawl",
				Value: u,
			}) {
				mu.Lock()
				endpoints = append(endpoints, u)
				mu.Unlock()
			}
		},
	}

	crawlerOptions, err := katana_types.NewCrawlerOptions(ktOptions)
	if err != nil {
		fmt.Printf("[!] Could not create katana crawler options: %s\n", err)
		return nil
	}
	defer crawlerOptions.Close()

	crawler, err := katana_standard.New(crawlerOptions)
	if err != nil {
		fmt.Printf("[!] Could not create katana crawler: %s\n", err)
		return nil
	}
	defer crawler.Close()

	// Crawl each live host
	for _, host := range liveHosts {
		if err := crawler.Crawl(host); err != nil {
			fmt.Printf("[!] Katana crawl error for %s: %s\n", host, err)
		}
	}

	fmt.Printf("[+] Katana discovered %d unique endpoints\n", len(endpoints))
	return endpoints
}

// ─── Step 4: Nuclei ─────────────────────────────────────────────────────

func (w *WebWorkflow) runNuclei(targets []string, emitUnique func(webResult) bool) int64 {
	fmt.Printf("[*] Scanning %d targets with nuclei...\n", len(targets))

	var vulnCount int64
	ctx := context.Background()

	ne, err := nuclei.NewNucleiEngineCtx(ctx,
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			Severity: "medium,high,critical",
		}),
		nuclei.WithConcurrency(nuclei.Concurrency{
			TemplateConcurrency:           25,
			HostConcurrency:               25,
			HeadlessHostConcurrency:       5,
			HeadlessTemplateConcurrency:    5,
			JavascriptTemplateConcurrency: 10,
			TemplatePayloadConcurrency:    25,
			ProbeConcurrency:              50,
		}),
		nuclei.WithVerbosity(nuclei.VerbosityOptions{Silent: true}),
		nuclei.DisableUpdateCheck(),
	)
	if err != nil {
		fmt.Printf("[!] Could not create nuclei engine: %s\n", err)
		return 0
	}
	defer ne.Close()

	if err := ne.LoadAllTemplates(); err != nil {
		fmt.Printf("[!] Could not load nuclei templates: %s\n", err)
		return 0
	}

	ne.LoadTargets(targets, false)

	if err := ne.ExecuteCallbackWithCtx(ctx, func(event *nuclei_output.ResultEvent) {
		severity := event.Info.SeverityHolder.Severity.String()
		emitUnique(webResult{
			Phase:      "vuln",
			Value:      event.Matched,
			Host:       event.Host,
			TemplateID: event.TemplateID,
			VulnName:   event.Info.Name,
			Severity:   severity,
			VulnType:   event.Type,
		})
		atomic.AddInt64(&vulnCount, 1)
	}); err != nil {
		fmt.Printf("[!] Nuclei scan error: %s\n", err)
	}

	fmt.Printf("[+] Nuclei found %d vulnerabilities\n", atomic.LoadInt64(&vulnCount))
	return atomic.LoadInt64(&vulnCount)
}

// ─── Result types ───────────────────────────────────────────────────────

// webResult is the unified result type for all phases of the web workflow.
type webResult struct {
	Phase      string   `json:"phase"`                 // "probe", "crawl", "vuln"
	Value      string   `json:"value"`                 // URL or matched-at
	Host       string   `json:"host,omitempty"`        // target host
	StatusCode int      `json:"status_code,omitempty"` // HTTP status
	Title      string   `json:"title,omitempty"`       // page title
	Tech       []string `json:"tech,omitempty"`        // detected technologies
	Webserver  string   `json:"webserver,omitempty"`   // server header
	CDN        bool     `json:"cdn,omitempty"`         // behind CDN
	CDNName    string   `json:"cdn_name,omitempty"`    // CDN name
	TemplateID string   `json:"template_id,omitempty"` // nuclei template
	VulnName   string   `json:"vuln_name,omitempty"`   // vulnerability name
	Severity   string   `json:"severity,omitempty"`    // low/medium/high/critical
	VulnType   string   `json:"vuln_type,omitempty"`   // http/dns/network/etc
}

func (r webResult) summary() string {
	switch r.Phase {
	case "probe":
		tech := ""
		if len(r.Tech) > 0 {
			tech = " [" + strings.Join(r.Tech, ", ") + "]"
		}
		title := ""
		if r.Title != "" {
			title = " - " + r.Title
		}
		return fmt.Sprintf("[LIVE] %s (%d)%s%s", r.Value, r.StatusCode, title, tech)
	case "crawl":
		return fmt.Sprintf("[ENDPOINT] %s", r.Value)
	case "vuln":
		return fmt.Sprintf("[%s] %s — %s (%s)", strings.ToUpper(r.Severity), r.Value, r.VulnName, r.TemplateID)
	default:
		return r.Value
	}
}

// ─── Helpers ────────────────────────────────────────────────────────────

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
