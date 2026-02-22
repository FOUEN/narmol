package web

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FOUEN/narmol/internal/scope"
	"github.com/FOUEN/narmol/internal/workflows"
	"github.com/FOUEN/narmol/internal/workflows/secrets"

	"github.com/projectdiscovery/goflags"
	httpx_runner "github.com/projectdiscovery/httpx/runner"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
	nuclei_output "github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	subfinder_runner "github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

func init() {
	workflows.Register(&WebWorkflow{})
}

// WebWorkflow performs web audit using a Nessus-style approach:
// fingerprint first, then run only vulnerability checks relevant to the detected stack.
// Pipeline:
//  1. subfinder   — discover subdomains (if wildcard scope)
//  2. httpx       — probe + fingerprint (tech detection, server, CDN)
//  3. nuclei      — targeted vuln scan (templates filtered by detected technologies)
type WebWorkflow struct{}

func (w *WebWorkflow) Name() string { return "web" }

func (w *WebWorkflow) Description() string {
	return "Web audit: discovery → fingerprint → targeted vuln scan (Nessus-style)."
}

func (w *WebWorkflow) Run(domain string, s *scope.Scope, opts workflows.OutputOptions) error {
	if !s.IsInScope(domain) {
		return fmt.Errorf("domain %s is not in scope", domain)
	}

	// ── Report collector ──────────────────────────────────────────────
	report := &webReport{
		Target: domain,
		Date:   time.Now().UTC().Format(time.RFC3339),
	}

	seen := &sync.Map{}
	collect := func(r webResult) bool {
		key := r.Phase + ":" + r.Value
		if _, loaded := seen.LoadOrStore(key, true); loaded {
			return false
		}
		report.add(r)
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

	// ── Step 2: httpx — probe + fingerprint ───────────────────────────
	liveHosts, techSet := w.runHttpx(hosts, s, collect)

	if len(liveHosts) == 0 {
		fmt.Println("[!] No live hosts found — stopping workflow")
		return nil
	}
	fmt.Printf("[+] %d live hosts found, %d unique technologies detected\n", len(liveHosts), len(techSet))

	// ── Step 3: nuclei + trufflehog + security checks IN PARALLEL ─────
	tags := buildNucleiTags(techSet)
	fmt.Printf("[+] Nuclei tags from fingerprint: %s\n", strings.Join(tags, ", "))

	var wg sync.WaitGroup

	// 3a. Nuclei — targeted vulnerability scan
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.runNuclei(liveHosts, tags, collect)
	}()

	// 3b. TruffleHog — check for exposed .git repos and scan for secrets
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.runGitExposureCheck(liveHosts, collect)
	}()

	// 3c. Security header checks — CORS, missing headers, cookies (stdlib)
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.runSecurityHeaderChecks(liveHosts, collect)
	}()

	// 3d. SSL/TLS configuration checks (stdlib crypto/tls)
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.runTLSChecks(liveHosts, collect)
	}()

	// 3e. Open redirect detection (stdlib)
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.runOpenRedirectChecks(liveHosts, collect)
	}()

	// 3f. HTTP request smuggling detection (stdlib net)
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.runSmugglingChecks(liveHosts, collect)
	}()

	wg.Wait()

	// ── Generate & write report ───────────────────────────────────────
	report.HostsDiscovered = len(hosts)
	report.HostsLive = len(liveHosts)
	report.TechCount = len(techSet)
	return report.write(opts)
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

func (w *WebWorkflow) runHttpx(hosts []string, s *scope.Scope, emitUnique func(webResult) bool) ([]string, map[string]struct{}) {
	fmt.Printf("[*] Probing %d hosts with httpx...\n", len(hosts))

	var mu sync.Mutex
	var liveHosts []string
	techSet := make(map[string]struct{})

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
			for _, t := range r.Technologies {
				techSet[strings.ToLower(t)] = struct{}{}
			}
			if r.WebServer != "" {
				// Extract base server name (e.g. "nginx" from "nginx/1.19.0")
				ws := strings.ToLower(strings.Split(r.WebServer, "/")[0])
				techSet[ws] = struct{}{}
			}
			mu.Unlock()
		},
	}

	if err := hxOptions.ValidateOptions(); err != nil {
		fmt.Printf("[!] httpx options error: %s\n", err)
		return nil, techSet
	}

	hxRunner, err := httpx_runner.New(hxOptions)
	if err != nil {
		fmt.Printf("[!] Could not create httpx runner: %s\n", err)
		return nil, techSet
	}

	hxRunner.RunEnumeration()
	hxRunner.Close()

	return liveHosts, techSet
}

// ─── Step 3: Nuclei (targeted by fingerprint) ───────────────────────────

func (w *WebWorkflow) runNuclei(targets []string, tags []string, emitUnique func(webResult) bool) int64 {
	fmt.Printf("[*] Scanning %d targets with nuclei (%d tech tags)...\n", len(targets), len(tags))

	var vulnCount int64
	ctx := context.Background()

	// Ensure nuclei templates are installed (first-run auto-download)
	tm := &installer.TemplateManager{}
	if err := tm.FreshInstallIfNotExists(); err != nil {
		fmt.Printf("[!] Could not install nuclei templates: %s\n", err)
		return 0
	}

	ne, err := nuclei.NewNucleiEngineCtx(ctx,
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			Severity: "medium,high,critical",
			Tags:     tags,
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
	Phase      string   `json:"phase"`                 // "probe", "vuln", "secret", "header"
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
	Detail     string   `json:"detail,omitempty"`      // extra detail for header/secret findings
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
	case "vuln":
		return fmt.Sprintf("[%s] %s — %s (%s)", strings.ToUpper(r.Severity), r.Value, r.VulnName, r.TemplateID)
	case "secret":
		return fmt.Sprintf("[SECRET] %s — %s", r.Value, r.Detail)
	case "header":
		return fmt.Sprintf("[HEADER] %s — %s", r.Value, r.Detail)
	case "tls":
		return fmt.Sprintf("[TLS-%s] %s — %s", strings.ToUpper(r.Severity), r.Value, r.Detail)
	case "redirect":
		return fmt.Sprintf("[REDIRECT] %s — %s", r.Value, r.Detail)
	case "smuggling":
		return fmt.Sprintf("[SMUGGLING-%s] %s — %s", strings.ToUpper(r.Severity), r.Value, r.Detail)
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

// ─── Report types ───────────────────────────────────────────────────────

// webReport collects all findings organized by phase for structured report generation.
type webReport struct {
	mu              sync.Mutex
	Target          string
	Date            string
	HostsDiscovered int
	HostsLive       int
	TechCount       int
	Probes          []webResult
	Vulns           []webResult
	Secrets         []webResult
	Headers         []webResult
	TLS             []webResult
	Redirects       []webResult
	Smuggling       []webResult
}

func (rpt *webReport) add(r webResult) {
	rpt.mu.Lock()
	defer rpt.mu.Unlock()
	switch r.Phase {
	case "probe":
		rpt.Probes = append(rpt.Probes, r)
	case "vuln":
		rpt.Vulns = append(rpt.Vulns, r)
	case "secret":
		rpt.Secrets = append(rpt.Secrets, r)
	case "header":
		rpt.Headers = append(rpt.Headers, r)
	case "tls":
		rpt.TLS = append(rpt.TLS, r)
	case "redirect":
		rpt.Redirects = append(rpt.Redirects, r)
	case "smuggling":
		rpt.Smuggling = append(rpt.Smuggling, r)
	}
}

func (rpt *webReport) write(opts workflows.OutputOptions) error {
	textReport := rpt.formatText()

	// Always print to console
	fmt.Print(textReport)

	// Text file
	if opts.TextFile != "" {
		if err := os.WriteFile(opts.TextFile, []byte(textReport), 0644); err != nil {
			return fmt.Errorf("failed to write text report: %w", err)
		}
		fmt.Printf("[+] Text report saved to: %s\n", opts.TextFile)
	}

	// JSON file
	if opts.JSONFile != "" {
		js, err := json.MarshalIndent(rpt.jsonData(), "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON report: %w", err)
		}
		if err := os.WriteFile(opts.JSONFile, js, 0644); err != nil {
			return fmt.Errorf("failed to write JSON report: %w", err)
		}
		fmt.Printf("[+] JSON report saved to: %s\n", opts.JSONFile)
	}

	return nil
}

// reportJSON is the structured JSON output for report generation.
type reportJSON struct {
	Target  string        `json:"target"`
	Date    string        `json:"date"`
	Summary reportSummary `json:"summary"`
	Phases  reportPhases  `json:"phases"`
}

type reportSummary struct {
	HostsDiscovered int `json:"hosts_discovered"`
	HostsLive       int `json:"hosts_live"`
	Technologies    int `json:"technologies_detected"`
	Vulnerabilities int `json:"vulnerabilities"`
	Secrets         int `json:"secrets"`
	HeaderIssues    int `json:"header_issues"`
	TLSIssues       int `json:"tls_issues"`
	Redirects       int `json:"redirects"`
	Smuggling       int `json:"smuggling"`
}

type reportPhases struct {
	Discovery       []webResult `json:"discovery"`
	Vulnerabilities []webResult `json:"vulnerabilities"`
	Secrets         []webResult `json:"secrets"`
	Headers         []webResult `json:"header_issues"`
	TLS             []webResult `json:"tls_issues"`
	Redirects       []webResult `json:"redirects"`
	Smuggling       []webResult `json:"smuggling"`
}

func (rpt *webReport) jsonData() reportJSON {
	ensureSlice := func(s []webResult) []webResult {
		if s == nil {
			return []webResult{}
		}
		return s
	}
	return reportJSON{
		Target: rpt.Target,
		Date:   rpt.Date,
		Summary: reportSummary{
			HostsDiscovered: rpt.HostsDiscovered,
			HostsLive:       rpt.HostsLive,
			Technologies:    rpt.TechCount,
			Vulnerabilities: len(rpt.Vulns),
			Secrets:         len(rpt.Secrets),
			HeaderIssues:    len(rpt.Headers),
			TLSIssues:       len(rpt.TLS),
			Redirects:       len(rpt.Redirects),
			Smuggling:       len(rpt.Smuggling),
		},
		Phases: reportPhases{
			Discovery:       ensureSlice(rpt.Probes),
			Vulnerabilities: ensureSlice(rpt.Vulns),
			Secrets:         ensureSlice(rpt.Secrets),
			Headers:         ensureSlice(rpt.Headers),
			TLS:             ensureSlice(rpt.TLS),
			Redirects:       ensureSlice(rpt.Redirects),
			Smuggling:       ensureSlice(rpt.Smuggling),
		},
	}
}

func (rpt *webReport) formatText() string {
	var b strings.Builder
	line := strings.Repeat("\u2500", 70)
	doubleLine := strings.Repeat("\u2550", 70)

	// ── Header ──
	b.WriteString("\n" + doubleLine + "\n")
	b.WriteString("  NARMOL \u2014 Web Security Audit Report\n")
	b.WriteString("  Target: " + rpt.Target + "\n")
	b.WriteString("  Date:   " + rpt.Date + "\n")
	b.WriteString(doubleLine + "\n")

	// ── Phase 1: Discovery ──
	b.WriteString("\n" + line + "\n")
	b.WriteString("  1. DISCOVERY & FINGERPRINTING\n")
	b.WriteString(line + "\n")
	if len(rpt.Probes) == 0 {
		b.WriteString("  No live hosts found.\n")
	} else {
		for _, r := range rpt.Probes {
			b.WriteString("  " + r.summary() + "\n")
		}
	}

	// ── Phase 2: Vulnerabilities ──
	b.WriteString("\n" + line + "\n")
	b.WriteString("  2. VULNERABILITIES\n")
	b.WriteString(line + "\n")
	if len(rpt.Vulns) == 0 {
		b.WriteString("  No vulnerabilities found.\n")
	} else {
		sort.Slice(rpt.Vulns, func(i, j int) bool {
			return severityOrder(rpt.Vulns[i].Severity) > severityOrder(rpt.Vulns[j].Severity)
		})
		for _, r := range rpt.Vulns {
			b.WriteString("  " + r.summary() + "\n")
		}
	}

	// ── Phase 3: Secrets ──
	b.WriteString("\n" + line + "\n")
	b.WriteString("  3. SECRETS & EXPOSURES\n")
	b.WriteString(line + "\n")
	if len(rpt.Secrets) == 0 {
		b.WriteString("  No secrets or exposures found.\n")
	} else {
		for _, r := range rpt.Secrets {
			b.WriteString("  " + r.summary() + "\n")
		}
	}

	// ── Phase 4: Headers ──
	b.WriteString("\n" + line + "\n")
	b.WriteString("  4. SECURITY HEADERS\n")
	b.WriteString(line + "\n")
	if len(rpt.Headers) == 0 {
		b.WriteString("  No header issues found.\n")
	} else {
		for _, r := range rpt.Headers {
			b.WriteString("  " + r.summary() + "\n")
		}
	}

	// ── Phase 5: TLS ──
	b.WriteString("\n" + line + "\n")
	b.WriteString("  5. TLS / SSL CONFIGURATION\n")
	b.WriteString(line + "\n")
	if len(rpt.TLS) == 0 {
		b.WriteString("  No TLS issues found.\n")
	} else {
		for _, r := range rpt.TLS {
			b.WriteString("  " + r.summary() + "\n")
		}
	}

	// ── Phase 6: Redirects ──
	b.WriteString("\n" + line + "\n")
	b.WriteString("  6. OPEN REDIRECTS\n")
	b.WriteString(line + "\n")
	if len(rpt.Redirects) == 0 {
		b.WriteString("  No open redirects found.\n")
	} else {
		for _, r := range rpt.Redirects {
			b.WriteString("  " + r.summary() + "\n")
		}
	}

	// ── Phase 7: Smuggling ──
	b.WriteString("\n" + line + "\n")
	b.WriteString("  7. HTTP REQUEST SMUGGLING\n")
	b.WriteString(line + "\n")
	if len(rpt.Smuggling) == 0 {
		b.WriteString("  No smuggling issues found.\n")
	} else {
		for _, r := range rpt.Smuggling {
			b.WriteString("  " + r.summary() + "\n")
		}
	}

	// ── Summary ──
	b.WriteString("\n" + doubleLine + "\n")
	b.WriteString("  SUMMARY\n")
	b.WriteString(doubleLine + "\n")
	b.WriteString(fmt.Sprintf("  Hosts:           %d discovered, %d live\n", rpt.HostsDiscovered, rpt.HostsLive))
	b.WriteString(fmt.Sprintf("  Technologies:    %d detected\n", rpt.TechCount))
	b.WriteString(fmt.Sprintf("  Vulnerabilities: %s\n", rpt.vulnBreakdown()))
	b.WriteString(fmt.Sprintf("  Secrets:         %d\n", len(rpt.Secrets)))
	b.WriteString(fmt.Sprintf("  Header Issues:   %d\n", len(rpt.Headers)))
	b.WriteString(fmt.Sprintf("  TLS Issues:      %d\n", len(rpt.TLS)))
	b.WriteString(fmt.Sprintf("  Redirects:       %d\n", len(rpt.Redirects)))
	b.WriteString(fmt.Sprintf("  Smuggling:       %d\n", len(rpt.Smuggling)))
	b.WriteString(doubleLine + "\n")

	return b.String()
}

func (rpt *webReport) vulnBreakdown() string {
	if len(rpt.Vulns) == 0 {
		return "0"
	}
	counts := map[string]int{}
	for _, v := range rpt.Vulns {
		counts[v.Severity]++
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if c, ok := counts[sev]; ok && c > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c, sev))
		}
	}
	return fmt.Sprintf("%d (%s)", len(rpt.Vulns), strings.Join(parts, ", "))
}

func severityOrder(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// ─── Nessus-style fingerprint → tag mapping ───────────────────────────────

// alwaysTags are generic check categories that always run regardless of tech stack.
// Mirrors Nessus: exposed files, misconfigurations, default credentials.
var alwaysTags = []string{
	"exposure", "misconfig", "default-login", "takeover", "config",
}

// techTagMap maps wappalyzer technology names (lowercase) to nuclei template tags.
// This is the core of the Nessus-style approach: fingerprint → relevant plugins only.
var techTagMap = map[string][]string{
	"wordpress":        {"wordpress", "wp", "wp-plugin", "wp-theme"},
	"joomla":           {"joomla"},
	"drupal":           {"drupal"},
	"magento":          {"magento"},
	"shopify":          {"shopify"},
	"nginx":            {"nginx"},
	"apache":           {"apache"},
	"iis":              {"iis"},
	"tomcat":           {"tomcat", "apache-tomcat"},
	"lighttpd":         {"lighttpd"},
	"caddy":            {"caddy"},
	"php":              {"php"},
	"java":             {"java"},
	"asp.net":          {"asp", "aspx", "iis"},
	"python":           {"python"},
	"ruby":             {"ruby", "rails"},
	"node.js":          {"nodejs"},
	"jenkins":          {"jenkins"},
	"jira":             {"jira", "atlassian"},
	"confluence":       {"confluence", "atlassian"},
	"bitbucket":        {"bitbucket", "atlassian"},
	"gitlab":           {"gitlab"},
	"grafana":          {"grafana"},
	"kibana":           {"kibana", "elastic"},
	"elasticsearch":    {"elasticsearch", "elastic"},
	"spring":           {"spring", "springboot"},
	"spring boot":      {"spring", "springboot"},
	"laravel":          {"laravel", "php"},
	"django":           {"django", "python"},
	"flask":            {"flask", "python"},
	"express":          {"express", "nodejs"},
	"next.js":          {"nextjs", "nodejs"},
	"nuxt.js":          {"nuxtjs", "nodejs"},
	"react":            {"react"},
	"angular":          {"angular"},
	"vue.js":           {"vuejs"},
	"cloudflare":       {"cloudflare"},
	"varnish":          {"varnish"},
	"docker":           {"docker"},
	"kubernetes":       {"kubernetes", "k8s"},
	"mongodb":          {"mongodb"},
	"mysql":            {"mysql"},
	"postgresql":       {"postgresql", "postgres"},
	"redis":            {"redis"},
	"rabbitmq":         {"rabbitmq"},
	"apache solr":      {"solr", "apache"},
	"apache struts":    {"struts", "apache"},
	"apache airflow":   {"airflow", "apache"},
	"sonarqube":        {"sonarqube"},
	"moodle":           {"moodle"},
	"phpmyadmin":       {"phpmyadmin", "php"},
	"webmin":           {"webmin"},
	"zimbra":           {"zimbra"},
	"citrix":           {"citrix"},
	"fortinet":         {"fortinet", "fortigate"},
	"palo alto":        {"paloalto"},
	"sonicwall":        {"sonicwall"},
	"microsoft exchange": {"exchange", "microsoft"},
	"microsoft sharepoint": {"sharepoint", "microsoft"},
	"outlook":          {"outlook", "microsoft"},
	"swagger":          {"swagger", "api"},
	"graphql":          {"graphql", "api"},
}

// buildNucleiTags converts detected technologies into nuclei template tags.
// This is the key optimization: instead of running all 10k+ templates, we only
// run templates relevant to the detected stack + generic exposure/misconfig checks.
func buildNucleiTags(techSet map[string]struct{}) []string {
	tagSet := make(map[string]struct{})

	// Always include generic check categories
	for _, t := range alwaysTags {
		tagSet[t] = struct{}{}
	}

	// Map detected techs to nuclei tags
	for tech := range techSet {
		tech = strings.ToLower(strings.TrimSpace(tech))
		if tech == "" {
			continue
		}
		if mapped, ok := techTagMap[tech]; ok {
			for _, tag := range mapped {
				tagSet[tag] = struct{}{}
			}
		} else {
			// Direct mapping: use lowercased tech name as tag (many match directly)
			tagSet[tech] = struct{}{}
		}
	}

	tags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	return tags
}

// ─── Git Exposure + TruffleHog ──────────────────────────────────────────

// runGitExposureCheck checks each live host for exposed .git/HEAD.
// If found, runs TruffleHog to scan for leaked secrets in the exposed repo.
func (w *WebWorkflow) runGitExposureCheck(liveHosts []string, emitUnique func(webResult) bool) int64 {
	fmt.Printf("[*] Checking %d hosts for .git exposure...\n", len(liveHosts))

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
			DialContext: (&net.Dialer{
				Timeout: 3 * time.Second,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}

	var count int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20) // concurrency limiter

	for _, host := range liveHosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			gitURL := strings.TrimRight(h, "/") + "/.git/HEAD"
			resp, err := client.Get(gitURL)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			// Read small body to check for git signature
			buf := make([]byte, 256)
			n, _ := resp.Body.Read(buf)
			body := string(buf[:n])

			if resp.StatusCode == 200 && strings.HasPrefix(body, "ref: refs/") {
				emitUnique(webResult{
					Phase:    "secret",
					Value:    h,
					Severity: "high",
					Detail:   ".git repository exposed — scanning for secrets",
				})

				// Run TruffleHog on the exposed git repo
				results, err := secrets.ScanGitRepo(h)
				if err != nil {
					fmt.Printf("[!] TruffleHog error for %s: %s\n", h, err)
					return
				}
				for _, sr := range results {
					emitUnique(webResult{
						Phase:    "secret",
						Value:    h,
						Severity: "critical",
						Detail:   fmt.Sprintf("[%s] %s", sr.DetectorType, sr.Redacted),
					})
					atomic.AddInt64(&count, 1)
				}
			}
		}(host)
	}

	wg.Wait()
	exposures := atomic.LoadInt64(&count)
	fmt.Printf("[+] Git exposure check done — %d secrets found\n", exposures)
	return exposures
}

// ─── Security Header Checks (stdlib) ────────────────────────────────────

// requiredHeaders are security headers that should be present on any web application.
var requiredHeaders = []struct {
	Name     string
	Severity string
}{
	{"Strict-Transport-Security", "medium"},
	{"X-Content-Type-Options", "low"},
	{"X-Frame-Options", "medium"},
	{"Content-Security-Policy", "medium"},
	{"Referrer-Policy", "low"},
	{"Permissions-Policy", "low"},
}

// runSecurityHeaderChecks performs fast HTTP requests to check for missing security
// headers, CORS misconfigurations, and insecure cookies. Pure stdlib, no external tools.
func (w *WebWorkflow) runSecurityHeaderChecks(liveHosts []string, emitUnique func(webResult) bool) int64 {
	fmt.Printf("[*] Checking security headers on %d hosts...\n", len(liveHosts))

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
			DialContext: (&net.Dialer{
				Timeout: 3 * time.Second,
			}).DialContext,
		},
	}

	var count int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20) // concurrency limiter

	for _, host := range liveHosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			req, err := http.NewRequest("GET", h, nil)
			if err != nil {
				return
			}
			req.Header.Set("Origin", "https://evil.com")
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			// Check missing security headers
			for _, hdr := range requiredHeaders {
				if resp.Header.Get(hdr.Name) == "" {
					if emitUnique(webResult{
						Phase:    "header",
						Value:    h,
						Severity: hdr.Severity,
						Detail:   "Missing " + hdr.Name,
					}) {
						atomic.AddInt64(&count, 1)
					}
				}
			}

			// Check CORS misconfiguration
			acao := resp.Header.Get("Access-Control-Allow-Origin")
			if acao == "*" || acao == "https://evil.com" {
				if emitUnique(webResult{
					Phase:    "header",
					Value:    h,
					Severity: "high",
					Detail:   fmt.Sprintf("CORS misconfiguration: Access-Control-Allow-Origin: %s", acao),
				}) {
					atomic.AddInt64(&count, 1)
				}
			}

			// Check ACAO with credentials (very dangerous)
			acac := resp.Header.Get("Access-Control-Allow-Credentials")
			if acac == "true" && (acao == "*" || acao == "https://evil.com") {
				if emitUnique(webResult{
					Phase:    "header",
					Value:    h,
					Severity: "critical",
					Detail:   "CORS with credentials: origin reflected + Allow-Credentials: true",
				}) {
					atomic.AddInt64(&count, 1)
				}
			}

			// Check insecure cookies
			for _, cookie := range resp.Cookies() {
				var issues []string
				if !cookie.Secure && strings.HasPrefix(h, "https://") {
					issues = append(issues, "missing Secure")
				}
				if !cookie.HttpOnly {
					issues = append(issues, "missing HttpOnly")
				}
				if cookie.SameSite == http.SameSiteNoneMode || cookie.SameSite == 0 {
					issues = append(issues, "missing/weak SameSite")
				}
				if len(issues) > 0 {
					if emitUnique(webResult{
						Phase:    "header",
						Value:    h,
						Severity: "low",
						Detail:   fmt.Sprintf("Cookie '%s': %s", cookie.Name, strings.Join(issues, ", ")),
					}) {
						atomic.AddInt64(&count, 1)
					}
				}
			}
		}(host)
	}

	wg.Wait()
	total := atomic.LoadInt64(&count)
	fmt.Printf("[+] Security header checks done — %d issues found\n", total)
	return total
}

// ─── SSL/TLS Configuration Checks ──────────────────────────────────────

// weakCiphers contains TLS cipher suites considered insecure.
var weakCiphers = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:                "RC4-SHA",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           "3DES-CBC-SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "RSA-AES128-CBC-SHA",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:            "RSA-AES256-CBC-SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:         "RSA-AES128-CBC-SHA256",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          "ECDHE-RC4-SHA",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     "ECDHE-3DES-CBC-SHA",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        "ECDHE-ECDSA-RC4-SHA",
}

// runTLSChecks checks SSL/TLS configuration: protocol versions, weak ciphers, cert validity.
func (w *WebWorkflow) runTLSChecks(liveHosts []string, emitUnique func(webResult) bool) int64 {
	// Filter to HTTPS hosts only
	var httpsHosts []string
	for _, h := range liveHosts {
		if strings.HasPrefix(h, "https://") {
			httpsHosts = append(httpsHosts, h)
		}
	}
	if len(httpsHosts) == 0 {
		return 0
	}

	fmt.Printf("[*] Checking TLS config on %d HTTPS hosts...\n", len(httpsHosts))

	var count int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for _, host := range httpsHosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			parsed, err := url.Parse(h)
			if err != nil {
				return
			}
			hostname := parsed.Hostname()
			port := parsed.Port()
			if port == "" {
				port = "443"
			}
			addr := net.JoinHostPort(hostname, port)

			// Connect with TLS and inspect the negotiated connection
			conn, err := tls.DialWithDialer(
				&net.Dialer{Timeout: 5 * time.Second},
				"tcp", addr,
				&tls.Config{
					InsecureSkipVerify: true,
					// Try to negotiate with all versions to detect what server accepts
				},
			)
			if err != nil {
				return
			}
			defer conn.Close()

			state := conn.ConnectionState()

			// Check protocol version
			switch state.Version {
			case tls.VersionTLS10:
				if emitUnique(webResult{
					Phase: "tls", Value: h, Severity: "high",
					Detail: "TLS 1.0 supported (deprecated, vulnerable to BEAST/POODLE)",
				}) {
					atomic.AddInt64(&count, 1)
				}
			case tls.VersionTLS11:
				if emitUnique(webResult{
					Phase: "tls", Value: h, Severity: "medium",
					Detail: "TLS 1.1 supported (deprecated)",
				}) {
					atomic.AddInt64(&count, 1)
				}
			}

			// Check for weak cipher suite
			if name, weak := weakCiphers[state.CipherSuite]; weak {
				if emitUnique(webResult{
					Phase: "tls", Value: h, Severity: "high",
					Detail: fmt.Sprintf("Weak cipher suite: %s", name),
				}) {
					atomic.AddInt64(&count, 1)
				}
			}

			// Check certificate validity
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				now := time.Now()

				// Expired certificate
				if now.After(cert.NotAfter) {
					if emitUnique(webResult{
						Phase: "tls", Value: h, Severity: "high",
						Detail: fmt.Sprintf("Certificate expired: %s", cert.NotAfter.Format("2006-01-02")),
					}) {
						atomic.AddInt64(&count, 1)
					}
				}

				// Certificate expiring within 30 days
				if now.Before(cert.NotAfter) && cert.NotAfter.Before(now.Add(30*24*time.Hour)) {
					if emitUnique(webResult{
						Phase: "tls", Value: h, Severity: "medium",
						Detail: fmt.Sprintf("Certificate expiring soon: %s", cert.NotAfter.Format("2006-01-02")),
					}) {
						atomic.AddInt64(&count, 1)
					}
				}

				// Self-signed certificate
				if cert.Issuer.CommonName == cert.Subject.CommonName {
					pool := x509.NewCertPool()
					pool.AddCert(cert)
					_, verifyErr := cert.Verify(x509.VerifyOptions{Roots: pool})
					if verifyErr == nil {
						if emitUnique(webResult{
							Phase: "tls", Value: h, Severity: "medium",
							Detail: "Self-signed certificate",
						}) {
							atomic.AddInt64(&count, 1)
						}
					}
				}

				// Hostname mismatch
				if err := cert.VerifyHostname(hostname); err != nil {
					if emitUnique(webResult{
						Phase: "tls", Value: h, Severity: "high",
						Detail: fmt.Sprintf("Certificate hostname mismatch: cert for %s", strings.Join(cert.DNSNames, ", ")),
					}) {
						atomic.AddInt64(&count, 1)
					}
				}
			}
		}(host)
	}

	wg.Wait()
	total := atomic.LoadInt64(&count)
	fmt.Printf("[+] TLS checks done — %d issues found\n", total)
	return total
}

// ─── Open Redirect Detection ────────────────────────────────────────────

// openRedirectPayloads are common parameter-based redirect payloads.
var openRedirectParams = []string{
	"url", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
	"returnTo", "next", "goto", "target", "destination", "dest", "rurl",
	"continue", "forward", "out", "view", "login_url", "callback",
}

// runOpenRedirectChecks tests each live host for basic open redirect via common parameters.
func (w *WebWorkflow) runOpenRedirectChecks(liveHosts []string, emitUnique func(webResult) bool) int64 {
	fmt.Printf("[*] Checking %d hosts for open redirects...\n", len(liveHosts))

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout: 3 * time.Second,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow — we inspect the Location header
		},
	}

	var count int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	canary := "https://evil.com/pwned"

	for _, host := range liveHosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			for _, param := range openRedirectParams {
				testURL := fmt.Sprintf("%s/?%s=%s", strings.TrimRight(h, "/"), param, url.QueryEscape(canary))

				resp, err := client.Get(testURL)
				if err != nil {
					continue
				}
				resp.Body.Close()

				if resp.StatusCode >= 300 && resp.StatusCode < 400 {
					location := resp.Header.Get("Location")
					if strings.HasPrefix(location, "https://evil.com") || strings.HasPrefix(location, "//evil.com") {
						if emitUnique(webResult{
							Phase: "redirect", Value: h, Severity: "medium",
							Detail: fmt.Sprintf("Open redirect via ?%s= → %s (HTTP %d)", param, location, resp.StatusCode),
						}) {
							atomic.AddInt64(&count, 1)
						}
						break // one finding per host is enough
					}
				}
			}
		}(host)
	}

	wg.Wait()
	total := atomic.LoadInt64(&count)
	fmt.Printf("[+] Open redirect checks done — %d issues found\n", total)
	return total
}

// ─── HTTP Request Smuggling Detection ───────────────────────────────────

// runSmugglingChecks performs CL.TE and TE.CL detection using raw TCP sockets.
// This is a timing-based detection: if a smuggled request causes a different
// response time than a normal request, the server may be vulnerable.
func (w *WebWorkflow) runSmugglingChecks(liveHosts []string, emitUnique func(webResult) bool) int64 {
	fmt.Printf("[*] Checking %d hosts for HTTP request smuggling...\n", len(liveHosts))

	var count int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // lower concurrency — raw sockets + timing

	for _, host := range liveHosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			parsed, err := url.Parse(h)
			if err != nil {
				return
			}
			hostname := parsed.Hostname()
			port := parsed.Port()
			isHTTPS := parsed.Scheme == "https"

			if port == "" {
				if isHTTPS {
					port = "443"
				} else {
					port = "80"
				}
			}
			addr := net.JoinHostPort(hostname, port)

			// CL.TE detection: Content-Length says body is short, but body contains
			// Transfer-Encoding chunked data. If front-end uses CL and back-end uses TE,
			// the remainder gets smuggled.
			cltePayload := fmt.Sprintf(
				"POST / HTTP/1.1\r\n"+
					"Host: %s\r\n"+
					"Content-Length: 4\r\n"+
					"Transfer-Encoding: chunked\r\n"+
					"\r\n"+
					"1\r\n"+
					"Z\r\n"+
					"Q\r\n", // Q should NOT be processed — if it is, CL.TE smuggling exists
				hostname)

			// TE.CL detection: Transfer-Encoding says chunked, but Content-Length
			// specifies a short body. If front-end uses TE and back-end uses CL,
			// the chunked trailer gets smuggled.
			teclPayload := fmt.Sprintf(
				"POST / HTTP/1.1\r\n"+
					"Host: %s\r\n"+
					"Content-Length: 6\r\n"+
					"Transfer-Encoding: chunked\r\n"+
					"\r\n"+
					"0\r\n"+
					"\r\n"+
					"X", // X should NOT be processed — if it causes delay, TE.CL exists
				hostname)

			// Test CL.TE
			if w.testSmuggling(addr, isHTTPS, hostname, cltePayload) {
				if emitUnique(webResult{
					Phase: "smuggling", Value: h, Severity: "critical",
					Detail: "Potential CL.TE HTTP request smuggling",
				}) {
					atomic.AddInt64(&count, 1)
				}
			}

			// Test TE.CL
			if w.testSmuggling(addr, isHTTPS, hostname, teclPayload) {
				if emitUnique(webResult{
					Phase: "smuggling", Value: h, Severity: "critical",
					Detail: "Potential TE.CL HTTP request smuggling",
				}) {
					atomic.AddInt64(&count, 1)
				}
			}
		}(host)
	}

	wg.Wait()
	total := atomic.LoadInt64(&count)
	fmt.Printf("[+] HTTP smuggling checks done — %d issues found\n", total)
	return total
}

// testSmuggling sends a raw HTTP payload and checks for anomalous response behavior.
// Returns true if the response suggests smuggling vulnerability.
func (w *WebWorkflow) testSmuggling(addr string, isHTTPS bool, hostname, payload string) bool {
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	var conn net.Conn
	var err error

	if isHTTPS {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         hostname,
		})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return false
	}
	defer conn.Close()

	// Set overall deadline
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send the smuggling payload
	_, err = conn.Write([]byte(payload))
	if err != nil {
		return false
	}

	// Read response — look for anomalies
	reader := bufio.NewReader(conn)

	// Read first response
	resp1, err := http.ReadResponse(reader, nil)
	if err != nil {
		return false
	}
	resp1.Body.Close()

	// Try to read a second response (shouldn't exist in normal case).
	// If we get one, it means the server processed the smuggled part
	// as a separate request — strong indicator of smuggling.
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	resp2, err := http.ReadResponse(reader, nil)
	if err == nil && resp2 != nil {
		resp2.Body.Close()
		return true // got a second response → smuggling likely
	}

	return false
}
