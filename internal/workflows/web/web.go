package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/FOUEN/narmol/internal/scope"
	"github.com/FOUEN/narmol/internal/workflows"

	"github.com/projectdiscovery/goflags"
	httpx_runner "github.com/projectdiscovery/httpx/runner"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
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

	// ── Step 2: httpx — probe + fingerprint ───────────────────────────
	liveHosts, techSet := w.runHttpx(hosts, s, emitUnique)

	if len(liveHosts) == 0 {
		fmt.Println("[!] No live hosts found — stopping workflow")
		return nil
	}
	fmt.Printf("[+] %d live hosts found, %d unique technologies detected\n", len(liveHosts), len(techSet))

	// ── Step 3: nuclei — targeted vulnerability scan ──────────────────
	// Nessus-style: use fingerprint to select only relevant templates.
	// Instead of running all 10k+ templates, we filter by detected tech stack.
	tags := buildNucleiTags(techSet)
	fmt.Printf("[+] Nuclei tags from fingerprint: %s\n", strings.Join(tags, ", "))

	vulnCount := w.runNuclei(liveHosts, tags, emitUnique)

	// ── Summary ───────────────────────────────────────────────────────
	if opts.TextFile != "" {
		fmt.Printf("[+] Text results saved to: %s\n", opts.TextFile)
	}
	if opts.JSONFile != "" {
		fmt.Printf("[+] JSON results saved to: %s\n", opts.JSONFile)
	}
	fmt.Printf("[+] Workflow 'web' completed — %d live, %d techs, %d vulns\n",
		len(liveHosts), len(techSet), vulnCount)
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
	Phase      string   `json:"phase"`                 // "probe", "vuln"
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
