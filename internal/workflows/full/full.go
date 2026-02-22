package full

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

	mapset "github.com/deckarep/golang-set/v2"
	gau_providers "github.com/lc/gau/v2/pkg/providers"
	gau_runner "github.com/lc/gau/v2/runner"
	"github.com/valyala/fasthttp"

	"github.com/projectdiscovery/goflags"
	httpx_runner "github.com/projectdiscovery/httpx/runner"
	katana_output "github.com/projectdiscovery/katana/pkg/output"
	katana_standard "github.com/projectdiscovery/katana/pkg/engine/standard"
	katana_types "github.com/projectdiscovery/katana/pkg/types"
	naabu_result "github.com/projectdiscovery/naabu/v2/pkg/result"
	naabu_runner "github.com/projectdiscovery/naabu/v2/pkg/runner"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
	nuclei_output "github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	subfinder_runner "github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

func init() {
	workflows.Register(&FullWorkflow{})
}

// FullWorkflow runs the complete scan pipeline:
//  1. Recon        — subfinder (recursive) + gau (passive, no target contact)
//  2. Probe        — httpx alive check + tech fingerprinting
//  3. Crawl        — katana endpoint discovery on live hosts
//  4. Port scan    — naabu on live hosts + IPs/CIDRs from scope
//  5. Vuln assess  — nuclei + headers + TLS + redirects + smuggling + git secrets (parallel)
//  6. Report       — unified structured output by phases
type FullWorkflow struct{}

func (w *FullWorkflow) Name() string { return "full" }

func (w *FullWorkflow) Description() string {
	return "Complete scan: recon → probe → crawl → portscan → vuln assessment. Everything."
}

func (w *FullWorkflow) Run(domain string, s *scope.Scope, opts workflows.OutputOptions) error {
	if !s.IsInScope(domain) {
		return fmt.Errorf("domain %s is not in scope", domain)
	}

	report := &fullReport{
		Target: domain,
		Date:   time.Now().UTC().Format(time.RFC3339),
	}

	seen := &sync.Map{}
	collect := func(r finding) bool {
		key := r.Phase + ":" + r.Value
		if r.Detail != "" {
			key += ":" + r.Detail
		}
		if _, loaded := seen.LoadOrStore(key, true); loaded {
			return false
		}
		report.add(r)
		return true
	}

	// ═══════════════════════════════════════════════════════════════════
	// Phase 1: RECON — passive subdomain + URL discovery
	// ═══════════════════════════════════════════════════════════════════
	fmt.Println("\n[*] ═══ Phase 1: RECON (passive) ═══")

	var subdomains []string
	if s.HasWildcard(domain) {
		subdomains = w.runSubfinder(domain, s, collect)
		if len(subdomains) > 0 {
			w.runSubfinderRecursive(subdomains, s, collect)
		}
	} else {
		collect(finding{Phase: "recon", Value: domain, Detail: "scope target"})
	}

	// Always include the domain itself
	subdomains = appendUnique(subdomains, domain)

	// Gau — historical URLs (parallel with next phase prep)
	var gauWg sync.WaitGroup
	gauWg.Add(1)
	go func() {
		defer gauWg.Done()
		w.runGau(domain, s, collect)
	}()

	fmt.Printf("[+] %d subdomains discovered\n", len(subdomains))

	// ═══════════════════════════════════════════════════════════════════
	// Phase 2: PROBE — httpx alive check + fingerprinting
	// ═══════════════════════════════════════════════════════════════════
	fmt.Println("\n[*] ═══ Phase 2: PROBE (alive + fingerprint) ═══")

	liveHosts, techSet := w.runHttpx(subdomains, s, collect)
	if len(liveHosts) == 0 {
		fmt.Println("[!] No live hosts found")
	} else {
		fmt.Printf("[+] %d live hosts, %d technologies detected\n", len(liveHosts), len(techSet))
	}

	// Wait for gau to finish
	gauWg.Wait()

	// ═══════════════════════════════════════════════════════════════════
	// Phase 3: CRAWL + PORT SCAN (parallel)
	// ═══════════════════════════════════════════════════════════════════
	fmt.Println("\n[*] ═══ Phase 3: CRAWL + PORT SCAN ═══")

	var phase3Wg sync.WaitGroup

	// 3a. Katana crawl on live hosts
	if len(liveHosts) > 0 {
		phase3Wg.Add(1)
		go func() {
			defer phase3Wg.Done()
			w.runKatana(liveHosts, s, collect)
		}()
	}

	// 3b. Naabu port scan on all targets (hosts + IPs)
	portTargets := make([]string, len(subdomains))
	copy(portTargets, subdomains)
	if s.HasIPs() {
		portTargets = append(portTargets, s.IPs()...)
	}
	if len(portTargets) > 0 {
		phase3Wg.Add(1)
		go func() {
			defer phase3Wg.Done()
			w.runNaabu(portTargets, collect)
		}()
	}

	phase3Wg.Wait()

	// ═══════════════════════════════════════════════════════════════════
	// Phase 4: VULNERABILITY ASSESSMENT (all parallel)
	// ═══════════════════════════════════════════════════════════════════
	if len(liveHosts) > 0 {
		fmt.Println("\n[*] ═══ Phase 4: VULNERABILITY ASSESSMENT ═══")

		tags := buildNucleiTags(techSet)
		fmt.Printf("[+] Nuclei tags from fingerprint: %s\n", strings.Join(tags, ", "))

		var vulnWg sync.WaitGroup

		vulnWg.Add(1)
		go func() {
			defer vulnWg.Done()
			w.runNuclei(liveHosts, tags, collect)
		}()

		vulnWg.Add(1)
		go func() {
			defer vulnWg.Done()
			w.runGitExposureCheck(liveHosts, collect)
		}()

		vulnWg.Add(1)
		go func() {
			defer vulnWg.Done()
			w.runSecurityHeaderChecks(liveHosts, collect)
		}()

		vulnWg.Add(1)
		go func() {
			defer vulnWg.Done()
			w.runTLSChecks(liveHosts, collect)
		}()

		vulnWg.Add(1)
		go func() {
			defer vulnWg.Done()
			w.runOpenRedirectChecks(liveHosts, collect)
		}()

		vulnWg.Add(1)
		go func() {
			defer vulnWg.Done()
			w.runSmugglingChecks(liveHosts, collect)
		}()

		vulnWg.Wait()
	}

	// ═══════════════════════════════════════════════════════════════════
	// Phase 5: REPORT
	// ═══════════════════════════════════════════════════════════════════
	report.HostsDiscovered = len(subdomains)
	report.HostsLive = len(liveHosts)
	report.TechCount = len(techSet)
	return report.write(opts)
}

// ─── Subfinder ──────────────────────────────────────────────────────────

func (w *FullWorkflow) runSubfinder(domain string, s *scope.Scope, collect func(finding) bool) []string {
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
		ProviderConfig:     "",
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
			collect(finding{Phase: "recon", Value: host, Detail: "subfinder"})
		},
	}

	sfRunner, err := subfinder_runner.NewRunner(sfOptions)
	if err != nil {
		fmt.Printf("[!] Could not create subfinder runner: %s\n", err)
		return nil
	}
	if err := sfRunner.RunEnumerationWithCtx(context.Background()); err != nil {
		fmt.Printf("[!] Subfinder enumeration failed: %s\n", err)
	}

	fmt.Printf("[+] Subfinder: %d found, %d in scope\n", total, inScope)
	return hosts
}

func (w *FullWorkflow) runSubfinderRecursive(seeds []string, s *scope.Scope, collect func(finding) bool) {
	bases := map[string]bool{}
	for _, host := range seeds {
		if strings.Count(host, ".") >= 2 {
			bases[host] = true
		}
	}
	if len(bases) == 0 {
		return
	}

	fmt.Printf("[*] Recursive subfinder on %d subdomains...\n", len(bases))
	var newFound int64

	for base := range bases {
		sfOptions := &subfinder_runner.Options{
			Domain:             goflags.StringSlice{base},
			Silent:             true,
			All:                false,
			Timeout:            30,
			MaxEnumerationTime: 5,
			Threads:            10,
			DisableUpdateCheck: true,
			Output:             io.Discard,
			ProviderConfig:     "",
			ResultCallback: func(result *resolve.HostEntry) {
				host := strings.TrimSpace(result.Host)
				if host == "" || !s.IsInScope(host) {
					return
				}
				if collect(finding{Phase: "recon", Value: host, Detail: "subfinder-recursive"}) {
					atomic.AddInt64(&newFound, 1)
				}
			},
		}
		sfRunner, err := subfinder_runner.NewRunner(sfOptions)
		if err != nil {
			continue
		}
		_ = sfRunner.RunEnumerationWithCtx(context.Background())
	}

	fmt.Printf("[+] Recursive subfinder: %d new subdomains\n", newFound)
}

// ─── Gau ────────────────────────────────────────────────────────────────

func (w *FullWorkflow) runGau(domain string, s *scope.Scope, collect func(finding) bool) {
	fmt.Printf("[*] Running gau on %s...\n", domain)
	var urlCount int64

	config := &gau_providers.Config{
		Threads:           5,
		Timeout:           45,
		MaxRetries:        3,
		IncludeSubdomains: true,
		RemoveParameters:  false,
		Client: &fasthttp.Client{
			TLSConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Blacklist: mapset.NewThreadUnsafeSet(""),
	}

	providerNames := []string{"wayback", "otx", "urlscan"}

	gau := &gau_runner.Runner{}
	if err := gau.Init(config, providerNames, gau_providers.Filters{}); err != nil {
		fmt.Printf("[!] Could not initialize gau: %s\n", err)
		return
	}

	results := make(chan string, 100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	workChan := make(chan gau_runner.Work)
	gau.Start(ctx, workChan, results)

	go func() {
		for _, provider := range gau.Providers {
			workChan <- gau_runner.NewWork(domain, provider)
		}
		close(workChan)
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for u := range results {
			u = strings.TrimSpace(u)
			if u == "" || !s.IsInScope(u) {
				continue
			}
			if collect(finding{Phase: "url", Value: u, Detail: "gau"}) {
				atomic.AddInt64(&urlCount, 1)
			}
		}
	}()

	gau.Wait()
	close(results)
	wg.Wait()

	fmt.Printf("[+] Gau: %d URLs collected\n", urlCount)
}

// ─── httpx ──────────────────────────────────────────────────────────────

func (w *FullWorkflow) runHttpx(hosts []string, s *scope.Scope, collect func(finding) bool) ([]string, map[string]struct{}) {
	fmt.Printf("[*] Probing %d hosts with httpx...\n", len(hosts))

	var mu sync.Mutex
	var liveHosts []string
	techSet := make(map[string]struct{})

	hxOptions := httpx_runner.Options{
		Methods:         "GET",
		InputTargetHost: goflags.StringSlice(hosts),
		Silent:          true,
		NoColor:         true,
		Threads:         50,
		Timeout:         10,
		FollowRedirects: true,
		MaxRedirects:    10,
		RateLimit:       150,
		RandomAgent:     true,
		TechDetect:      true,
		OutputCDN:       "true",
		ExtractTitle:    true,
		DisableUpdateCheck: true,
		OnResult: func(result httpx_runner.Result) {
			if result.Err != nil {
				return
			}
			host := result.Input
			u := result.URL
			if !s.IsInScope(host) {
				return
			}

			mu.Lock()
			liveHosts = append(liveHosts, u)
			for _, tech := range result.Technologies {
				techSet[tech] = struct{}{}
			}
			mu.Unlock()

			collect(finding{
				Phase:      "probe",
				Value:      u,
				Host:       host,
				StatusCode: result.StatusCode,
				Title:      result.Title,
				Tech:       result.Technologies,
				Webserver:  result.WebServer,
				CDN:        result.CDN,
				CDNName:    result.CDNName,
			})
		},
	}

	hxRunner, err := httpx_runner.New(&hxOptions)
	if err != nil {
		fmt.Printf("[!] Could not create httpx runner: %s\n", err)
		return nil, techSet
	}
	defer hxRunner.Close()

	hxRunner.RunEnumeration()

	return liveHosts, techSet
}

// ─── Katana ─────────────────────────────────────────────────────────────

func (w *FullWorkflow) runKatana(liveHosts []string, s *scope.Scope, collect func(finding) bool) {
	fmt.Printf("[*] Crawling %d hosts with katana...\n", len(liveHosts))
	var count int64

	katanaOpts := &katana_types.Options{
		MaxDepth:    3,
		FieldScope:  "rdn",
		Concurrency: 10,
		Parallelism: 10,
		Timeout:     10,
		RateLimit:   100,
		Strategy:    "breadth-first",
		KnownFiles:  "all",
		NoColors:    true,
		Silent:      true,
		OnResult: func(result katana_output.Result) {
			u := result.Request.URL
			if u == "" || !s.IsInScope(u) {
				return
			}
			if collect(finding{Phase: "url", Value: u, Detail: "katana"}) {
				atomic.AddInt64(&count, 1)
			}
		},
	}

	crawlerOpts, err := katana_types.NewCrawlerOptions(katanaOpts)
	if err != nil {
		fmt.Printf("[!] Could not create katana options: %s\n", err)
		return
	}
	defer crawlerOpts.Close()

	crawler, err := katana_standard.New(crawlerOpts)
	if err != nil {
		fmt.Printf("[!] Could not create katana crawler: %s\n", err)
		return
	}
	defer crawler.Close()

	if err := crawler.Crawl(liveHosts[0]); err != nil {
		fmt.Printf("[!] Katana crawl error: %s\n", err)
	}
	for _, h := range liveHosts[1:] {
		_ = crawler.Crawl(h)
	}

	fmt.Printf("[+] Katana: %d URLs crawled\n", count)
}

// ─── Naabu ──────────────────────────────────────────────────────────────

func (w *FullWorkflow) runNaabu(targets []string, collect func(finding) bool) {
	fmt.Printf("[*] Port scanning %d targets with naabu...\n", len(targets))
	var count int64

	options := &naabu_runner.Options{
		Host:               goflags.StringSlice(targets),
		TopPorts:           "1000",
		ScanType:           naabu_runner.ConnectScan,
		Rate:               1500,
		Threads:            25,
		Retries:            2,
		Timeout:            3 * time.Second,
		Silent:             true,
		DisableStdout:      true,
		NoColor:            true,
		DisableUpdateCheck: true,
		OnResult: func(hr *naabu_result.HostResult) {
			for _, p := range hr.Ports {
				host := hr.Host
				if hr.IP != "" && hr.IP != hr.Host {
					host = hr.Host + " (" + hr.IP + ")"
				}
				if collect(finding{
					Phase:  "port",
					Value:  fmt.Sprintf("%s:%d", hr.Host, p.Port),
					Host:   host,
					Detail: fmt.Sprintf("port %d/%s open", p.Port, p.Protocol.String()),
				}) {
					atomic.AddInt64(&count, 1)
				}
			}
		},
	}

	runner, err := naabu_runner.NewRunner(options)
	if err != nil {
		fmt.Printf("[!] Could not create naabu runner: %s\n", err)
		return
	}
	defer runner.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if err := runner.RunEnumeration(ctx); err != nil {
		fmt.Printf("[!] Naabu scan error: %s\n", err)
	}

	fmt.Printf("[+] Naabu: %d open ports found\n", count)
}

// ─── Nuclei ─────────────────────────────────────────────────────────────

func (w *FullWorkflow) runNuclei(targets []string, tags []string, collect func(finding) bool) {
	fmt.Printf("[*] Scanning %d targets with nuclei (%d tech tags)...\n", len(targets), len(tags))
	var vulnCount int64
	ctx := context.Background()

	tm := &installer.TemplateManager{}
	if err := tm.FreshInstallIfNotExists(); err != nil {
		fmt.Printf("[!] Could not install nuclei templates: %s\n", err)
		return
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
			HeadlessTemplateConcurrency:   5,
			JavascriptTemplateConcurrency: 10,
			TemplatePayloadConcurrency:    25,
			ProbeConcurrency:              50,
		}),
		nuclei.WithVerbosity(nuclei.VerbosityOptions{Silent: true}),
		nuclei.DisableUpdateCheck(),
	)
	if err != nil {
		fmt.Printf("[!] Could not create nuclei engine: %s\n", err)
		return
	}
	defer ne.Close()

	if err := ne.LoadAllTemplates(); err != nil {
		fmt.Printf("[!] Could not load nuclei templates: %s\n", err)
		return
	}

	ne.LoadTargets(targets, false)

	if err := ne.ExecuteCallbackWithCtx(ctx, func(event *nuclei_output.ResultEvent) {
		severity := event.Info.SeverityHolder.Severity.String()
		collect(finding{
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

	fmt.Printf("[+] Nuclei: %d vulnerabilities found\n", vulnCount)
}

// ─── Git Exposure + TruffleHog ──────────────────────────────────────────

func (w *FullWorkflow) runGitExposureCheck(liveHosts []string, collect func(finding) bool) {
	fmt.Printf("[*] Checking %d hosts for .git exposure...\n", len(liveHosts))

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
			DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var count int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

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

			buf := make([]byte, 256)
			n, _ := resp.Body.Read(buf)
			body := string(buf[:n])

			if resp.StatusCode == 200 && strings.HasPrefix(body, "ref: refs/") {
				collect(finding{
					Phase:    "secret",
					Value:    h,
					Severity: "high",
					Detail:   ".git repository exposed — scanning for secrets",
				})

				results, err := secrets.ScanGitRepo(h)
				if err != nil {
					return
				}
				for _, sr := range results {
					collect(finding{
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
	fmt.Printf("[+] Git exposure: %d secrets found\n", count)
}

// ─── Security Headers ──────────────────────────────────────────────────

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

func (w *FullWorkflow) runSecurityHeaderChecks(liveHosts []string, collect func(finding) bool) {
	fmt.Printf("[*] Checking security headers on %d hosts...\n", len(liveHosts))

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
			DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		},
	}

	var count int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

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

			for _, hdr := range requiredHeaders {
				if resp.Header.Get(hdr.Name) == "" {
					if collect(finding{Phase: "header", Value: h, Severity: hdr.Severity, Detail: "Missing " + hdr.Name}) {
						atomic.AddInt64(&count, 1)
					}
				}
			}

			acao := resp.Header.Get("Access-Control-Allow-Origin")
			if acao == "*" || acao == "https://evil.com" {
				if collect(finding{Phase: "header", Value: h, Severity: "high", Detail: fmt.Sprintf("CORS misconfiguration: Access-Control-Allow-Origin: %s", acao)}) {
					atomic.AddInt64(&count, 1)
				}
			}

			acac := resp.Header.Get("Access-Control-Allow-Credentials")
			if acac == "true" && (acao == "*" || acao == "https://evil.com") {
				if collect(finding{Phase: "header", Value: h, Severity: "critical", Detail: "CORS with credentials: origin reflected + Allow-Credentials: true"}) {
					atomic.AddInt64(&count, 1)
				}
			}

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
					if collect(finding{Phase: "header", Value: h, Severity: "low", Detail: fmt.Sprintf("Cookie '%s': %s", cookie.Name, strings.Join(issues, ", "))}) {
						atomic.AddInt64(&count, 1)
					}
				}
			}
		}(host)
	}

	wg.Wait()
	fmt.Printf("[+] Security headers: %d issues found\n", count)
}

// ─── TLS Checks ─────────────────────────────────────────────────────────

var weakCiphers = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:            "RC4-SHA",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:       "3DES-CBC-SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:        "RSA-AES128-CBC-SHA",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:        "RSA-AES256-CBC-SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:     "RSA-AES128-CBC-SHA256",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:      "ECDHE-RC4-SHA",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: "ECDHE-3DES-CBC-SHA",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:    "ECDHE-ECDSA-RC4-SHA",
}

func (w *FullWorkflow) runTLSChecks(liveHosts []string, collect func(finding) bool) {
	var httpsHosts []string
	for _, h := range liveHosts {
		if strings.HasPrefix(h, "https://") {
			httpsHosts = append(httpsHosts, h)
		}
	}
	if len(httpsHosts) == 0 {
		return
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

			conn, err := tls.DialWithDialer(
				&net.Dialer{Timeout: 5 * time.Second},
				"tcp", addr,
				&tls.Config{InsecureSkipVerify: true},
			)
			if err != nil {
				return
			}
			defer conn.Close()

			state := conn.ConnectionState()

			switch state.Version {
			case tls.VersionTLS10:
				if collect(finding{Phase: "tls", Value: h, Severity: "high", Detail: "TLS 1.0 supported (deprecated, vulnerable to BEAST/POODLE)"}) {
					atomic.AddInt64(&count, 1)
				}
			case tls.VersionTLS11:
				if collect(finding{Phase: "tls", Value: h, Severity: "medium", Detail: "TLS 1.1 supported (deprecated)"}) {
					atomic.AddInt64(&count, 1)
				}
			}

			if name, weak := weakCiphers[state.CipherSuite]; weak {
				if collect(finding{Phase: "tls", Value: h, Severity: "high", Detail: fmt.Sprintf("Weak cipher suite: %s", name)}) {
					atomic.AddInt64(&count, 1)
				}
			}

			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				now := time.Now()

				if now.After(cert.NotAfter) {
					if collect(finding{Phase: "tls", Value: h, Severity: "high", Detail: fmt.Sprintf("Certificate expired: %s", cert.NotAfter.Format("2006-01-02"))}) {
						atomic.AddInt64(&count, 1)
					}
				}

				if now.Before(cert.NotAfter) && cert.NotAfter.Before(now.Add(30*24*time.Hour)) {
					if collect(finding{Phase: "tls", Value: h, Severity: "medium", Detail: fmt.Sprintf("Certificate expiring soon: %s", cert.NotAfter.Format("2006-01-02"))}) {
						atomic.AddInt64(&count, 1)
					}
				}

				if cert.Issuer.CommonName == cert.Subject.CommonName {
					pool := x509.NewCertPool()
					pool.AddCert(cert)
					_, verifyErr := cert.Verify(x509.VerifyOptions{Roots: pool})
					if verifyErr == nil {
						if collect(finding{Phase: "tls", Value: h, Severity: "medium", Detail: "Self-signed certificate"}) {
							atomic.AddInt64(&count, 1)
						}
					}
				}

				if err := cert.VerifyHostname(hostname); err != nil {
					if collect(finding{Phase: "tls", Value: h, Severity: "high", Detail: fmt.Sprintf("Certificate hostname mismatch: cert for %s", strings.Join(cert.DNSNames, ", "))}) {
						atomic.AddInt64(&count, 1)
					}
				}
			}
		}(host)
	}

	wg.Wait()
	fmt.Printf("[+] TLS checks: %d issues found\n", count)
}

// ─── Open Redirect ──────────────────────────────────────────────────────

var openRedirectParams = []string{
	"url", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
	"returnTo", "next", "goto", "target", "destination", "dest", "rurl",
	"continue", "forward", "out", "view", "login_url", "callback",
}

func (w *FullWorkflow) runOpenRedirectChecks(liveHosts []string, collect func(finding) bool) {
	fmt.Printf("[*] Checking %d hosts for open redirects...\n", len(liveHosts))

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext:     (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
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
						if collect(finding{Phase: "redirect", Value: h, Severity: "medium", Detail: fmt.Sprintf("Open redirect via ?%s= → %s (HTTP %d)", param, location, resp.StatusCode)}) {
							atomic.AddInt64(&count, 1)
						}
						break
					}
				}
			}
		}(host)
	}

	wg.Wait()
	fmt.Printf("[+] Open redirect checks: %d issues found\n", count)
}

// ─── HTTP Smuggling ─────────────────────────────────────────────────────

func (w *FullWorkflow) runSmugglingChecks(liveHosts []string, collect func(finding) bool) {
	fmt.Printf("[*] Checking %d hosts for HTTP request smuggling...\n", len(liveHosts))

	var count int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

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

			cltePayload := fmt.Sprintf(
				"POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\nQ\r\n",
				hostname)

			teclPayload := fmt.Sprintf(
				"POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
				hostname)

			if w.testSmuggling(addr, isHTTPS, hostname, cltePayload) {
				if collect(finding{Phase: "smuggling", Value: h, Severity: "critical", Detail: "Potential CL.TE HTTP request smuggling"}) {
					atomic.AddInt64(&count, 1)
				}
			}

			if w.testSmuggling(addr, isHTTPS, hostname, teclPayload) {
				if collect(finding{Phase: "smuggling", Value: h, Severity: "critical", Detail: "Potential TE.CL HTTP request smuggling"}) {
					atomic.AddInt64(&count, 1)
				}
			}
		}(host)
	}

	wg.Wait()
	fmt.Printf("[+] HTTP smuggling checks: %d issues found\n", count)
}

func (w *FullWorkflow) testSmuggling(addr string, isHTTPS bool, hostname, payload string) bool {
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

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err = conn.Write([]byte(payload)); err != nil {
		return false
	}

	reader := bufio.NewReader(conn)
	resp1, err := http.ReadResponse(reader, nil)
	if err != nil {
		return false
	}
	resp1.Body.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	resp2, err := http.ReadResponse(reader, nil)
	if err == nil && resp2 != nil {
		resp2.Body.Close()
		return true
	}
	return false
}

// ─── Result + Report types ──────────────────────────────────────────────

type finding struct {
	Phase      string   `json:"phase"`
	Value      string   `json:"value"`
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
	Detail     string   `json:"detail,omitempty"`
}

func (f finding) summary() string {
	switch f.Phase {
	case "recon":
		return fmt.Sprintf("[RECON] %s (%s)", f.Value, f.Detail)
	case "probe":
		tech := ""
		if len(f.Tech) > 0 {
			tech = " [" + strings.Join(f.Tech, ", ") + "]"
		}
		title := ""
		if f.Title != "" {
			title = " - " + f.Title
		}
		return fmt.Sprintf("[LIVE] %s (%d)%s%s", f.Value, f.StatusCode, title, tech)
	case "url":
		return fmt.Sprintf("[URL] %s (%s)", f.Value, f.Detail)
	case "port":
		return fmt.Sprintf("[PORT] %s", f.Detail)
	case "vuln":
		return fmt.Sprintf("[%s] %s — %s (%s)", strings.ToUpper(f.Severity), f.Value, f.VulnName, f.TemplateID)
	case "secret":
		return fmt.Sprintf("[SECRET] %s — %s", f.Value, f.Detail)
	case "header":
		return fmt.Sprintf("[HEADER] %s — %s", f.Value, f.Detail)
	case "tls":
		return fmt.Sprintf("[TLS-%s] %s — %s", strings.ToUpper(f.Severity), f.Value, f.Detail)
	case "redirect":
		return fmt.Sprintf("[REDIRECT] %s — %s", f.Value, f.Detail)
	case "smuggling":
		return fmt.Sprintf("[SMUGGLING-%s] %s — %s", strings.ToUpper(f.Severity), f.Value, f.Detail)
	default:
		return f.Value
	}
}

// ─── Report ─────────────────────────────────────────────────────────────

type fullReport struct {
	mu              sync.Mutex
	Target          string
	Date            string
	HostsDiscovered int
	HostsLive       int
	TechCount       int
	Recon           []finding
	Probes          []finding
	URLs            []finding
	Ports           []finding
	Vulns           []finding
	Secrets         []finding
	Headers         []finding
	TLS             []finding
	Redirects       []finding
	Smuggling       []finding
}

func (rpt *fullReport) add(f finding) {
	rpt.mu.Lock()
	defer rpt.mu.Unlock()
	switch f.Phase {
	case "recon":
		rpt.Recon = append(rpt.Recon, f)
	case "probe":
		rpt.Probes = append(rpt.Probes, f)
	case "url":
		rpt.URLs = append(rpt.URLs, f)
	case "port":
		rpt.Ports = append(rpt.Ports, f)
	case "vuln":
		rpt.Vulns = append(rpt.Vulns, f)
	case "secret":
		rpt.Secrets = append(rpt.Secrets, f)
	case "header":
		rpt.Headers = append(rpt.Headers, f)
	case "tls":
		rpt.TLS = append(rpt.TLS, f)
	case "redirect":
		rpt.Redirects = append(rpt.Redirects, f)
	case "smuggling":
		rpt.Smuggling = append(rpt.Smuggling, f)
	}
}

func (rpt *fullReport) write(opts workflows.OutputOptions) error {
	textReport := rpt.formatText()
	fmt.Print(textReport)

	if opts.TextFile != "" {
		if err := os.WriteFile(opts.TextFile, []byte(textReport), 0644); err != nil {
			return fmt.Errorf("failed to write text report: %w", err)
		}
		fmt.Printf("[+] Text report saved to: %s\n", opts.TextFile)
	}

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

type fullReportJSON struct {
	Target  string           `json:"target"`
	Date    string           `json:"date"`
	Summary fullSummary      `json:"summary"`
	Phases  fullReportPhases `json:"phases"`
}

type fullSummary struct {
	HostsDiscovered int `json:"hosts_discovered"`
	HostsLive       int `json:"hosts_live"`
	Technologies    int `json:"technologies_detected"`
	URLsCollected   int `json:"urls_collected"`
	OpenPorts       int `json:"open_ports"`
	Vulnerabilities int `json:"vulnerabilities"`
	Secrets         int `json:"secrets"`
	HeaderIssues    int `json:"header_issues"`
	TLSIssues       int `json:"tls_issues"`
	Redirects       int `json:"redirects"`
	Smuggling       int `json:"smuggling"`
}

type fullReportPhases struct {
	Recon           []finding `json:"recon"`
	Discovery       []finding `json:"discovery"`
	URLs            []finding `json:"urls"`
	Ports           []finding `json:"ports"`
	Vulnerabilities []finding `json:"vulnerabilities"`
	Secrets         []finding `json:"secrets"`
	Headers         []finding `json:"header_issues"`
	TLS             []finding `json:"tls_issues"`
	Redirects       []finding `json:"redirects"`
	Smuggling       []finding `json:"smuggling"`
}

func (rpt *fullReport) jsonData() fullReportJSON {
	e := func(s []finding) []finding {
		if s == nil {
			return []finding{}
		}
		return s
	}
	return fullReportJSON{
		Target: rpt.Target,
		Date:   rpt.Date,
		Summary: fullSummary{
			HostsDiscovered: rpt.HostsDiscovered,
			HostsLive:       rpt.HostsLive,
			Technologies:    rpt.TechCount,
			URLsCollected:   len(rpt.URLs),
			OpenPorts:       len(rpt.Ports),
			Vulnerabilities: len(rpt.Vulns),
			Secrets:         len(rpt.Secrets),
			HeaderIssues:    len(rpt.Headers),
			TLSIssues:       len(rpt.TLS),
			Redirects:       len(rpt.Redirects),
			Smuggling:       len(rpt.Smuggling),
		},
		Phases: fullReportPhases{
			Recon:           e(rpt.Recon),
			Discovery:       e(rpt.Probes),
			URLs:            e(rpt.URLs),
			Ports:           e(rpt.Ports),
			Vulnerabilities: e(rpt.Vulns),
			Secrets:         e(rpt.Secrets),
			Headers:         e(rpt.Headers),
			TLS:             e(rpt.TLS),
			Redirects:       e(rpt.Redirects),
			Smuggling:       e(rpt.Smuggling),
		},
	}
}

func (rpt *fullReport) formatText() string {
	var b strings.Builder
	line := strings.Repeat("\u2500", 70)
	doubleLine := strings.Repeat("\u2550", 70)

	b.WriteString("\n" + doubleLine + "\n")
	b.WriteString("  NARMOL \u2014 Full Security Audit Report\n")
	b.WriteString("  Target: " + rpt.Target + "\n")
	b.WriteString("  Date:   " + rpt.Date + "\n")
	b.WriteString(doubleLine + "\n")

	// 1. Recon
	b.WriteString("\n" + line + "\n")
	b.WriteString("  1. RECONNAISSANCE (passive)\n")
	b.WriteString(line + "\n")
	if len(rpt.Recon) == 0 {
		b.WriteString("  No subdomains discovered.\n")
	} else {
		for _, r := range rpt.Recon {
			b.WriteString("  " + r.summary() + "\n")
		}
	}

	// 2. Discovery
	b.WriteString("\n" + line + "\n")
	b.WriteString("  2. DISCOVERY & FINGERPRINTING\n")
	b.WriteString(line + "\n")
	if len(rpt.Probes) == 0 {
		b.WriteString("  No live hosts found.\n")
	} else {
		for _, r := range rpt.Probes {
			b.WriteString("  " + r.summary() + "\n")
		}
	}

	// 3. URLs
	b.WriteString("\n" + line + "\n")
	b.WriteString(fmt.Sprintf("  3. URLS COLLECTED (%d)\n", len(rpt.URLs)))
	b.WriteString(line + "\n")
	if len(rpt.URLs) == 0 {
		b.WriteString("  No URLs collected.\n")
	} else {
		// Show max 50 URLs, then summary
		limit := len(rpt.URLs)
		if limit > 50 {
			limit = 50
		}
		for _, r := range rpt.URLs[:limit] {
			b.WriteString("  " + r.summary() + "\n")
		}
		if len(rpt.URLs) > 50 {
			b.WriteString(fmt.Sprintf("  ... and %d more URLs\n", len(rpt.URLs)-50))
		}
	}

	// 4. Ports
	b.WriteString("\n" + line + "\n")
	b.WriteString("  4. OPEN PORTS\n")
	b.WriteString(line + "\n")
	if len(rpt.Ports) == 0 {
		b.WriteString("  No open ports found.\n")
	} else {
		for _, r := range rpt.Ports {
			b.WriteString("  " + r.summary() + "\n")
		}
	}

	// 5. Vulns
	b.WriteString("\n" + line + "\n")
	b.WriteString("  5. VULNERABILITIES\n")
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

	// 6. Secrets
	b.WriteString("\n" + line + "\n")
	b.WriteString("  6. SECRETS & EXPOSURES\n")
	b.WriteString(line + "\n")
	if len(rpt.Secrets) == 0 {
		b.WriteString("  No secrets or exposures found.\n")
	} else {
		for _, r := range rpt.Secrets {
			b.WriteString("  " + r.summary() + "\n")
		}
	}

	// 7. Headers
	b.WriteString("\n" + line + "\n")
	b.WriteString("  7. SECURITY HEADERS\n")
	b.WriteString(line + "\n")
	if len(rpt.Headers) == 0 {
		b.WriteString("  No header issues found.\n")
	} else {
		for _, r := range rpt.Headers {
			b.WriteString("  " + r.summary() + "\n")
		}
	}

	// 8. TLS
	b.WriteString("\n" + line + "\n")
	b.WriteString("  8. TLS / SSL CONFIGURATION\n")
	b.WriteString(line + "\n")
	if len(rpt.TLS) == 0 {
		b.WriteString("  No TLS issues found.\n")
	} else {
		for _, r := range rpt.TLS {
			b.WriteString("  " + r.summary() + "\n")
		}
	}

	// 9. Redirects
	b.WriteString("\n" + line + "\n")
	b.WriteString("  9. OPEN REDIRECTS\n")
	b.WriteString(line + "\n")
	if len(rpt.Redirects) == 0 {
		b.WriteString("  No open redirects found.\n")
	} else {
		for _, r := range rpt.Redirects {
			b.WriteString("  " + r.summary() + "\n")
		}
	}

	// 10. Smuggling
	b.WriteString("\n" + line + "\n")
	b.WriteString("  10. HTTP REQUEST SMUGGLING\n")
	b.WriteString(line + "\n")
	if len(rpt.Smuggling) == 0 {
		b.WriteString("  No smuggling issues found.\n")
	} else {
		for _, r := range rpt.Smuggling {
			b.WriteString("  " + r.summary() + "\n")
		}
	}

	// Summary
	b.WriteString("\n" + doubleLine + "\n")
	b.WriteString("  SUMMARY\n")
	b.WriteString(doubleLine + "\n")
	b.WriteString(fmt.Sprintf("  Hosts:           %d discovered, %d live\n", rpt.HostsDiscovered, rpt.HostsLive))
	b.WriteString(fmt.Sprintf("  Technologies:    %d detected\n", rpt.TechCount))
	b.WriteString(fmt.Sprintf("  URLs:            %d collected\n", len(rpt.URLs)))
	b.WriteString(fmt.Sprintf("  Open Ports:      %d\n", len(rpt.Ports)))
	b.WriteString(fmt.Sprintf("  Vulnerabilities: %s\n", rpt.vulnBreakdown()))
	b.WriteString(fmt.Sprintf("  Secrets:         %d\n", len(rpt.Secrets)))
	b.WriteString(fmt.Sprintf("  Header Issues:   %d\n", len(rpt.Headers)))
	b.WriteString(fmt.Sprintf("  TLS Issues:      %d\n", len(rpt.TLS)))
	b.WriteString(fmt.Sprintf("  Redirects:       %d\n", len(rpt.Redirects)))
	b.WriteString(fmt.Sprintf("  Smuggling:       %d\n", len(rpt.Smuggling)))
	b.WriteString(doubleLine + "\n")

	return b.String()
}

func (rpt *fullReport) vulnBreakdown() string {
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

// ─── Helpers ────────────────────────────────────────────────────────────

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

// ─── Nessus-style fingerprint → nuclei tag mapping ──────────────────────

var alwaysTags = []string{
	"exposure", "misconfig", "default-login", "takeover", "config",
}

var techTagMap = map[string][]string{
	"wordpress":            {"wordpress", "wp", "wp-plugin", "wp-theme"},
	"joomla":               {"joomla"},
	"drupal":               {"drupal"},
	"magento":              {"magento"},
	"shopify":              {"shopify"},
	"nginx":                {"nginx"},
	"apache":               {"apache"},
	"iis":                  {"iis"},
	"tomcat":               {"tomcat", "apache-tomcat"},
	"lighttpd":             {"lighttpd"},
	"caddy":                {"caddy"},
	"php":                  {"php"},
	"java":                 {"java"},
	"asp.net":              {"asp", "aspx", "iis"},
	"python":               {"python"},
	"ruby":                 {"ruby", "rails"},
	"node.js":              {"nodejs"},
	"jenkins":              {"jenkins"},
	"jira":                 {"jira", "atlassian"},
	"confluence":           {"confluence", "atlassian"},
	"bitbucket":            {"bitbucket", "atlassian"},
	"gitlab":               {"gitlab"},
	"grafana":              {"grafana"},
	"kibana":               {"kibana", "elastic"},
	"elasticsearch":        {"elasticsearch", "elastic"},
	"spring":               {"spring", "springboot"},
	"spring boot":          {"spring", "springboot"},
	"laravel":              {"laravel", "php"},
	"django":               {"django", "python"},
	"flask":                {"flask", "python"},
	"express":              {"express", "nodejs"},
	"next.js":              {"nextjs", "nodejs"},
	"nuxt.js":              {"nuxtjs", "nodejs"},
	"react":                {"react"},
	"angular":              {"angular"},
	"vue.js":               {"vuejs"},
	"cloudflare":           {"cloudflare"},
	"varnish":              {"varnish"},
	"docker":               {"docker"},
	"kubernetes":           {"kubernetes", "k8s"},
	"mongodb":              {"mongodb"},
	"mysql":                {"mysql"},
	"postgresql":           {"postgresql", "postgres"},
	"redis":                {"redis"},
	"rabbitmq":             {"rabbitmq"},
	"apache solr":          {"solr", "apache"},
	"apache struts":        {"struts", "apache"},
	"apache airflow":       {"airflow", "apache"},
	"sonarqube":            {"sonarqube"},
	"moodle":               {"moodle"},
	"phpmyadmin":           {"phpmyadmin", "php"},
	"webmin":               {"webmin"},
	"zimbra":               {"zimbra"},
	"citrix":               {"citrix"},
	"fortinet":             {"fortinet", "fortigate"},
	"palo alto":            {"paloalto"},
	"sonicwall":            {"sonicwall"},
	"microsoft exchange":   {"exchange", "microsoft"},
	"microsoft sharepoint": {"sharepoint", "microsoft"},
	"outlook":              {"outlook", "microsoft"},
	"swagger":              {"swagger", "api"},
	"graphql":              {"graphql", "api"},
}

func buildNucleiTags(techSet map[string]struct{}) []string {
	tagSet := make(map[string]struct{})
	for _, t := range alwaysTags {
		tagSet[t] = struct{}{}
	}
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
