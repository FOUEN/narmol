package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/FOUEN/narmol/internal/scope"
	"github.com/FOUEN/narmol/internal/workflows"

	gau_providers "github.com/lc/gau/v2/pkg/providers"
	gau_runner "github.com/lc/gau/v2/runner"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	subfinder_runner "github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

func init() {
	workflows.Register(&ReconWorkflow{})
}

// ReconWorkflow performs passive reconnaissance on targets defined in scope.
// - If scope has wildcard (*.example.com): runs subfinder (+ recursive) then gau.
// - If scope is exact domain (example.com): runs only gau.
// - If scope has IPs/CIDRs: passes them through as known targets.
// This workflow NEVER touches the target directly — only external data sources.
type ReconWorkflow struct{}

func (w *ReconWorkflow) Name() string {
	return "recon"
}

func (w *ReconWorkflow) Description() string {
	return "Passive reconnaissance: subdomain enumeration (subfinder) + historical URLs (gau). No direct contact with target."
}

func (w *ReconWorkflow) Run(domain string, s *scope.Scope, opts workflows.OutputOptions) error {
	if !s.IsInScope(domain) {
		return fmt.Errorf("domain %s is not in scope", domain)
	}

	// Open output files
	var textFile, jsonFile *os.File
	var err error

	if opts.TextFile != "" {
		textFile, err = os.OpenFile(opts.TextFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open text output file %s: %w", opts.TextFile, err)
		}
		defer textFile.Close()
	}
	if opts.JSONFile != "" {
		jsonFile, err = os.OpenFile(opts.JSONFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open JSON output file %s: %w", opts.JSONFile, err)
		}
		defer jsonFile.Close()
	}

	emit := func(r reconResult) {
		if textFile == nil && jsonFile == nil {
			fmt.Println(r.Value)
		}
		if textFile != nil {
			fmt.Fprintln(textFile, r.Value)
		}
		if jsonFile != nil {
			if js, err := json.Marshal(r); err == nil {
				fmt.Fprintln(jsonFile, string(js))
			}
		}
	}

	// Track unique values across all steps
	seen := &sync.Map{}
	emitUnique := func(r reconResult) bool {
		if _, loaded := seen.LoadOrStore(r.Value, true); loaded {
			return false
		}
		emit(r)
		return true
	}

	var subdomainCount, urlCount int64

	// ── Step 1: Subfinder (only if wildcard scope) ────────────────────
	if s.HasWildcard(domain) {
		subs := w.runSubfinder(domain, s, emitUnique, &subdomainCount)

		// ── Step 1b: Recursive subfinder ──────────────────────────────
		// Feed discovered subdomains back to find deeper levels.
		if len(subs) > 0 {
			w.runSubfinderRecursive(subs, s, emitUnique, &subdomainCount)
		}
	} else {
		// Exact domain — emit the domain itself as a subdomain result
		emitUnique(reconResult{Type: "subdomain", Value: domain, Source: "scope", Domain: domain})
		atomic.AddInt64(&subdomainCount, 1)
		fmt.Printf("[*] Exact domain scope — skipping subfinder for %s\n", domain)
	}

	// ── Step 2: Gau (historical URLs) ─────────────────────────────────
	w.runGau(domain, s, emitUnique, &urlCount)

	// ── Summary ───────────────────────────────────────────────────────
	subs := atomic.LoadInt64(&subdomainCount)
	urls := atomic.LoadInt64(&urlCount)

	if opts.JSONFile != "" {
		fmt.Printf("[+] JSON results saved to: %s\n", opts.JSONFile)
	}
	if opts.TextFile != "" {
		fmt.Printf("[+] Text results saved to: %s\n", opts.TextFile)
	}
	fmt.Printf("[+] Recon for %s completed — %d subdomains, %d URLs collected.\n", domain, subs, urls)
	return nil
}

// runSubfinder runs passive subdomain enumeration and returns discovered hosts.
func (w *ReconWorkflow) runSubfinder(domain string, s *scope.Scope, emitUnique func(reconResult) bool, count *int64) []string {
	fmt.Println("[*] Running subfinder...")

	var totalFound, inScope, excluded int64
	var hosts []string

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
			atomic.AddInt64(&totalFound, 1)
			host := strings.TrimSpace(result.Host)
			if host == "" {
				return
			}
			if !s.IsInScope(host) {
				atomic.AddInt64(&excluded, 1)
				return
			}
			atomic.AddInt64(&inScope, 1)
			hosts = append(hosts, host)

			if emitUnique(reconResult{Type: "subdomain", Value: host, Source: "subfinder", Domain: domain}) {
				atomic.AddInt64(count, 1)
			}
		},
	}

	sfRunner, err := subfinder_runner.NewRunner(sfOptions)
	if err != nil {
		fmt.Printf("[!] Could not create subfinder runner: %s\n", err)
		return nil
	}
	if err := sfRunner.RunEnumerationWithCtx(context.Background()); err != nil {
		fmt.Printf("[!] Subfinder enumeration failed: %s\n", err)
		return nil
	}

	fmt.Printf("[+] Subfinder found %d subdomains — %d in scope, %d excluded\n",
		totalFound, inScope, excluded)

	return hosts
}

// runSubfinderRecursive takes already-discovered subdomains and feeds them back
// to subfinder to find deeper subdomain levels (e.g. sub.sub.example.com).
func (w *ReconWorkflow) runSubfinderRecursive(seeds []string, s *scope.Scope, emitUnique func(reconResult) bool, count *int64) {
	// Deduplicate base domains for recursive enumeration
	bases := map[string]bool{}
	for _, host := range seeds {
		// Only recurse on subdomains that could have their own subdomains
		// e.g. "api.example.com" → try to find "*.api.example.com"
		if strings.Count(host, ".") >= 2 {
			bases[host] = true
		}
	}
	if len(bases) == 0 {
		return
	}

	fmt.Printf("[*] Running recursive subfinder on %d subdomains...\n", len(bases))

	var newFound int64

	for base := range bases {
		sfOptions := &subfinder_runner.Options{
			Domain:             goflags.StringSlice{base},
			Silent:             true,
			All:                false,
			Timeout:            30,
			MaxEnumerationTime: 5, // shorter timeout for recursive
			Threads:            10,
			DisableUpdateCheck: true,
			Output:             io.Discard,
			ProviderConfig:     "",
			ResultCallback: func(result *resolve.HostEntry) {
				host := strings.TrimSpace(result.Host)
				if host == "" || !s.IsInScope(host) {
					return
				}
				if emitUnique(reconResult{Type: "subdomain", Value: host, Source: "subfinder-recursive", Domain: base}) {
					atomic.AddInt64(&newFound, 1)
					atomic.AddInt64(count, 1)
				}
			},
		}

		sfRunner, err := subfinder_runner.NewRunner(sfOptions)
		if err != nil {
			continue
		}
		_ = sfRunner.RunEnumerationWithCtx(context.Background())
	}

	fmt.Printf("[+] Recursive subfinder found %d new subdomains\n", newFound)
}

// runGau collects historical URLs from Wayback Machine, Common Crawl, OTX, URLScan.
func (w *ReconWorkflow) runGau(domain string, s *scope.Scope, emitUnique func(reconResult) bool, count *int64) {
	fmt.Printf("[*] Running gau on %s...\n", domain)

	config := &gau_providers.Config{
		Threads:           5,
		Timeout:           30,
		MaxRetries:        3,
		IncludeSubdomains: true,
		RemoveParameters:  false,
	}

	providerNames := []string{"wayback", "commoncrawl", "otx", "urlscan"}

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

	// Feed work
	go func() {
		for _, provider := range gau.Providers {
			workChan <- gau_runner.NewWork(domain, provider)
		}
		close(workChan)
	}()

	// Collect results in background
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for urlStr := range results {
			urlStr = strings.TrimSpace(urlStr)
			if urlStr == "" {
				continue
			}
			// Scope filter the URL
			if !s.IsInScope(urlStr) {
				continue
			}
			if emitUnique(reconResult{Type: "url", Value: urlStr, Source: "gau", Domain: domain}) {
				atomic.AddInt64(count, 1)
			}
		}
	}()

	// Wait for gau workers to finish
	gau.Wait()
	close(results)
	wg.Wait()

	fmt.Printf("[+] Gau collected %d unique URLs for %s\n", atomic.LoadInt64(count), domain)
}

// reconResult represents a single finding from the recon workflow.
type reconResult struct {
	Type   string `json:"type"`   // "subdomain", "url", "ip"
	Value  string `json:"value"`  // the actual subdomain, URL, or IP
	Source string `json:"source"` // "subfinder", "subfinder-recursive", "gau", "scope"
	Domain string `json:"domain"` // parent domain this was found for
}
