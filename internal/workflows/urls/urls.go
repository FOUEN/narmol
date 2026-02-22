package urls

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/FOUEN/narmol/internal/scope"
	"github.com/FOUEN/narmol/internal/workflows"

	mapset "github.com/deckarep/golang-set/v2"
	gau_providers "github.com/lc/gau/v2/pkg/providers"
	gau_runner "github.com/lc/gau/v2/runner"
	"github.com/valyala/fasthttp"

	katana_standard "github.com/projectdiscovery/katana/pkg/engine/standard"
	katana_output "github.com/projectdiscovery/katana/pkg/output"
	katana_types "github.com/projectdiscovery/katana/pkg/types"
)

func init() {
	workflows.Register(&URLsWorkflow{})
}

// URLsWorkflow collects URLs from historical sources (gau) + live crawling (katana).
// Both run in parallel.
type URLsWorkflow struct{}

func (w *URLsWorkflow) Name() string { return "urls" }

func (w *URLsWorkflow) Description() string {
	return "Collect URLs: historical (gau: Wayback, OTX, URLScan) + live crawl (katana). Parallel."
}

// urlResult is the JSON output format.
type urlResult struct {
	URL    string `json:"url"`
	Source string `json:"source"` // "gau", "katana"
}

func (w *URLsWorkflow) Run(domain string, s *scope.Scope, opts workflows.OutputOptions) error {
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

	seen := &sync.Map{}
	emit := func(r urlResult) bool {
		if _, loaded := seen.LoadOrStore(r.URL, true); loaded {
			return false
		}
		if textFile == nil && jsonFile == nil {
			fmt.Println(r.URL)
		}
		if textFile != nil {
			fmt.Fprintln(textFile, r.URL)
		}
		if jsonFile != nil {
			if js, jErr := json.Marshal(r); jErr == nil {
				fmt.Fprintln(jsonFile, string(js))
			}
		}
		return true
	}

	var gauCount, katanaCount int64
	var wg sync.WaitGroup

	// ── gau (historical) ──────────────────────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		gauCount = w.runGau(domain, s, emit)
	}()

	// ── katana (live crawl) ───────────────────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		katanaCount = w.runKatana(domain, s, emit)
	}()

	wg.Wait()

	// ── Summary ───────────────────────────────────────────────────────
	if opts.TextFile != "" {
		fmt.Printf("[+] Text results saved to: %s\n", opts.TextFile)
	}
	if opts.JSONFile != "" {
		fmt.Printf("[+] JSON results saved to: %s\n", opts.JSONFile)
	}
	fmt.Printf("[+] Workflow 'urls' completed — %d from gau, %d from katana\n", gauCount, katanaCount)
	return nil
}

func (w *URLsWorkflow) runGau(domain string, s *scope.Scope, emit func(urlResult) bool) int64 {
	fmt.Printf("[*] Running gau on %s...\n", domain)

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
		return 0
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

	var count int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for urlStr := range results {
			urlStr = strings.TrimSpace(urlStr)
			if urlStr == "" || !s.IsInScope(urlStr) {
				continue
			}
			if emit(urlResult{URL: urlStr, Source: "gau"}) {
				atomic.AddInt64(&count, 1)
			}
		}
	}()

	gau.Wait()
	close(results)
	wg.Wait()

	total := atomic.LoadInt64(&count)
	fmt.Printf("[+] Gau collected %d URLs\n", total)
	return total
}

func (w *URLsWorkflow) runKatana(domain string, s *scope.Scope, emit func(urlResult) bool) int64 {
	target := domain
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	fmt.Printf("[*] Crawling %s with katana...\n", target)

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
			if emit(urlResult{URL: u, Source: "katana"}) {
				atomic.AddInt64(&count, 1)
			}
		},
	}

	crawlerOptions, err := katana_types.NewCrawlerOptions(katanaOpts)
	if err != nil {
		fmt.Printf("[!] Failed to create katana options: %s\n", err)
		return 0
	}
	defer crawlerOptions.Close()

	crawler, err := katana_standard.New(crawlerOptions)
	if err != nil {
		fmt.Printf("[!] Failed to create katana crawler: %s\n", err)
		return 0
	}
	defer crawler.Close()

	if err := crawler.Crawl(target); err != nil {
		fmt.Printf("[!] Katana crawl failed: %s\n", err)
	}

	total := atomic.LoadInt64(&count)
	fmt.Printf("[+] Katana discovered %d URLs\n", total)
	return total
}
