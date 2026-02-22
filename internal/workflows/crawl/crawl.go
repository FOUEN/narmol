package crawl

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/FOUEN/narmol/internal/scope"
	"github.com/FOUEN/narmol/internal/workflows"

	katana_output "github.com/projectdiscovery/katana/pkg/output"
	katana_standard "github.com/projectdiscovery/katana/pkg/engine/standard"
	katana_types "github.com/projectdiscovery/katana/pkg/types"
)

func init() {
	workflows.Register(&CrawlWorkflow{})
}

// CrawlWorkflow crawls alive hosts to discover endpoints, links, and JS files.
// Uses katana standard (HTTP) engine.
type CrawlWorkflow struct{}

func (w *CrawlWorkflow) Name() string { return "crawl" }

func (w *CrawlWorkflow) Description() string {
	return "Crawl alive hosts with katana to discover endpoints, links, and JS files."
}

// crawlResult is the JSON output format.
type crawlResult struct {
	URL    string `json:"url"`
	Source string `json:"source"`
	Tag    string `json:"tag,omitempty"`
	Attr   string `json:"attribute,omitempty"`
}

func (r crawlResult) summary() string {
	extra := ""
	if r.Tag != "" {
		extra = fmt.Sprintf(" (%s.%s)", r.Tag, r.Attr)
	}
	return fmt.Sprintf("%s%s", r.URL, extra)
}

func (w *CrawlWorkflow) Run(domain string, s *scope.Scope, opts workflows.OutputOptions) error {
	if !s.IsInScope(domain) {
		return fmt.Errorf("domain %s is not in scope", domain)
	}

	// Ensure URL has scheme
	target := domain
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
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
	var count int64

	fmt.Printf("[*] Crawling %s with katana...\n", target)

	katanaOpts := &katana_types.Options{
		MaxDepth:     3,
		FieldScope:   "rdn",
		Concurrency:  10,
		Parallelism:  10,
		Timeout:      10,
		RateLimit:    100,
		Strategy:     "breadth-first",
		KnownFiles:   "all",
		NoColors:     true,
		Silent:       true,
		OnResult: func(result katana_output.Result) {
			u := result.Request.URL
			if u == "" {
				return
			}
			if _, loaded := seen.LoadOrStore(u, true); loaded {
				return
			}
			if !s.IsInScope(u) {
				return
			}

			r := crawlResult{
				URL:    u,
				Source: result.Request.Source,
				Tag:    result.Request.Tag,
				Attr:   result.Request.Attribute,
			}
			atomic.AddInt64(&count, 1)

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
		},
	}

	crawlerOptions, err := katana_types.NewCrawlerOptions(katanaOpts)
	if err != nil {
		return fmt.Errorf("failed to create crawler options: %w", err)
	}
	defer crawlerOptions.Close()

	crawler, err := katana_standard.New(crawlerOptions)
	if err != nil {
		return fmt.Errorf("failed to create crawler: %w", err)
	}
	defer crawler.Close()

	if err := crawler.Crawl(target); err != nil {
		return fmt.Errorf("crawl failed: %w", err)
	}

	// ── Summary ───────────────────────────────────────────────────────
	total := atomic.LoadInt64(&count)
	if opts.TextFile != "" {
		fmt.Printf("[+] Text results saved to: %s\n", opts.TextFile)
	}
	if opts.JSONFile != "" {
		fmt.Printf("[+] JSON results saved to: %s\n", opts.JSONFile)
	}
	fmt.Printf("[+] Workflow 'crawl' completed — %d URLs discovered\n", total)
	return nil
}
