package active

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"

	"github.com/FOUEN/narmol/internal/scope"
	"github.com/FOUEN/narmol/internal/workflows"

	"github.com/projectdiscovery/goflags"
	httpx_runner "github.com/projectdiscovery/httpx/runner"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	subfinder_runner "github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

func init() {
	workflows.Register(&ActiveWorkflow{})
}

// ActiveWorkflow finds all subdomains for a domain and probes which ones are active.
// Step 1: subfinder discovers subdomains, filtering through scope.
// Step 2: httpx probes all in-scope hosts to find active ones.
type ActiveWorkflow struct{}

func (w *ActiveWorkflow) Name() string {
	return "active"
}

func (w *ActiveWorkflow) Description() string {
	return "Find all subdomains and check which are active (alive). Runs subfinder then httpx."
}

func (w *ActiveWorkflow) Run(domain string, s *scope.Scope, opts workflows.OutputOptions) error {
	// Pre-checks
	if !s.IsInScope(domain) {
		return fmt.Errorf("domain %s is not in scope", domain)
	}
	if !s.HasWildcard(domain) {
		return fmt.Errorf("active workflow requires a wildcard scope (*.%s) to invoke subdomain enumeration", domain)
	}

	// ── Step 1: Subfinder ─────────────────────────────────────────────
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
		},
	}

	sfRunner, err := subfinder_runner.NewRunner(sfOptions)
	if err != nil {
		return fmt.Errorf("could not create subfinder runner: %w", err)
	}
	if err := sfRunner.RunEnumerationWithCtx(context.Background()); err != nil {
		return fmt.Errorf("subfinder enumeration failed: %w", err)
	}

	fmt.Printf("[+] Subfinder found %d subdomains -- %d in scope, %d excluded\n",
		totalFound, inScope, excluded)

	if len(hosts) == 0 {
		return fmt.Errorf("no subdomains remaining after scope filtering")
	}

	// ── Step 2: httpx ─────────────────────────────────────────────────
	fmt.Printf("[*] Probing %d hosts with httpx...\n", len(hosts))

	// Open output files
	var textFile, jsonFile *os.File
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

	var activeCount int64

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
			compact := compactFromResult(r)
			atomic.AddInt64(&activeCount, 1)

			if textFile == nil && jsonFile == nil {
				fmt.Println(compact.URL)
			}
			if textFile != nil {
				fmt.Fprintln(textFile, compact.URL)
			}
			if jsonFile != nil {
				if js, err := json.Marshal(compact); err == nil {
					fmt.Fprintln(jsonFile, string(js))
				}
			}
		},
	}

	if err := hxOptions.ValidateOptions(); err != nil {
		return fmt.Errorf("httpx options validation failed: %w", err)
	}

	hxRunner, err := httpx_runner.New(hxOptions)
	if err != nil {
		return fmt.Errorf("could not create httpx runner: %w", err)
	}

	hxRunner.RunEnumeration()
	hxRunner.Close()

	// ── Summary ───────────────────────────────────────────────────────
	active := atomic.LoadInt64(&activeCount)

	if opts.JSONFile != "" {
		fmt.Printf("[+] JSON results saved to: %s\n", opts.JSONFile)
	}
	if opts.TextFile != "" {
		fmt.Printf("[+] Text results saved to: %s\n", opts.TextFile)
	}

	fmt.Printf("[+] Workflow 'active' completed -- %d active hosts found.\n", active)
	return nil
}

// activeResult contains only the essential fields for the active workflow.
// Other workflows (tech, vuln, recon) will provide deeper detail.
type activeResult struct {
	URL        string   `json:"url"`
	Input      string   `json:"input"`
	Host       string   `json:"host"`
	Port       string   `json:"port,omitempty"`
	Scheme     string   `json:"scheme"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title,omitempty"`
	Webserver  string   `json:"webserver,omitempty"`
	Tech       []string `json:"tech,omitempty"`
	CDN        bool     `json:"cdn,omitempty"`
	CDNName    string   `json:"cdn_name,omitempty"`
}

// compactFromResult converts a full httpx Result struct into a compact
// activeResult keeping only fields relevant for the active workflow.
func compactFromResult(r httpx_runner.Result) activeResult {
	return activeResult{
		URL:        r.URL,
		Input:      r.Input,
		Host:       r.Host,
		Port:       r.Port,
		Scheme:     r.Scheme,
		StatusCode: r.StatusCode,
		Title:      r.Title,
		Webserver:  r.WebServer,
		Tech:       r.Technologies,
		CDN:        r.CDN,
		CDNName:    r.CDNName,
	}
}

// compactResult parses a full httpx JSON line and returns a compact JSON string
// with only the fields relevant for the active workflow, plus the URL.
// Used by tests and as a fallback for JSON line processing.
func compactResult(jsonLine string) (string, string) {
	var full map[string]json.RawMessage
	if err := json.Unmarshal([]byte(jsonLine), &full); err != nil {
		return "", ""
	}

	r := activeResult{}
	jsonGetString(full, "url", &r.URL)
	jsonGetString(full, "input", &r.Input)
	jsonGetString(full, "host", &r.Host)
	jsonGetString(full, "port", &r.Port)
	jsonGetString(full, "scheme", &r.Scheme)
	jsonGetString(full, "title", &r.Title)
	jsonGetString(full, "webserver", &r.Webserver)
	jsonGetString(full, "cdn_name", &r.CDNName)

	if raw, ok := full["status_code"]; ok {
		json.Unmarshal(raw, &r.StatusCode)
	}
	if raw, ok := full["cdn"]; ok {
		json.Unmarshal(raw, &r.CDN)
	}
	if raw, ok := full["tech"]; ok {
		json.Unmarshal(raw, &r.Tech)
	}

	out, err := json.Marshal(r)
	if err != nil {
		return "", ""
	}
	return string(out), r.URL
}

func jsonGetString(m map[string]json.RawMessage, key string, dst *string) {
	if raw, ok := m[key]; ok {
		json.Unmarshal(raw, dst)
	}
}
