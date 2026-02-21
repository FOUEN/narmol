//go:build !bootstrap

package active

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

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
// Subfinder and httpx run concurrently: as subdomains are discovered they are
// immediately streamed to httpx for probing, eliminating the wait between steps.
type ActiveWorkflow struct{}

func (w *ActiveWorkflow) Name() string {
	return "active"
}

func (w *ActiveWorkflow) Description() string {
	return "Find all subdomains and check which are active (alive). Runs subfinder->httpx as a concurrent pipeline."
}

func (w *ActiveWorkflow) Run(domain string, s *scope.Scope, opts workflows.OutputOptions) error {
	// Pre-checks
	if !s.IsInScope(domain) {
		return fmt.Errorf("domain %s is not in scope", domain)
	}
	if !s.HasWildcard(domain) {
		return fmt.Errorf("active workflow requires a wildcard scope (*.%s) to invoke subdomain enumeration", domain)
	}

	// Temp directory for the FIFO
	tmpDir, err := os.MkdirTemp("", "narmol-active-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a named pipe (FIFO)
	// Subfinder writes in-scope hosts here; httpx reads from it in stream mode.
	fifoPath := filepath.Join(tmpDir, "pipeline.fifo")
	if err := syscall.Mkfifo(fifoPath, 0600); err != nil {
		return fmt.Errorf("failed to create FIFO: %w", err)
	}

	// Counters for the summary line
	var totalFound int64
	var inScope int64
	var excluded int64
	var activeCount int64

	// Open output files up front so we can stream results into them.
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

	// Goroutine: httpx (consumer)
	// httpx opens the FIFO for reading in Stream mode. It blocks until the
	// writer (subfinder goroutine) also opens the FIFO.
	// OnResult streams each result to output files/stdout in real time.
	var httpxErr error
	var httpxWg sync.WaitGroup
	httpxWg.Add(1)

	go func() {
		defer httpxWg.Done()

		hxOptions := &httpx_runner.Options{
			InputFile:          fifoPath,
			Silent:             true,
			DisableStdout:      true,
			Stream:             true,
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
				// Compact the full httpx result to essential fields
				compact := compactFromResult(r)
				atomic.AddInt64(&activeCount, 1)

				// Stream to stdout (default)
				if textFile == nil && jsonFile == nil {
					fmt.Println(compact.URL)
				}
				// Stream to text file
				if textFile != nil {
					fmt.Fprintln(textFile, compact.URL)
				}
				// Stream to JSON file
				if jsonFile != nil {
					if js, err := json.Marshal(compact); err == nil {
						fmt.Fprintln(jsonFile, string(js))
					}
				}
			},
		}

		if err := hxOptions.ValidateOptions(); err != nil {
			httpxErr = fmt.Errorf("httpx options validation failed: %w", err)
			if f, openErr := os.Open(fifoPath); openErr == nil {
				f.Close()
			}
			return
		}

		hxRunner, err := httpx_runner.New(hxOptions)
		if err != nil {
			httpxErr = fmt.Errorf("could not create httpx runner: %w", err)
			if f, openErr := os.Open(fifoPath); openErr == nil {
				f.Close()
			}
			return
		}

		hxRunner.RunEnumeration()
		hxRunner.Close()
	}()

	// Goroutine: subfinder (producer)
	// Opens the FIFO for writing and pushes every in-scope subdomain through it.
	fmt.Println("[*] Pipeline started: subfinder -> scope filter -> httpx (concurrent)")

	var subfinderErr error
	var sfWg sync.WaitGroup
	sfWg.Add(1)

	go func() {
		defer sfWg.Done()

		// Open the write end of the FIFO (blocks until httpx opens the read end)
		fifoWriter, err := os.OpenFile(fifoPath, os.O_WRONLY, os.ModeNamedPipe)
		if err != nil {
			subfinderErr = fmt.Errorf("failed to open FIFO for writing: %w", err)
			return
		}
		defer fifoWriter.Close()

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
				fmt.Fprintln(fifoWriter, host)
			},
		}

		sfRunner, err := subfinder_runner.NewRunner(sfOptions)
		if err != nil {
			subfinderErr = fmt.Errorf("could not create subfinder runner: %w", err)
			return
		}

		if err := sfRunner.RunEnumerationWithCtx(context.Background()); err != nil {
			subfinderErr = fmt.Errorf("subfinder enumeration failed: %w", err)
			return
		}
	}()

	// Wait for subfinder to finish (closes the FIFO write end -> EOF for httpx)
	sfWg.Wait()
	// Then wait for httpx to drain remaining targets
	httpxWg.Wait()

	// Error handling
	if subfinderErr != nil {
		return subfinderErr
	}
	if httpxErr != nil {
		return httpxErr
	}

	fmt.Printf("[+] Subfinder found %d subdomains -- %d in scope, %d excluded\n",
		atomic.LoadInt64(&totalFound), atomic.LoadInt64(&inScope), atomic.LoadInt64(&excluded))

	if atomic.LoadInt64(&inScope) == 0 {
		return fmt.Errorf("no subdomains remaining after scope filtering")
	}

	active := atomic.LoadInt64(&activeCount)

	if opts.JSONFile != "" {
		fmt.Printf("[+] JSON results streamed to: %s\n", opts.JSONFile)
	}
	if opts.TextFile != "" {
		fmt.Printf("[+] Text results streamed to: %s\n", opts.TextFile)
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
