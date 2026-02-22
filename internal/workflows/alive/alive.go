package alive

import (
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/FOUEN/narmol/internal/scope"
	"github.com/FOUEN/narmol/internal/workflows"

	"github.com/projectdiscovery/goflags"
	httpx_runner "github.com/projectdiscovery/httpx/runner"
)

func init() {
	workflows.Register(&AliveWorkflow{})
}

// AliveWorkflow probes a list of hosts to check which ones are alive.
// Single step: httpx probe → alive hosts with status code, title, server.
type AliveWorkflow struct{}

func (w *AliveWorkflow) Name() string { return "alive" }

func (w *AliveWorkflow) Description() string {
	return "Check which hosts are alive using httpx. Returns status code, title, server."
}

// aliveResult is the JSON output format.
type aliveResult struct {
	URL        string `json:"url"`
	Host       string `json:"host"`
	StatusCode int    `json:"status_code"`
	Title      string `json:"title,omitempty"`
	Webserver  string `json:"webserver,omitempty"`
	Scheme     string `json:"scheme"`
}

func (r aliveResult) summary() string {
	title := ""
	if r.Title != "" {
		title = " - " + r.Title
	}
	server := ""
	if r.Webserver != "" {
		server = " [" + r.Webserver + "]"
	}
	return fmt.Sprintf("[%d] %s%s%s", r.StatusCode, r.URL, title, server)
}

func (w *AliveWorkflow) Run(domain string, s *scope.Scope, opts workflows.OutputOptions) error {
	if !s.IsInScope(domain) {
		return fmt.Errorf("domain %s is not in scope", domain)
	}

	// The domain itself is the target (or could be a list via scope)
	hosts := []string{domain}

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

	// ── httpx probe ───────────────────────────────────────────────────
	fmt.Printf("[*] Probing %d hosts with httpx...\n", len(hosts))

	var aliveCount int64

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
		ExtractTitle:       true,
		OnResult: func(r httpx_runner.Result) {
			if r.Err != nil {
				return
			}
			if !s.IsInScope(r.Host) {
				return
			}

			result := aliveResult{
				URL:        r.URL,
				Host:       r.Host,
				StatusCode: r.StatusCode,
				Title:      r.Title,
				Webserver:  r.WebServer,
				Scheme:     r.Scheme,
			}
			atomic.AddInt64(&aliveCount, 1)

			if textFile == nil && jsonFile == nil {
				fmt.Println(result.summary())
			}
			if textFile != nil {
				fmt.Fprintln(textFile, result.summary())
			}
			if jsonFile != nil {
				if js, jErr := json.Marshal(result); jErr == nil {
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
	alive := atomic.LoadInt64(&aliveCount)
	if opts.TextFile != "" {
		fmt.Printf("[+] Text results saved to: %s\n", opts.TextFile)
	}
	if opts.JSONFile != "" {
		fmt.Printf("[+] JSON results saved to: %s\n", opts.JSONFile)
	}
	fmt.Printf("[+] Workflow 'alive' completed — %d hosts alive\n", alive)
	return nil
}
