package gitexpose

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FOUEN/narmol/internal/scope"
	"github.com/FOUEN/narmol/internal/workflows"
	"github.com/FOUEN/narmol/internal/workflows/secrets"
)

func init() {
	workflows.Register(&GitExposeWorkflow{})
}

// GitExposeWorkflow checks hosts for exposed .git repositories and scans
// them for secrets using TruffleHog.
type GitExposeWorkflow struct{}

func (w *GitExposeWorkflow) Name() string { return "gitexpose" }

func (w *GitExposeWorkflow) Description() string {
	return "Detect exposed .git repos and scan for leaked secrets using TruffleHog."
}

// gitResult is the JSON output format.
type gitResult struct {
	URL      string `json:"url"`
	Phase    string `json:"phase"`    // "exposed", "secret"
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

func (r gitResult) summary() string {
	return fmt.Sprintf("[%s-%s] %s — %s", strings.ToUpper(r.Phase), strings.ToUpper(r.Severity), r.URL, r.Detail)
}

func (w *GitExposeWorkflow) Run(domain string, s *scope.Scope, opts workflows.OutputOptions) error {
	if !s.IsInScope(domain) {
		return fmt.Errorf("domain %s is not in scope", domain)
	}

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

	seen := &sync.Map{}
	emit := func(r gitResult) bool {
		key := r.Phase + ":" + r.URL + ":" + r.Detail
		if _, loaded := seen.LoadOrStore(key, true); loaded {
			return false
		}
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
		return true
	}

	// Ensure hosts have scheme
	var targets []string
	for _, h := range hosts {
		if !strings.HasPrefix(h, "http://") && !strings.HasPrefix(h, "https://") {
			targets = append(targets, "https://"+h)
		} else {
			targets = append(targets, h)
		}
	}

	fmt.Printf("[*] Checking %d hosts for .git exposure...\n", len(targets))

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

	// Paths to check for git exposure
	gitPaths := []string{
		"/.git/HEAD",
		"/.git/config",
	}

	var exposedCount, secretCount int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for _, host := range targets {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			baseURL := strings.TrimRight(h, "/")
			exposed := false

			for _, path := range gitPaths {
				resp, reqErr := client.Get(baseURL + path)
				if reqErr != nil {
					continue
				}
				resp.Body.Close()

				if resp.StatusCode == 200 {
					if emit(gitResult{
						URL:      h,
						Phase:    "exposed",
						Severity: "high",
						Detail:   fmt.Sprintf("Git repository exposed: %s (HTTP 200)", path),
					}) {
						atomic.AddInt64(&exposedCount, 1)
					}
					exposed = true
					break
				}
			}

			// If .git is exposed, scan for leaked secrets with TruffleHog
			if exposed {
				gitURL := baseURL + "/.git/"
				results, scanErr := secrets.ScanGitRepo(gitURL)
				if scanErr != nil {
					return
				}
				for _, r := range results {
					detail := fmt.Sprintf("[%s] %s", r.DetectorType, r.Redacted)
					if r.Verified {
						detail += " (VERIFIED)"
					}
					if emit(gitResult{
						URL:      h,
						Phase:    "secret",
						Severity: "critical",
						Detail:   detail,
					}) {
						atomic.AddInt64(&secretCount, 1)
					}
				}
			}
		}(host)
	}

	wg.Wait()

	// ── Summary ───────────────────────────────────────────────────────
	exposed := atomic.LoadInt64(&exposedCount)
	secretsFound := atomic.LoadInt64(&secretCount)
	if opts.TextFile != "" {
		fmt.Printf("[+] Text results saved to: %s\n", opts.TextFile)
	}
	if opts.JSONFile != "" {
		fmt.Printf("[+] JSON results saved to: %s\n", opts.JSONFile)
	}
	fmt.Printf("[+] Workflow 'gitexpose' completed — %d exposed, %d secrets found\n", exposed, secretsFound)
	return nil
}
