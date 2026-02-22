package techdetect

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FOUEN/narmol/internal/scope"
	"github.com/FOUEN/narmol/internal/workflows"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

func init() {
	workflows.Register(&TechDetectWorkflow{})
}

// TechDetectWorkflow fingerprints technologies on alive hosts using wappalyzergo.
// Pure stdlib HTTP + wappalyzergo fingerprinting.
type TechDetectWorkflow struct{}

func (w *TechDetectWorkflow) Name() string { return "techdetect" }

func (w *TechDetectWorkflow) Description() string {
	return "Detect technologies on alive hosts using wappalyzer fingerprinting."
}

// techResult is the JSON output format.
type techResult struct {
	URL  string   `json:"url"`
	Host string   `json:"host"`
	Tech []string `json:"tech"`
}

func (r techResult) summary() string {
	return fmt.Sprintf("%s → %s", r.URL, strings.Join(r.Tech, ", "))
}

func (w *TechDetectWorkflow) Run(domain string, s *scope.Scope, opts workflows.OutputOptions) error {
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

	// ── Wappalyzer init ───────────────────────────────────────────────
	wap, err := wappalyzer.New()
	if err != nil {
		return fmt.Errorf("failed to initialize wappalyzer: %w", err)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
		},
	}

	fmt.Printf("[*] Fingerprinting %d hosts...\n", len(hosts))

	var count int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Ensure URL has scheme
			target := h
			if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
				target = "https://" + target
			}

			resp, reqErr := client.Get(target)
			if reqErr != nil {
				// Try HTTP if HTTPS fails
				if strings.HasPrefix(target, "https://") {
					target = "http://" + strings.TrimPrefix(target, "https://")
					resp, reqErr = client.Get(target)
					if reqErr != nil {
						return
					}
				} else {
					return
				}
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max

			techs := wap.Fingerprint(resp.Header, body)
			if len(techs) == 0 {
				return
			}

			techList := make([]string, 0, len(techs))
			for t := range techs {
				techList = append(techList, t)
			}
			sort.Strings(techList)

			result := techResult{
				URL:  target,
				Host: h,
				Tech: techList,
			}
			atomic.AddInt64(&count, 1)

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
		}(host)
	}

	wg.Wait()

	// ── Summary ───────────────────────────────────────────────────────
	total := atomic.LoadInt64(&count)
	if opts.TextFile != "" {
		fmt.Printf("[+] Text results saved to: %s\n", opts.TextFile)
	}
	if opts.JSONFile != "" {
		fmt.Printf("[+] JSON results saved to: %s\n", opts.JSONFile)
	}
	fmt.Printf("[+] Workflow 'techdetect' completed — %d hosts fingerprinted\n", total)
	return nil
}
