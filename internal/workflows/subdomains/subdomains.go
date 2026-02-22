package subdomains

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

	dns "github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	subfinder_runner "github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

func init() {
	workflows.Register(&SubdomainsWorkflow{})
}

// SubdomainsWorkflow enumerates subdomains (passive + DNS resolution), no probing.
// Pipeline: subfinder (recursive) → dnsx resolution → dedup + scope filter.
type SubdomainsWorkflow struct{}

func (w *SubdomainsWorkflow) Name() string { return "subdomains" }

func (w *SubdomainsWorkflow) Description() string {
	return "Subdomain enumeration (passive subfinder + recursive + DNS resolution). No probing."
}

// subdomainResult is the JSON output format.
type subdomainResult struct {
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips,omitempty"`
	Source    string   `json:"source,omitempty"`
}

func (r subdomainResult) summary() string {
	if len(r.IPs) > 0 {
		return fmt.Sprintf("%s → %s", r.Subdomain, strings.Join(r.IPs, ", "))
	}
	return r.Subdomain
}

func (w *SubdomainsWorkflow) Run(domain string, s *scope.Scope, opts workflows.OutputOptions) error {
	if !s.IsInScope(domain) {
		return fmt.Errorf("domain %s is not in scope", domain)
	}
	if !s.HasWildcard(domain) {
		return fmt.Errorf("subdomains workflow requires wildcard scope (*.%s)", domain)
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
	emit := func(r subdomainResult) {
		key := r.Subdomain
		if _, loaded := seen.LoadOrStore(key, true); loaded {
			return
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
	}

	// ── Step 1: Subfinder (recursive) ─────────────────────────────────
	fmt.Println("[*] Running subfinder (recursive)...")

	allSubs := w.runSubfinderRecursive(domain, s)

	if len(allSubs) == 0 {
		fmt.Println("[!] No subdomains found")
		return nil
	}
	fmt.Printf("[+] Subfinder found %d unique subdomains\n", len(allSubs))

	// ── Step 2: DNS resolution (dnsx) ─────────────────────────────────
	fmt.Printf("[*] Resolving %d subdomains with dnsx...\n", len(allSubs))

	dnsOpts := dnsx.DefaultOptions
	dnsOpts.MaxRetries = 3
	dnsOpts.QuestionTypes = []uint16{dns.TypeA, dns.TypeAAAA}

	client, err := dnsx.New(dnsOpts)
	if err != nil {
		// Fallback: emit without resolution
		fmt.Printf("[!] Could not create dnsx client: %v — emitting without resolution\n", err)
		for _, sub := range allSubs {
			emit(subdomainResult{Subdomain: sub, Source: "subfinder"})
		}
	} else {
		var resolved, failed int64
		sem := make(chan struct{}, 50)
		var wg sync.WaitGroup

		for _, sub := range allSubs {
			wg.Add(1)
			go func(hostname string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				ips, lookupErr := client.Lookup(hostname)
				if lookupErr != nil || len(ips) == 0 {
					atomic.AddInt64(&failed, 1)
					emit(subdomainResult{Subdomain: hostname, Source: "subfinder"})
					return
				}
				atomic.AddInt64(&resolved, 1)
				emit(subdomainResult{Subdomain: hostname, IPs: ips, Source: "subfinder"})
			}(sub)
		}

		wg.Wait()
		fmt.Printf("[+] DNS resolution: %d resolved, %d without records\n", resolved, failed)
	}

	// ── Summary ───────────────────────────────────────────────────────
	if opts.TextFile != "" {
		fmt.Printf("[+] Text results saved to: %s\n", opts.TextFile)
	}
	if opts.JSONFile != "" {
		fmt.Printf("[+] JSON results saved to: %s\n", opts.JSONFile)
	}
	fmt.Printf("[+] Workflow 'subdomains' completed — %d subdomains\n", len(allSubs))
	return nil
}

// runSubfinderRecursive runs subfinder, then feeds discovered subdomains back
// for a second pass to find deeper subdomains.
func (w *SubdomainsWorkflow) runSubfinderRecursive(domain string, s *scope.Scope) []string {
	seen := make(map[string]bool)
	queue := []string{domain}

	for round := 0; round < 3; round++ {
		if len(queue) == 0 {
			break
		}

		var newSubs []string
		for _, target := range queue {
			var mu sync.Mutex
			sfOptions := &subfinder_runner.Options{
				Domain:             goflags.StringSlice{target},
				Silent:             true,
				All:                false,
				Timeout:            30,
				MaxEnumerationTime: 10,
				Threads:            10,
				DisableUpdateCheck: true,
				Output:             io.Discard,
				ResultCallback: func(result *resolve.HostEntry) {
					host := strings.TrimSpace(result.Host)
					if host == "" || !s.IsInScope(host) {
						return
					}
					mu.Lock()
					if !seen[host] {
						seen[host] = true
						newSubs = append(newSubs, host)
					}
					mu.Unlock()
				},
			}
			sfRunner, err := subfinder_runner.NewRunner(sfOptions)
			if err != nil {
				continue
			}
			sfRunner.RunEnumerationWithCtx(context.Background())
		}

		if round == 0 {
			fmt.Printf("[+] Round 1: %d subdomains\n", len(newSubs))
		} else {
			fmt.Printf("[+] Round %d: %d new subdomains\n", round+1, len(newSubs))
		}
		queue = newSubs
	}

	result := make([]string, 0, len(seen))
	for sub := range seen {
		result = append(result, sub)
	}
	return result
}
