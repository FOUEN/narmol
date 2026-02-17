package active

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"narmol/scope"
	"narmol/workflows"

	"github.com/projectdiscovery/goflags"
	httpx_runner "github.com/projectdiscovery/httpx/runner"
	subfinder_runner "github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

func init() {
	workflows.Register(&ActiveWorkflow{})
}

// ActiveWorkflow finds all subdomains for a domain and probes which ones are active.
// All outputs are in JSON format. Results are filtered by scope.
type ActiveWorkflow struct{}

func (w *ActiveWorkflow) Name() string {
	return "active"
}

func (w *ActiveWorkflow) Description() string {
	return "Find all subdomains and check which are active (alive). Output: JSON."
}

func (w *ActiveWorkflow) Run(domain string, outputDir string, s *scope.Scope) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	subdomainsFile := filepath.Join(outputDir, "subdomains.json")
	hostsFile := filepath.Join(outputDir, "hosts.txt")
	activeFile := filepath.Join(outputDir, "active.json")

	// ──────────────────────────────────────────────
	// Step 1: Subfinder — discover subdomains
	// ──────────────────────────────────────────────
	fmt.Println("[*] Step 1/3: Running subfinder to discover subdomains...")

	sfOptions := &subfinder_runner.Options{
		Domain:             goflags.StringSlice{domain},
		JSON:               true,
		OutputFile:         subdomainsFile,
		Silent:             true,
		All:                false,
		Timeout:            30,
		MaxEnumerationTime: 10,
		Threads:            10,
		DisableUpdateCheck: true,
		Output:             os.Stdout,
		ProviderConfig:     "", // use default
	}
	sfOptions.ConfigureOutput()

	sfRunner, err := subfinder_runner.NewRunner(sfOptions)
	if err != nil {
		return fmt.Errorf("could not create subfinder runner: %w", err)
	}

	if err := sfRunner.RunEnumerationWithCtx(context.Background()); err != nil {
		return fmt.Errorf("subfinder enumeration failed: %w", err)
	}

	// Verify output
	info, err := os.Stat(subdomainsFile)
	if err != nil || info.Size() == 0 {
		return fmt.Errorf("subfinder produced no results for domain: %s", domain)
	}
	fmt.Printf("[+] Subdomains saved to: %s\n", subdomainsFile)

	// ──────────────────────────────────────────────
	// Step 2: Scope filtering
	// ──────────────────────────────────────────────
	fmt.Println("[*] Step 2/3: Filtering subdomains by scope...")

	hosts, err := extractHostsFromSubfinderJSON(subdomainsFile)
	if err != nil {
		return fmt.Errorf("could not extract hosts from subfinder output: %w", err)
	}

	originalCount := len(hosts)
	hosts = s.FilterHosts(hosts)
	filteredOut := originalCount - len(hosts)

	fmt.Printf("[+] Scope filter: %d in scope, %d excluded\n", len(hosts), filteredOut)

	if len(hosts) == 0 {
		return fmt.Errorf("no subdomains remaining after scope filtering")
	}

	// Write filtered hosts for httpx
	if err := os.WriteFile(hostsFile, []byte(strings.Join(hosts, "\n")+"\n"), 0644); err != nil {
		return fmt.Errorf("could not write hosts file: %w", err)
	}

	// ──────────────────────────────────────────────
	// Step 3: Httpx — probe active subdomains
	// ──────────────────────────────────────────────
	fmt.Println("[*] Step 3/3: Running httpx to find active subdomains...")

	hxOptions := &httpx_runner.Options{
		InputFile:          hostsFile,
		JSONOutput:         true,
		Output:             activeFile,
		Silent:             true,
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

	fmt.Printf("[+] Active subdomains saved to: %s\n", activeFile)
	fmt.Println("[✓] Workflow 'active' completed successfully.")
	return nil
}

// extractHostsFromSubfinderJSON reads subfinder JSONL output and extracts host fields.
func extractHostsFromSubfinderJSON(jsonlFile string) ([]string, error) {
	data, err := os.ReadFile(jsonlFile)
	if err != nil {
		return nil, err
	}

	var hosts []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		host := extractJSONField(line, "host")
		if host != "" {
			hosts = append(hosts, host)
		}
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("no hosts found in subfinder output")
	}

	return hosts, nil
}

// extractJSONField extracts a string value for a given key from a JSON line.
func extractJSONField(jsonLine, key string) string {
	search := fmt.Sprintf(`"%s":"`, key)
	idx := strings.Index(jsonLine, search)
	if idx == -1 {
		search = fmt.Sprintf(`"%s": "`, key)
		idx = strings.Index(jsonLine, search)
		if idx == -1 {
			return ""
		}
	}
	start := idx + len(search)
	end := strings.Index(jsonLine[start:], `"`)
	if end == -1 {
		return ""
	}
	return jsonLine[start : start+end]
}
