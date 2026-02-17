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

func (w *ActiveWorkflow) Run(domain string, s *scope.Scope, opts workflows.OutputOptions) error {
	// Verify scope before doing anything else
	if !s.IsInScope(domain) {
		return fmt.Errorf("domain %s is not in scope", domain)
	}

	// Verify wildcard scope for subdomain enumeration
	if !s.HasWildcard(domain) {
		return fmt.Errorf("active workflow requires a wildcard scope (*.%s) to invoke subdomain enumeration", domain)
	}

	// Create a temporary directory for intermediate results
	tmpDir, err := os.MkdirTemp("", "narmol-active-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	subdomainsFile := filepath.Join(tmpDir, "subdomains.json")
	hostsFile := filepath.Join(tmpDir, "hosts.txt")
	activeFile := filepath.Join(tmpDir, "active.json")

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
	fmt.Printf("[+] Subdomains saved to temp: %s\n", subdomainsFile)

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
		// Method:			 "GET", // Default is GET
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

	// ──────────────────────────────────────────────
	// Step 4: Process Output
	// ──────────────────────────────────────────────
	fmt.Println("[*] Processing results...")

	// Read active.json results
	activeData, err := os.ReadFile(activeFile)
	if err != nil {
		return fmt.Errorf("failed to read active results: %w", err)
	}

	// Parse JSON lines to extract URLs for text output if needed
	var activeURLs []string
	lines := strings.Split(string(activeData), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		url := extractJSONField(line, "url")
		if url != "" {
			activeURLs = append(activeURLs, url)
		}
	}

	// Output logic based on options
	// 1. JSON File Output
	if opts.JSONFile != "" {
		f, err := os.OpenFile(opts.JSONFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open JSON output file %s: %w", opts.JSONFile, err)
		}
		defer f.Close()

		if _, err := f.Write(activeData); err != nil {
			return fmt.Errorf("failed to write JSON output to %s: %w", opts.JSONFile, err)
		}
		// Add newline if needed between appends? JSON lines usually need newlines. activeData often has trailing newline.
		// If not, we might want to ensure it.
		// Assuming activeData from httpx JSON output has newlines.
		fmt.Printf("[+] JSON results appended to: %s\n", opts.JSONFile)
	}

	// 2. Text File Output
	if opts.TextFile != "" {
		content := strings.Join(activeURLs, "\n")
		if len(activeURLs) > 0 {
			content += "\n"
		}

		f, err := os.OpenFile(opts.TextFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open text output file %s: %w", opts.TextFile, err)
		}
		defer f.Close()

		if _, err := f.WriteString(content); err != nil {
			return fmt.Errorf("failed to write text output to %s: %w", opts.TextFile, err)
		}
		fmt.Printf("[+] Text results appended to: %s\n", opts.TextFile)
	}

	// 3. Stdout Output (Default if no files specified, OR maybe always? User said "default normal text... if -o specified then that file". Usually exclusive or implies stdout if NO file)
	// User said: "por default sean en texto normal sino se pone nada" (default text normal if nothing put)
	// "si se pone -o se pone en ese archivo" (if -o put, put in that file)
	// This implies: if NO output options, output to stdout.
	if opts.TextFile == "" && opts.JSONFile == "" {
		for _, url := range activeURLs {
			fmt.Println(url)
		}
	}

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
