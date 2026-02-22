package secrets

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/FOUEN/narmol/internal/scope"
	"github.com/FOUEN/narmol/internal/workflows"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func init() {
	workflows.Register(&SecretsWorkflow{})
}

// SecretsWorkflow scans for leaked secrets using TruffleHog.
// Supports scanning:
// - Git repositories (by URL)
// - Filesystem paths
// Uses TruffleHog's 800+ detectors to find API keys, tokens, passwords, etc.
type SecretsWorkflow struct{}

func (w *SecretsWorkflow) Name() string {
	return "secrets"
}

func (w *SecretsWorkflow) Description() string {
	return "Scan for leaked secrets (API keys, tokens, passwords) using TruffleHog. Supports git repos and filesystem paths."
}

func (w *SecretsWorkflow) Run(domain string, s *scope.Scope, opts workflows.OutputOptions) error {
	if !s.IsInScope(domain) {
		return fmt.Errorf("target %s is not in scope", domain)
	}

	var textFile, jsonFile *os.File
	var err error

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

	emit := func(r SecretResult) {
		if textFile == nil && jsonFile == nil {
			fmt.Println(r.OneLiner())
		}
		if textFile != nil {
			fmt.Fprintln(textFile, r.OneLiner())
		}
		if jsonFile != nil {
			if js, err := json.Marshal(r); err == nil {
				fmt.Fprintln(jsonFile, string(js))
			}
		}
	}

	// Determine scan type based on domain value
	scanType := determineScanType(domain)

	var totalFound int64

	switch scanType {
	case "git":
		fmt.Printf("[*] Scanning git repository: %s\n", domain)
		err = scanGit(domain, emit, &totalFound)
	case "filesystem":
		fmt.Printf("[*] Scanning filesystem path: %s\n", domain)
		err = scanFilesystem(domain, emit, &totalFound)
	default:
		// For domain targets, try git scan with common patterns
		fmt.Printf("[*] Scanning target: %s\n", domain)
		err = scanGit(domain, emit, &totalFound)
	}

	if err != nil {
		fmt.Printf("[!] TruffleHog scan error: %s\n", err)
	}

	found := atomic.LoadInt64(&totalFound)
	if opts.JSONFile != "" {
		fmt.Printf("[+] JSON results saved to: %s\n", opts.JSONFile)
	}
	if opts.TextFile != "" {
		fmt.Printf("[+] Text results saved to: %s\n", opts.TextFile)
	}
	fmt.Printf("[+] Secrets scan completed — %d secrets found.\n", found)
	return nil
}

// ScanGitRepo scans a git repository URL for secrets and returns results.
// This is the public API for use by other workflows.
func ScanGitRepo(repoURL string) ([]SecretResult, error) {
	var results []SecretResult
	var mu sync.Mutex
	var count int64

	emit := func(r SecretResult) {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
	}

	err := scanGit(repoURL, emit, &count)
	return results, err
}

// ScanPath scans a filesystem path for secrets and returns results.
// This is the public API for use by other workflows.
func ScanPath(path string) ([]SecretResult, error) {
	var results []SecretResult
	var mu sync.Mutex
	var count int64

	emit := func(r SecretResult) {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
	}

	err := scanFilesystem(path, emit, &count)
	return results, err
}

func scanGit(repoURL string, emit func(SecretResult), count *int64) error {
	ctx := context.Background()

	sourceMgr := sources.NewManager(
		sources.WithConcurrentSources(1),
		sources.WithConcurrentTargets(4),
		sources.WithSourceUnits(),
	)

	eng, err := engine.NewEngine(ctx, &engine.Config{
		Concurrency:   4,
		Verify:        false,
		SourceManager: sourceMgr,
	})
	if err != nil {
		return fmt.Errorf("failed to create trufflehog engine: %w", err)
	}

	eng.Start(ctx)

	_, err = eng.ScanGit(ctx, sources.GitConfig{
		URI:          repoURL,
		MaxDepth:     50,
		SkipBinaries: true,
	})
	if err != nil {
		_ = eng.Finish(ctx)
		return fmt.Errorf("failed to scan git repo: %w", err)
	}

	// Collect results in background
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for result := range eng.ResultsChan() {
			r := resultToSecret(result, "git", repoURL)
			emit(r)
			atomic.AddInt64(count, 1)
		}
	}()

	if err := eng.Finish(ctx); err != nil {
		return fmt.Errorf("engine finish error: %w", err)
	}
	wg.Wait()
	return nil
}

func scanFilesystem(path string, emit func(SecretResult), count *int64) error {
	ctx := context.Background()

	sourceMgr := sources.NewManager(
		sources.WithConcurrentSources(1),
		sources.WithConcurrentTargets(4),
		sources.WithSourceUnits(),
	)

	eng, err := engine.NewEngine(ctx, &engine.Config{
		Concurrency:   4,
		Verify:        false,
		SourceManager: sourceMgr,
	})
	if err != nil {
		return fmt.Errorf("failed to create trufflehog engine: %w", err)
	}

	eng.Start(ctx)

	_, err = eng.ScanFileSystem(ctx, sources.FilesystemConfig{
		Paths: []string{path},
	})
	if err != nil {
		_ = eng.Finish(ctx)
		return fmt.Errorf("failed to scan filesystem: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for result := range eng.ResultsChan() {
			r := resultToSecret(result, "filesystem", path)
			emit(r)
			atomic.AddInt64(count, 1)
		}
	}()

	if err := eng.Finish(ctx); err != nil {
		return fmt.Errorf("engine finish error: %w", err)
	}
	wg.Wait()
	return nil
}

func resultToSecret(r detectors.ResultWithMetadata, source, target string) SecretResult {
	detectorName := r.DetectorType.String()
	if r.DetectorName != "" {
		detectorName = r.DetectorName
	}

	return SecretResult{
		Type:         "secret",
		DetectorType: detectorName,
		Verified:     r.Verified,
		Redacted:     r.Redacted,
		Source:       source,
		Target:       target,
		SourceName:   r.SourceName,
		ExtraData:    r.ExtraData,
	}
}

func determineScanType(target string) string {
	lower := strings.ToLower(target)

	// Git repo patterns
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(lower, "git@") || strings.HasSuffix(lower, ".git") {
		return "git"
	}

	// Filesystem patterns (absolute paths or relative paths with separators)
	if strings.HasPrefix(target, "/") || strings.HasPrefix(target, "./") ||
		strings.HasPrefix(target, "~") || strings.Contains(target, "\\") ||
		(len(target) >= 2 && target[1] == ':') {
		return "filesystem"
	}

	return "auto"
}

// SecretResult represents a secret finding from TruffleHog.
type SecretResult struct {
	Type         string            `json:"type"`
	DetectorType string            `json:"detector_type"`
	Verified     bool              `json:"verified"`
	Redacted     string            `json:"redacted"`
	Source       string            `json:"source"`
	Target       string            `json:"target"`
	SourceName   string            `json:"source_name"`
	ExtraData    map[string]string `json:"extra_data,omitempty"`
}

func (r SecretResult) OneLiner() string {
	verified := ""
	if r.Verified {
		verified = " [VERIFIED]"
	}
	return fmt.Sprintf("[%s]%s %s (source: %s)", r.DetectorType, verified, r.Redacted, r.Source)
}
