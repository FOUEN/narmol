// Package updater handles fetching, cloning and patching external tools.
package updater

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ToolSource defines the git URL and patch info for an external tool.
type ToolSource struct {
	Name       string
	URL        string
	PkgName    string   // package name after patching (e.g. "httpx")
	MainFile   string   // relative path to main.go inside the tool dir
	ExtraFiles []string // additional files in the same package that need "package main" patched
}

// DefaultTools returns the list of all tools that narmol manages.
func DefaultTools() []ToolSource {
	return []ToolSource{
		{Name: "dnsx", URL: "https://github.com/projectdiscovery/dnsx", PkgName: "dnsx", MainFile: "cmd/dnsx/dnsx.go"},
		{Name: "gau", URL: "https://github.com/lc/gau", PkgName: "gau", MainFile: "cmd/gau/main.go"},
		{Name: "httpx", URL: "https://github.com/projectdiscovery/httpx", PkgName: "httpx", MainFile: "cmd/httpx/httpx.go"},
		{Name: "katana", URL: "https://github.com/projectdiscovery/katana", PkgName: "katana", MainFile: "cmd/katana/main.go"},
		{Name: "naabu", URL: "https://github.com/projectdiscovery/naabu", PkgName: "naabu", MainFile: "cmd/naabu/main.go"},
		{Name: "nuclei", URL: "https://github.com/projectdiscovery/nuclei", PkgName: "nuclei", MainFile: "cmd/nuclei/main.go"},
		{Name: "subfinder", URL: "https://github.com/projectdiscovery/subfinder", PkgName: "subfinder", MainFile: "cmd/subfinder/main.go"},
		{Name: "wappalyzergo", URL: "https://github.com/projectdiscovery/wappalyzergo"},
	}
}

// UpdateAll fetches/clones all tools and applies patches.
func UpdateAll(baseDir string) {
	fmt.Println("--------------------------------------------------")
	for _, tool := range DefaultTools() {
		dir := filepath.Join(baseDir, tool.Name)
		fmt.Printf("[*] Updating %-15s ", tool.Name)

		if err := fetchOrClone(dir, tool.URL); err != nil {
			fmt.Printf("\n[!] Failed to update %s: %s\n", tool.Name, err)
			continue
		}

		// Apply patches if the tool has a main file to patch
		if tool.MainFile != "" {
			PatchTool(dir, tool.PkgName, tool.MainFile)
		}

		// Patch extra files (only package declaration, no func main rename)
		for _, extra := range tool.ExtraFiles {
			PatchFile(dir, tool.PkgName, extra)
		}

		// Nuclei-specific: remove benchmark test that causes package conflicts
		if tool.Name == "nuclei" {
			os.Remove(filepath.Join(dir, "cmd", "nuclei", "main_benchmark_test.go"))
		}
	}
}

const sourceFile = ".narmol-source"

// fetchOrClone either git-pulls an existing repo or clones it fresh.
// It writes a .narmol-source marker file with the origin URL after cloning.
func fetchOrClone(dir, url string) error {
	if isGitRepo(dir) {
		// Fast path: .git exists, just fetch + reset
		if err := gitCmd(dir, "fetch", "origin"); err != nil {
			return fmt.Errorf("fetch failed: %w", err)
		}
		if err := gitCmd(dir, "reset", "--hard", "origin/HEAD"); err != nil {
			return fmt.Errorf("reset failed: %w", err)
		}
		writeSourceFile(dir, url)
		fmt.Println(" [Updated]")
		return nil
	}

	// No .git — need a fresh clone
	savedURL := readSourceFile(dir)
	if savedURL != "" {
		fmt.Printf("\n    - Source: %s — cloning...", savedURL)
		url = savedURL // honour the stored origin
	} else {
		fmt.Printf("\n    - Cloning from %s...", url)
	}

	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove failed: %w", err)
	}
	if err := gitCmd(".", "clone", url, dir); err != nil {
		return fmt.Errorf("clone failed: %w", err)
	}
	writeSourceFile(dir, url)
	fmt.Println(" [Cloned]")
	return nil
}

func isGitRepo(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil && info.IsDir()
}

// writeSourceFile writes the origin URL to .narmol-source inside dir.
func writeSourceFile(dir, url string) {
	_ = os.WriteFile(filepath.Join(dir, sourceFile), []byte(url+"\n"), 0644)
}

// readSourceFile returns the origin URL from .narmol-source, or "" if absent.
func readSourceFile(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, sourceFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func gitCmd(dir string, args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	return cmd.Run()
}
