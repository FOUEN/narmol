package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	// Imported tools (refactored to expose Main)
	dnsx_cmd "github.com/projectdiscovery/dnsx/cmd/dnsx"
	gau_cmd "github.com/lc/gau/v2/cmd/gau"
	httpx_cmd "github.com/projectdiscovery/httpx/cmd/httpx"
	katana_cmd "github.com/projectdiscovery/katana/cmd/katana"
	nuclei_cmd "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
	subfinder_cmd "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"

	// Scope & Workflows
	"narmol/scope"
	"narmol/workflows"
	_ "narmol/workflows/active" // auto-register active workflow
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	toolName := os.Args[1]

	// Handle "workflow" subcommand
	if toolName == "workflow" {
		runWorkflow(os.Args[2:])
		return
	}

	// Shift args: [narmol, tool, arg1, arg2...] -> [tool, arg1, arg2...]
	subArgs := append([]string{toolName}, os.Args[2:]...)
	os.Args = subArgs

	// Handle flags like "-nuclei" or "nuclei"
	tool := strings.TrimPrefix(toolName, "-")

	switch tool {
	case "nuclei":
		nuclei_cmd.Main()
	case "httpx":
		httpx_cmd.Main()
	case "katana":
		katana_cmd.Main()
	case "dnsx":
		dnsx_cmd.Main()
	case "subfinder":
		subfinder_cmd.Main()
	case "gau":
		gau_cmd.Main()
	default:
		fmt.Printf("Unknown tool: %s\n", toolName)
		printUsage()
	}
}

func runWorkflow(args []string) {
	if len(args) == 0 {
		printWorkflows()
		return
	}

	name := args[0]

	// Parse workflow flags
	fs := flag.NewFlagSet("workflow", flag.ExitOnError)
	var scopeFile string
	fs.StringVar(&scopeFile, "scope", "", "Scope file (required) — defines allowed targets")
	fs.StringVar(&scopeFile, "s", "", "Scope file (required) — shorthand for --scope")
	outputDir := fs.String("o", "./output", "Output directory")
	fs.Parse(args[1:])

	// Validate required flags
	if scopeFile == "" {
		fmt.Println("Error: --scope / -s is required. You must define a scope file.")
		fmt.Println()
		fmt.Println("Example scope.txt:")
		fmt.Println("  *.example.com          # all subdomains")
		fmt.Println("  -admin.example.com     # exclude admin")
		fmt.Println()
		fmt.Printf("Usage: narmol workflow %s --scope <scope.txt> [-o <output_dir>]\n", name)
		os.Exit(1)
	}

	// Load scope
	s, err := scope.LoadFromFile(scopeFile)
	if err != nil {
		fmt.Printf("[!] Scope error: %s\n", err)
		os.Exit(1)
	}

	fmt.Println(s.String())
	fmt.Printf("[*] Target domains: %s\n", strings.Join(s.Domains(), ", "))

	// Get workflow
	w, err := workflows.Get(name)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		printWorkflows()
		os.Exit(1)
	}

	fmt.Printf("[*] Running workflow '%s'\n", name)
	if err := w.Run(*outputDir, s); err != nil {
		fmt.Printf("[!] Workflow failed: %s\n", err)
		os.Exit(1)
	}
}

func printWorkflows() {
	fmt.Println("Available workflows:")
	for _, w := range workflows.List() {
		fmt.Printf("  - %-12s %s\n", w.Name(), w.Description())
	}
	fmt.Println()
	fmt.Println("Usage: narmol workflow <name> --scope <scope.txt> [-o <output_dir>]")
}

func printUsage() {
	fmt.Println("Narmol Wrapper")
	fmt.Println("Usage: narmol <command> [args...]")
	fmt.Println()
	fmt.Println("Tools:")
	fmt.Println("  nuclei       Run nuclei scanner")
	fmt.Println("  httpx        Run httpx prober")
	fmt.Println("  katana       Run katana crawler")
	fmt.Println("  dnsx         Run dnsx resolver")
	fmt.Println("  subfinder    Run subfinder enumerator")
	fmt.Println("  gau          Run gau URL fetcher")
	fmt.Println()
	fmt.Println("Workflows:")
	fmt.Println("  workflow     Run a predefined workflow (requires --scope)")
	fmt.Println()
	fmt.Println("Run 'narmol workflow' to see available workflows.")
}
