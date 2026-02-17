package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	// Imported tools (refactored to expose Main)
	dnsx_cmd "github.com/projectdiscovery/dnsx/cmd/dnsx"
	httpx_cmd "github.com/projectdiscovery/httpx/cmd/httpx"
	katana_cmd "github.com/projectdiscovery/katana/cmd/katana"
	nuclei_cmd "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
	subfinder_cmd "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
	gau_cmd "github.com/lc/gau/v2/cmd/gau"

	// Workflows
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
	domain := fs.String("d", "", "Target domain")
	outputDir := fs.String("o", "./output", "Output directory")
	fs.Parse(args[1:])

	if *domain == "" {
		fmt.Println("Error: -d (domain) is required")
		fmt.Printf("Usage: narmol workflow %s -d <domain> [-o <output_dir>]\n", name)
		os.Exit(1)
	}

	w, err := workflows.Get(name)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		printWorkflows()
		os.Exit(1)
	}

	fmt.Printf("[*] Running workflow '%s' for domain: %s\n", name, *domain)
	if err := w.Run(*domain, *outputDir); err != nil {
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
	fmt.Println("Usage: narmol workflow <name> -d <domain> [-o <output_dir>]")
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
	fmt.Println("  workflow     Run a predefined workflow")
	fmt.Println()
	fmt.Println("Run 'narmol workflow' to see available workflows.")
}
