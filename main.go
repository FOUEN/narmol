package main

import (
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
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	toolName := os.Args[1]
	// Remove the first argument (narmol) and the tool name from args for the sub-tool
	// But tools usually expect os.Args[0] to be the program name.
	// We will construct a synthetic os.Args.
	
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
	case "scan":
		runScanWorkflow(os.Args)
	default:
		// Reset args to print usage correctly (though we printed generic usage above)
		fmt.Printf("Unknown tool: %s\n", toolName)
		printUsage()
	}
}

func runScanWorkflow(args []string) {
	fmt.Println("Scan workflow not yet implemented. Use specific tools for now.")
	// Placeholder for future workflow logic
}

func printUsage() {
	fmt.Println("Narmol Wrapper")
	fmt.Println("Usage: narmol <tool> [args...]")
	fmt.Println("Tools:")
	fmt.Println("  - nuclei")
	fmt.Println("  - httpx")
	fmt.Println("  - katana")
	fmt.Println("  - dnsx")
	fmt.Println("  - subfinder")
	fmt.Println("  - gau")
	fmt.Println("  - scan (workflow)")
}
