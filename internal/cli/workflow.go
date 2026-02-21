package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/FOUEN/narmol/internal/scope"
	"github.com/FOUEN/narmol/internal/workflows"
)

// RunWorkflow handles the "narmol workflow <name> [flags]" subcommand.
func RunWorkflow(args []string) {
	if len(args) == 0 {
		printWorkflows()
		return
	}

	name := args[0]
	opts := parseWorkflowFlags(name, args[1:])

	// Load scope
	s, err := scope.Load(opts.scopeFile)
	if err != nil {
		fmt.Printf("[!] Scope error: %s\n", err)
		os.Exit(1)
	}

	fmt.Print(s.String())
	domains := s.Domains()
	fmt.Printf("[*] Target domains: %s\n", strings.Join(domains, ", "))

	// Get workflow
	w, err := workflows.Get(name)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		printWorkflows()
		os.Exit(1)
	}

	fmt.Printf("[*] Running workflow '%s'\n", name)

	out := workflows.OutputOptions{
		TextFile: opts.textFile,
		JSONFile: opts.jsonFile,
	}

	for _, domain := range domains {
		fmt.Printf("\n[+] Processing domain: %s\n", domain)
		if err := w.Run(domain, s, out); err != nil {
			fmt.Printf("[!] Workflow failed for %s: %s\n", domain, err)
		}
	}
}

// workflowFlags holds the parsed flags for a workflow invocation.
type workflowFlags struct {
	scopeFile string
	textFile  string
	jsonFile  string
}

// parseWorkflowFlags does manual arg parsing to support optional values for -o and -oj.
func parseWorkflowFlags(workflowName string, args []string) workflowFlags {
	var f workflowFlags

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--scope" || arg == "-scope" || arg == "-s":
			if i+1 < len(args) {
				f.scopeFile = args[i+1]
				i++
			}
		case arg == "-o":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				f.textFile = args[i+1]
				i++
			} else {
				f.textFile = workflowName + ".txt"
			}
		case arg == "-oj":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				f.jsonFile = args[i+1]
				i++
			} else {
				f.jsonFile = workflowName + ".json"
			}
		}
	}

	if f.scopeFile == "" {
		fmt.Println("Error: --scope / -s is required. You must define a scope file.")
		fmt.Println()
		fmt.Println("Example scope.txt:")
		fmt.Println("  *.example.com          # all subdomains")
		fmt.Println("  -admin.example.com     # exclude admin")
		fmt.Println()
		fmt.Printf("Usage: narmol workflow %s --scope <scope.txt> [-o [file]] [-oj [file]]\n", workflowName)
		os.Exit(1)
	}

	return f
}

func printWorkflows() {
	fmt.Println("Available workflows:")
	for _, w := range workflows.List() {
		fmt.Printf("  - %-12s %s\n", w.Name(), w.Description())
	}
	fmt.Println()
	fmt.Println("Usage: narmol workflow <name> --scope <scope.txt> [-o [file]] [-oj [file]]")
}
