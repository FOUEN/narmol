// Package cli implements the narmol command-line interface.
// It routes subcommands to the appropriate handler.
package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/FOUEN/narmol/internal/runner"
)

// Run is the main entry point for the CLI. It parses os.Args and dispatches.
func Run() {
	if len(os.Args) < 2 {
		PrintUsage()
		return
	}

	command := os.Args[1]

	switch command {
	case "workflow":
		RunWorkflow(os.Args[2:])
	case "update":
		RunUpdate()
	default:
		RunTool(command)
	}
}

// RunTool dispatches a passthrough call to an external tool.
func RunTool(name string) {
	// Shift args so the tool sees itself as argv[0]
	os.Args = append([]string{name}, os.Args[2:]...)

	// Strip leading dash (e.g. "-nuclei" → "nuclei")
	tool := strings.TrimPrefix(name, "-")

	t, err := runner.Get(tool)
	if err != nil {
		fmt.Printf("Unknown command: %s\n", name)
		PrintUsage()
		os.Exit(1)
	}

	t.Main()
}
