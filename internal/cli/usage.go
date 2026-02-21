package cli

import (
	"fmt"

	"github.com/FOUEN/narmol/internal/runner"
)

// PrintUsage prints the top-level help message.
func PrintUsage() {
	fmt.Println("Narmol — unified security toolkit")
	fmt.Println()
	fmt.Println("Usage: narmol <command> [args...]")
	fmt.Println()

	fmt.Println("Tools:")
	for _, t := range runner.List() {
		fmt.Printf("  %-12s %s\n", t.Name, t.Description)
	}
	fmt.Println()

	fmt.Println("Commands:")
	fmt.Println("  workflow     Run a predefined workflow (requires --scope)")
	fmt.Println("  update       Update all tools to latest version")
	fmt.Println()
	fmt.Println("Run 'narmol workflow' to see available workflows.")
}
