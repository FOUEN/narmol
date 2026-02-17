package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	// Imported tools (refactored to expose Main)
	gau_cmd "github.com/lc/gau/v2/cmd/gau"
	dnsx_cmd "github.com/projectdiscovery/dnsx/cmd/dnsx"
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

	// Handle "update" subcommand
	if toolName == "update" {
		updateTools()
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
	// We need custom parsing to support optional values for -o and -oj which standard flag pkg doesn't do well.
	// But goflags (projectdiscovery) supports similar things. Let's stick to standard flags but use string flags.
	// User said: "-o specified then that specific file... if no name specified put the name of the workflow".
	// Implementation: We use goflags for better CLI experience if possible, or just standard strings.
	// Let's use standard flag but maybe assume if value is NEXT arg it is value, else default.
	// Actually, standard flag package consumes the next arg if it's not a flag.
	// So `narmol workflow active -o` -> error/missing value.
	// To support optional value with standard flags is hard.
	// Let's use a workaround:
	// We will manually check args for "-o" and "-oj" to see if they are present,
	// and if the next arg looks like a file (not starting with -), we use it.

	var scopeFile string
	var outputText string
	var outputJson string

	// Simple manual parsing to support the requested behavior
	// Args start after "workflow" command: [active, --scope, ...]
	workflowArgs := args[1:]
	for i := 0; i < len(workflowArgs); i++ {
		arg := workflowArgs[i]
		switch {
		case arg == "--scope" || arg == "-scope" || arg == "-s":
			if i+1 < len(workflowArgs) {
				scopeFile = workflowArgs[i+1]
				i++
			}
		case arg == "-o":
			// Check if next arg is value or flag
			if i+1 < len(workflowArgs) && !strings.HasPrefix(workflowArgs[i+1], "-") {
				outputText = workflowArgs[i+1]
				i++
			} else {
				// No value provided, use default name
				outputText = name + ".txt"
			}
		case arg == "-oj":
			// Check if next arg is value or flag
			if i+1 < len(workflowArgs) && !strings.HasPrefix(workflowArgs[i+1], "-") {
				outputJson = workflowArgs[i+1]
				i++
			} else {
				// No value provided, use default name
				outputJson = name + ".json"
			}
		}
	}

	// Validate required flags
	if scopeFile == "" {
		fmt.Println("Error: --scope / -s is required. You must define a scope file.")
		fmt.Println()
		fmt.Println("Example scope.txt:")
		fmt.Println("  *.example.com          # all subdomains")
		fmt.Println("  -admin.example.com     # exclude admin")
		fmt.Println()
		fmt.Printf("Usage: narmol workflow %s --scope <scope.txt> [-o [file]] [-oj [file]]\n", name)
		os.Exit(1)
	}

	// Load scope
	s, err := scope.Load(scopeFile)
	if err != nil {
		fmt.Printf("[!] Scope error: %s\n", err)
		os.Exit(1)
	}

	filter := s.String()
	fmt.Println(filter)
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

	opts := workflows.OutputOptions{
		TextFile: outputText,
		JSONFile: outputJson,
	}

	// If iterating multiple domains, we might have an issue with single output file.
	// User said "if -o ... put in that specific file".
	// If multiple domains, writing to ONE file might overwrite or mix.
	// But `ActiveWorkflow.Run` is called per domain.
	// If we have multiple domains, we probably should Append? Or use domain directory?
	// User: "if not specified name put the name of the workflow".
	// If the user specifies a SINGLE file `-o final.txt`, but we have 10 domains.
	// The current logic calls Run 10 times.
	// We need to handle this.
	// Option A: Pass the file path to Run, and Run (ActiveWorkflow) handles overwriting/appending.
	// Option B: Update Run signature to handle all domains? No, interface is per domain (currently).
	// Actually, my interface change `Run(domain, s, opts)` implies per domain.
	// If I pass "output.txt" to 10 calls, they will likely overwrite each other unless I append.
	// The ActiveWorkflow implementation: `os.WriteFile` truncates.
	// I should probably change `ActiveWorkflow` to Append if file exists, OR
	// Change the loop in main.go to NOT call Run multiple times?
	// NO, `Run` does "Subfinder -> Httpx". This is per-domain logic.
	// If I want a single output file for ALL domains, I need to collect results or Append.
	// Given the tool structure, let's assume `Run` should append if file exists or I should modify the filename per domain if it's default?
	// User said: "sino se especifica nombre ponle el nombre del workflow".
	// If I have example.com and test.com.
	// Default behavior: Stdout. (Good)
	// -o behavior: `workflow.txt`.
	// If I run for example.com => writes workflow.txt.
	// Then test.com => writes workflow.txt (overwrites).
	// Bad.
	// I should probably Append to the file.
	// But `ActiveWorkflow` logic I just wrote uses `os.WriteFile`.
	// I will update `ActiveWorkflow` to open with `os.O_APPEND|os.O_CREATE|os.O_WRONLY` if I can.
	// BUT, `ActiveWorkflow` does a fresh scan.
	// Let's modify `main.go` to handle this?
	// Maybe: if multiple domains, iterate and run.
	// But `ActiveWorkflow` implementation of `WriteFile` needs to be `Append`.
	// I'll update `ActiveWorkflow` implementation in next step to support Append.

	// For now, let's just pass the opts to Run.

	for _, domain := range domains {
		fmt.Printf("\n[+] Processing domain: %s\n", domain)
		// We don't need domainDir anymore as output is controlled by opts
		if err := w.Run(domain, s, opts); err != nil {
			fmt.Printf("[!] Workflow failed for %s: %s\n", domain, err)
		}
	}
}

func updateTools() {
	tools := map[string]string{
		"dnsx":         "https://github.com/projectdiscovery/dnsx",
		"gau":          "https://github.com/lc/gau",
		"httpx":        "https://github.com/projectdiscovery/httpx",
		"katana":       "https://github.com/projectdiscovery/katana",
		"nuclei":       "https://github.com/projectdiscovery/nuclei",
		"subfinder":    "https://github.com/projectdiscovery/subfinder",
		"wappalyzergo": "https://github.com/projectdiscovery/wappalyzergo",
	}

	baseDir := "tools"
	fmt.Println("--------------------------------------------------")
	for name, url := range tools {
		dir := filepath.Join(baseDir, name)
		fmt.Printf("[*] Updating %-15s ", name)

		if isGitRepo(dir) {
			// Git fetch and reset hard
			if err := runGitCommand(dir, "fetch", "origin"); err != nil {
				fmt.Printf("\n[!] Failed to fetch %s: %s\n", name, err)
				continue
			}
			if err := runGitCommand(dir, "reset", "--hard", "origin/HEAD"); err != nil {
				fmt.Printf("\n[!] Failed to reset %s: %s\n", name, err)
				continue
			}
			fmt.Println(" [Done]")
		} else {
			// Re-clone
			fmt.Print("\n    - Not a git repo. Re-cloning...")
			if err := os.RemoveAll(dir); err != nil {
				fmt.Printf("\n[!] Failed to remove %s: %s\n", dir, err)
				continue
			}
			if err := runGitCommand(".", "clone", url, dir); err != nil {
				fmt.Printf("\n[!] Failed to clone %s: %s\n", name, err)
				continue
			}
			fmt.Println(" [Cloned]")
		}

		// Patch all tools to expose Main()
		switch name {
		case "gau":
			patchTool(dir, "gau", "cmd/gau/main.go")
		case "dnsx":
			patchTool(dir, "dnsx", "cmd/dnsx/dnsx.go")
		case "httpx":
			patchTool(dir, "httpx", "cmd/httpx/httpx.go")
		case "katana":
			patchTool(dir, "katana", "cmd/katana/main.go")
		case "nuclei":
			patchTool(dir, "nuclei", "cmd/nuclei/main.go")
			// Remove benchmark test file that causes package conflict
			os.Remove(filepath.Join(dir, "cmd", "nuclei", "main_benchmark_test.go"))
		case "subfinder":
			patchTool(dir, "subfinder", "cmd/subfinder/main.go")
		}
	}
}

func patchTool(baseDir, pkgName, relPath string) {
	fmt.Printf("[*] Patching %s to expose Main()...\n", pkgName)
	mainFile := filepath.Join(baseDir, relPath)
	content, err := os.ReadFile(mainFile)
	if err != nil {
		fmt.Printf("[!] Failed to read %s: %s\n", mainFile, err)
		return
	}

	newContent := strings.Replace(string(content), "package main", "package "+pkgName, 1)
	newContent = strings.Replace(newContent, "func main()", "func Main()", 1)

	if err := os.WriteFile(mainFile, []byte(newContent), 0644); err != nil {
		fmt.Printf("[!] Failed to patch %s: %s\n", mainFile, err)
		return
	}
	fmt.Printf("[+] Patched %s\n", pkgName)
}

func isGitRepo(dir string) bool {
	gitDir := filepath.Join(dir, ".git")
	info, err := os.Stat(gitDir)
	return err == nil && info.IsDir()
}

func runGitCommand(dir string, args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
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
	fmt.Println("Commands:")
	fmt.Println("  update       Update all tools to latest version (resets local changes)")
	fmt.Println("  workflow     Run a predefined workflow (requires --scope)")
	fmt.Println()
	fmt.Println("Run 'narmol workflow' to see available workflows.")
}
