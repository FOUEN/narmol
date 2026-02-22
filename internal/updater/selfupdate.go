package updater

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// NarmolRepo is the git URL used to clone the narmol source when running
// as a standalone binary (i.e. installed via go install or downloaded).
const NarmolRepo = "https://github.com/FOUEN/narmol"

// SelfUpdate is the full update cycle:
//  1. Ensure the narmol source tree is available (clone or pull).
//  2. Update and patch all tools inside it.
//  3. Rebuild the binary and replace the running executable.
//
// If already running from the source directory it uses that directly.
// Otherwise it manages a cached clone at ~/.narmol/src/.
func SelfUpdate() {
	srcDir := resolveSourceDir()

	// Step 1 — update tools
	UpdateAll(filepath.Join(srcDir, "tools"))

	// Step 2 — rebuild and replace the binary
	rebuildAndReplace(srcDir)
}

// resolveSourceDir returns the path to a narmol source tree, cloning or
// pulling as needed.
func resolveSourceDir() string {
	// Are we already inside the source repo?
	cwd, _ := os.Getwd()
	if isNarmolSource(cwd) {
		fmt.Println("[*] Running from source directory")
		return cwd
	}

	// Use ~/.narmol/src/ as a cached clone
	cache, err := narmolCacheDir()
	if err != nil {
		fmt.Printf("[!] Cannot determine home directory: %s\n", err)
		os.Exit(1)
	}

	srcDir := filepath.Join(cache, "src")

	if isGitRepo(srcDir) && isNarmolSource(srcDir) {
		fmt.Println("[*] Updating narmol source...")
		if err := gitCmd(srcDir, "fetch", "origin"); err != nil {
			fmt.Printf("[!] git fetch failed: %s\n", err)
		}
		if err := gitCmd(srcDir, "reset", "--hard", "origin/HEAD"); err != nil {
			fmt.Printf("[!] git reset failed: %s\n", err)
		}
	} else {
		fmt.Println("[*] Cloning narmol source...")
		os.MkdirAll(cache, 0755)
		os.RemoveAll(srcDir)
		if err := gitCmd(cache, "clone", NarmolRepo, "src"); err != nil {
			fmt.Printf("[!] Failed to clone narmol repo: %s\n", err)
			os.Exit(1)
		}
	}

	return srcDir
}

// rebuildAndReplace compiles the narmol binary from srcDir and replaces the
// currently running executable.
func rebuildAndReplace(srcDir string) {
	execPath, err := os.Executable()
	if err != nil {
		fmt.Printf("[!] Cannot determine current binary path: %s\n", err)
		return
	}
	execPath, _ = filepath.EvalSymlinks(execPath)

	fmt.Printf("[*] Rebuilding narmol → %s\n", execPath)

	// Build to a temporary path first so a failed build doesn't destroy
	// the current binary.
	tmpBin := execPath + ".new"
	if runtime.GOOS == "windows" && !strings.HasSuffix(tmpBin, ".exe") {
		tmpBin += ".exe"
	}

	build := exec.Command("go", "build", "-o", tmpBin, ".")
	build.Dir = srcDir
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr

	if err := build.Run(); err != nil {
		fmt.Printf("[!] Build failed: %s\n", err)
		os.Remove(tmpBin)
		return
	}

	// Swap: current → .old, new → current
	oldBin := execPath + ".old"
	os.Remove(oldBin) // clean up leftovers from a previous update

	if err := os.Rename(execPath, oldBin); err != nil {
		fmt.Printf("[!] Failed to move old binary: %s\n", err)
		os.Remove(tmpBin)
		return
	}
	if err := os.Rename(tmpBin, execPath); err != nil {
		// Rollback
		os.Rename(oldBin, execPath)
		fmt.Printf("[!] Failed to install new binary: %s\n", err)
		return
	}

	// Best-effort cleanup (may fail on Windows while binary is running — that's fine)
	os.Remove(oldBin)

	fmt.Println("[+] narmol rebuilt and updated successfully!")
}

// narmolCacheDir returns ~/.narmol/ (or %USERPROFILE%\.narmol\ on Windows).
func narmolCacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".narmol"), nil
}

// isNarmolSource returns true if dir contains a go.mod with the narmol module declaration.
func isNarmolSource(dir string) bool {
	data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "module github.com/FOUEN/narmol")
}
