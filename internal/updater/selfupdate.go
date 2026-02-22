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

// rebuildAndReplace compiles the narmol binary from srcDir and installs it.
// If invoked via "go run" (executable in a temp dir), it installs to $GOBIN
// or $GOPATH/bin. Otherwise it replaces the current binary in-place.
func rebuildAndReplace(srcDir string) {
	installPath := resolveInstallPath()

	fmt.Printf("[*] Rebuilding narmol → %s\n", installPath)

	// Build to a temporary path first so a failed build doesn't destroy
	// the current binary.
	tmpBin := installPath + ".new"
	if runtime.GOOS == "windows" && !strings.HasSuffix(tmpBin, ".exe") {
		tmpBin += ".exe"
	}

	build := exec.Command("go", "build", "-o", tmpBin, ".")
	build.Dir = srcDir
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr

	if err := build.Run(); err != nil {
		fmt.Printf("[!] Build failed: %s\n", err)
		os.Remove(tmpBin)
		return
	}

	// Swap: current → .old, new → current
	oldBin := installPath + ".old"
	os.Remove(oldBin)

	// The old binary may not exist yet (first install via go run)
	if _, err := os.Stat(installPath); err == nil {
		if err := os.Rename(installPath, oldBin); err != nil {
			fmt.Printf("[!] Failed to move old binary: %s\n", err)
			os.Remove(tmpBin)
			return
		}
	}
	if err := os.Rename(tmpBin, installPath); err != nil {
		os.Rename(oldBin, installPath) // rollback
		fmt.Printf("[!] Failed to install new binary: %s\n", err)
		return
	}

	os.Remove(oldBin)

	fmt.Printf("[+] narmol installed to %s\n", installPath)
	fmt.Println("[+] Make sure this directory is in your PATH.")
}

// resolveInstallPath determines where to place the compiled binary.
// If the current executable is a real installed binary (not from go run),
// replace it in-place. Otherwise install to $GOBIN / $GOPATH/bin / ~/go/bin.
func resolveInstallPath() string {
	execPath, err := os.Executable()
	if err == nil {
		execPath, _ = filepath.EvalSymlinks(execPath)
		// If the binary is NOT in a temp directory, replace it in-place
		if !isTempPath(execPath) {
			return execPath
		}
	}

	// Running via "go run" — find the right install directory
	binName := "narmol"
	if runtime.GOOS == "windows" {
		binName = "narmol.exe"
	}

	// 1. $GOBIN
	if gobin := os.Getenv("GOBIN"); gobin != "" {
		os.MkdirAll(gobin, 0755)
		return filepath.Join(gobin, binName)
	}

	// 2. $GOPATH/bin
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		bin := filepath.Join(gopath, "bin")
		os.MkdirAll(bin, 0755)
		return filepath.Join(bin, binName)
	}

	// 3. ~/go/bin (default GOPATH)
	home, _ := os.UserHomeDir()
	bin := filepath.Join(home, "go", "bin")
	os.MkdirAll(bin, 0755)
	return filepath.Join(bin, binName)
}

// isTempPath returns true if the path looks like it's inside a temp directory
// (i.e. the binary was launched via "go run").
func isTempPath(p string) bool {
	p = filepath.ToSlash(strings.ToLower(p))
	return strings.Contains(p, "/tmp/") ||
		strings.Contains(p, "/temp/") ||
		strings.Contains(p, "\\temp\\") ||
		strings.Contains(p, "/go-build") ||
		strings.Contains(p, "appdata/local/temp")
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
