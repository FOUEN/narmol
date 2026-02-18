package updater

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PatchTool rewrites a tool's main.go so it can be imported as a library:
//   - "package main" → "package <pkgName>"
//   - "func main()"  → "func Main()"
func PatchTool(baseDir, pkgName, relPath string) {
	fmt.Printf("[*] Patching %s to expose Main()...\n", pkgName)

	mainFile := filepath.Join(baseDir, relPath)
	content, err := os.ReadFile(mainFile)
	if err != nil {
		fmt.Printf("[!] Failed to read %s: %s\n", mainFile, err)
		return
	}

	patched := strings.Replace(string(content), "package main", "package "+pkgName, 1)
	patched = strings.Replace(patched, "func main()", "func Main()", 1)

	if err := os.WriteFile(mainFile, []byte(patched), 0644); err != nil {
		fmt.Printf("[!] Failed to patch %s: %s\n", mainFile, err)
		return
	}
	fmt.Printf("[+] Patched %s\n", pkgName)
}
