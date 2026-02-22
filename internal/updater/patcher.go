package updater

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PatchTrufflehogInit moves the body of func init() into the top of func Main()
// so that kingpin doesn't parse os.Args at import time and hijack narmol's CLI.
// This must run AFTER PatchTool (which already renamed main→Main).
func PatchTrufflehogInit(baseDir, relPath string) {
	filePath := filepath.Join(baseDir, relPath)
	raw, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("[!] PatchTrufflehogInit: failed to read %s: %s\n", filePath, err)
		return
	}
	src := string(raw)

	// Normalize line endings to LF for reliable matching.
	src = strings.ReplaceAll(src, "\r\n", "\n")

	// ── 1. Locate func init() { ──
	initSig := "func init() {"
	initIdx := strings.Index(src, initSig)
	if initIdx == -1 {
		fmt.Println("[+] PatchTrufflehogInit: no func init() found, skipping")
		return
	}

	// Find the matching closing brace using brace counting.
	bodyStart := initIdx + len(initSig) // right after the '{'
	depth := 1
	bodyEnd := -1
	for i := bodyStart; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				bodyEnd = i // the closing '}'
				break
			}
		}
		if bodyEnd != -1 {
			break
		}
	}
	if bodyEnd == -1 {
		fmt.Println("[!] PatchTrufflehogInit: could not find matching brace for init()")
		return
	}

	initBody := src[bodyStart:bodyEnd] // everything between { and }

	// ── 2. Remove the entire func init() { … } block ──
	// Find the start of the line containing "func init()"
	lineStart := initIdx
	for lineStart > 0 && src[lineStart-1] != '\n' {
		lineStart--
	}
	// Remove from lineStart to bodyEnd+1 (inclusive of closing brace + newline if present)
	removeEnd := bodyEnd + 1
	if removeEnd < len(src) && src[removeEnd] == '\n' {
		removeEnd++
	}
	src = src[:lineStart] + src[removeEnd:]

	// ── 3. Insert init body at the start of func Main() { ──
	mainSig := "func Main() {"
	mainIdx := strings.Index(src, mainSig)
	if mainIdx == -1 {
		fmt.Println("[!] PatchTrufflehogInit: no func Main() found")
		return
	}

	insertAt := mainIdx + len(mainSig)
	comment := "\n\t// ── CLI initialization (moved from init to avoid intercepting narmol's args) ──"
	src = src[:insertAt] + comment + initBody + "\n\t// ── End CLI initialization ──\n" + src[insertAt:]

	if err := os.WriteFile(filePath, []byte(src), 0644); err != nil {
		fmt.Printf("[!] PatchTrufflehogInit: failed to write %s: %s\n", filePath, err)
		return
	}
	fmt.Println("[+] Patched trufflehog: moved init() body into Main()")
}

// RemoveTestFiles removes all *_test.go files and testdata/ directories
// from the given directory tree. This prevents GitHub Push Protection from
// blocking pushes when test files contain sample secrets.
func RemoveTestFiles(dir string) {
	var removed int
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() && info.Name() == "testdata" {
			os.RemoveAll(path)
			removed++
			return filepath.SkipDir
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), "_test.go") {
			os.Remove(path)
			removed++
		}
		return nil
	})
	if removed > 0 {
		fmt.Printf("[+] Removed %d test files/dirs from %s\n", removed, filepath.Base(dir))
	}
}

// PatchGauCommoncrawl makes gau's Runner.Init() resilient to commoncrawl
// failures. Instead of aborting all providers when commoncrawl is unreachable,
// it logs a warning and continues with the remaining providers.
func PatchGauCommoncrawl(baseDir string) {
	relPath := filepath.Join("runner", "runner.go")
	filePath := filepath.Join(baseDir, relPath)
	raw, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("[!] PatchGauCommoncrawl: file not found: %s\n", filePath)
		return
	}
	src := string(raw)
	src = strings.ReplaceAll(src, "\r\n", "\n")

	// Replace: return fmt.Errorf("error instantiating commoncrawl: ...") → logrus.Warnf + continue
	old := `return fmt.Errorf("error instantiating commoncrawl: %v\n", err)`
	neu := `logrus.Warnf("commoncrawl unavailable, skipping: %v", err)` + "\n\t\t\t\tcontinue"

	if !strings.Contains(src, old) {
		fmt.Println("[+] PatchGauCommoncrawl: already patched, skipping")
		return
	}

	src = strings.Replace(src, old, neu, 1)

	// Remove unused "fmt" import if it becomes the only user
	src = strings.Replace(src, "\t\"fmt\"\n", "", 1)

	if err := os.WriteFile(filePath, []byte(src), 0644); err != nil {
		fmt.Printf("[!] PatchGauCommoncrawl: %s\n", err)
		return
	}
	fmt.Println("[+] Patched gau: commoncrawl failure is now non-fatal")
}

// PatchNucleiGitlab fixes type mismatches in nuclei's gitlab tracker caused
// by a newer go-gitlab dependency (int → int64) pulled in by trufflehog.
func PatchNucleiGitlab(baseDir string) {
	relPath := filepath.Join("pkg", "reporting", "trackers", "gitlab", "gitlab.go")
	filePath := filepath.Join(baseDir, relPath)
	raw, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("[!] PatchNucleiGitlab: file not found: %s\n", filePath)
		return
	}
	src := string(raw)

	// Normalize line endings to LF for reliable matching.
	src = strings.ReplaceAll(src, "\r\n", "\n")

	replacements := [][2]string{
		{"userID  int\n", "userID  int64\n"},
		{"assigneeIDs := []int{i.userID}", "assigneeIDs := []int64{i.userID}"},
		{"Page:    page,", "Page:    int64(page),"},
		{"PerPage: pageSize,", "PerPage: int64(pageSize),"},
	}

	changed := false
	for _, r := range replacements {
		if strings.Contains(src, r[0]) {
			src = strings.Replace(src, r[0], r[1], 1)
			changed = true
		}
	}

	if changed {
		if err := os.WriteFile(filePath, []byte(src), 0644); err != nil {
			fmt.Printf("[!] PatchNucleiGitlab: %s\n", err)
			return
		}
		fmt.Println("[+] Patched nuclei gitlab.go (int → int64)")
	}
}

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

// PatchFile rewrites a companion file's package declaration only:
//   - "package main" → "package <pkgName>"
func PatchFile(baseDir, pkgName, relPath string) {
	filePath := filepath.Join(baseDir, relPath)
	content, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("[!] Failed to read %s: %s\n", filePath, err)
		return
	}

	patched := strings.Replace(string(content), "package main", "package "+pkgName, 1)

	if err := os.WriteFile(filePath, []byte(patched), 0644); err != nil {
		fmt.Printf("[!] Failed to patch %s: %s\n", filePath, err)
		return
	}
	fmt.Printf("[+] Patched file %s\n", relPath)
}
