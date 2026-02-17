package active

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"narmol/scope"
	"narmol/workflows"

	httpx_runner "github.com/projectdiscovery/httpx/runner"
)

func createTempScopeFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunRejectsDomainNotInScope(t *testing.T) {
	path := createTempScopeFile(t, "*.example.com\n!out.example.com")
	s, err := scope.Load(path)
	if err != nil {
		t.Fatalf("scope.Load: %v", err)
	}
	w := &ActiveWorkflow{}
	err = w.Run("notinscope.com", s, workflows.OutputOptions{})
	if err == nil || !strings.Contains(err.Error(), "not in scope") {
		t.Errorf("expected 'not in scope' error, got: %v", err)
	}
}

func TestRunRejectsDomainWithoutWildcard(t *testing.T) {
	path := createTempScopeFile(t, "example.com")
	s, err := scope.Load(path)
	if err != nil {
		t.Fatalf("scope.Load: %v", err)
	}
	w := &ActiveWorkflow{}
	err = w.Run("example.com", s, workflows.OutputOptions{})
	if err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Errorf("expected 'wildcard' error, got: %v", err)
	}
}

func TestCompactFromResultKeepsEssentialFields(t *testing.T) {
	r := httpx_runner.Result{
		URL:          "https://www.hackerone.com",
		Input:        "www.hackerone.com",
		Host:         "www.hackerone.com",
		Port:         "443",
		Scheme:       "https",
		StatusCode:   200,
		Title:        "HackerOne",
		WebServer:    "cloudflare",
		Technologies: []string{"Cloudflare"},
		CDN:          true,
		CDNName:      "cloudflare",
	}

	compact := compactFromResult(r)

	if compact.URL != "https://www.hackerone.com" {
		t.Errorf("URL = %q, want %q", compact.URL, "https://www.hackerone.com")
	}
	if compact.Host != "www.hackerone.com" {
		t.Errorf("Host = %q, want %q", compact.Host, "www.hackerone.com")
	}
	if compact.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", compact.StatusCode)
	}
	if compact.Title != "HackerOne" {
		t.Errorf("Title = %q, want %q", compact.Title, "HackerOne")
	}
	if compact.Webserver != "cloudflare" {
		t.Errorf("Webserver = %q, want %q", compact.Webserver, "cloudflare")
	}
	if len(compact.Tech) != 1 || compact.Tech[0] != "Cloudflare" {
		t.Errorf("Tech = %v, want [Cloudflare]", compact.Tech)
	}
	if !compact.CDN {
		t.Error("CDN = false, want true")
	}
	if compact.CDNName != "cloudflare" {
		t.Errorf("CDNName = %q, want %q", compact.CDNName, "cloudflare")
	}

	// Ensure it serialises correctly to JSON (no extra bloat fields)
	js, err := json.Marshal(compact)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]interface{}
	json.Unmarshal(js, &m)

	// These fields should NOT be present in the compact JSON
	for _, absent := range []string{"body", "header", "raw_header", "request", "time", "hash", "words", "lines", "content_length"} {
		if _, ok := m[absent]; ok {
			t.Errorf("compact JSON should not contain field %q", absent)
		}
	}
}

func TestCompactFromResultHandlesMissingFields(t *testing.T) {
	r := httpx_runner.Result{
		URL:        "http://basic.example.com",
		Input:      "basic.example.com",
		Host:       "basic.example.com",
		Scheme:     "http",
		StatusCode: 301,
	}

	compact := compactFromResult(r)

	if compact.URL != "http://basic.example.com" {
		t.Errorf("URL = %q, want %q", compact.URL, "http://basic.example.com")
	}
	if compact.Title != "" {
		t.Errorf("Title = %q, want empty", compact.Title)
	}
	if compact.Port != "" {
		t.Errorf("Port = %q, want empty", compact.Port)
	}
	if len(compact.Tech) != 0 {
		t.Errorf("Tech = %v, want empty", compact.Tech)
	}
}

func TestCompactResultKeepsEssentialFields(t *testing.T) {
	input := `{"url":"https://www.hackerone.com","input":"www.hackerone.com","host":"www.hackerone.com","port":"443","scheme":"https","status_code":200,"title":"HackerOne","webserver":"cloudflare","tech":["Cloudflare"],"cdn":true,"cdn_name":"cloudflare","content_length":12345,"words":500,"lines":100,"body":"<html>big body</html>","header":{"Server":"cloudflare"}}`

	clean, url := compactResult(input)
	if url != "https://www.hackerone.com" {
		t.Errorf("url = %q, want %q", url, "https://www.hackerone.com")
	}

	var m map[string]interface{}
	if err := json.Unmarshal([]byte(clean), &m); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	// These fields should NOT be present
	for _, absent := range []string{"body", "header", "content_length", "words", "lines"} {
		if _, ok := m[absent]; ok {
			t.Errorf("compact JSON should not contain field %q", absent)
		}
	}
}

func TestCompactResultRejectsInvalidJSON(t *testing.T) {
	clean, url := compactResult("not json at all")
	if clean != "" || url != "" {
		t.Errorf("expected empty results for invalid JSON, got clean=%q url=%q", clean, url)
	}
}

func TestWorkflowRegistration(t *testing.T) {
	w, err := workflows.Get("active")
	if err != nil {
		t.Fatalf("Get(active): %v", err)
	}
	if w == nil {
		t.Fatal("active workflow not registered")
	}
	if w.Name() != "active" {
		t.Errorf("Name() = %q, want %q", w.Name(), "active")
	}
	if w.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestActiveWorkflowLiveExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live integration test in short mode")
	}

	path := createTempScopeFile(t, "*.hackerone.com\nhackerone.com")
	s, err := scope.Load(path)
	if err != nil {
		t.Fatalf("ParseScope: %v", err)
	}

	tmpDir := t.TempDir()
	textOut := filepath.Join(tmpDir, "active.txt")
	jsonOut := filepath.Join(tmpDir, "active.json")

	w := &ActiveWorkflow{}
	err = w.Run("hackerone.com", s, workflows.OutputOptions{
		TextFile: textOut,
		JSONFile: jsonOut,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Verify text output
	textData, err := os.ReadFile(textOut)
	if err != nil {
		t.Fatalf("ReadFile text: %v", err)
	}
	if len(textData) == 0 {
		t.Error("text output file is empty — expected active hosts")
	}

	// Verify JSON output
	jsonData, err := os.ReadFile(jsonOut)
	if err != nil {
		t.Fatalf("ReadFile json: %v", err)
	}
	if len(jsonData) == 0 {
		t.Error("JSON output file is empty — expected active hosts")
	}

	// Each JSON line should be valid and have compact fields
	for _, line := range strings.Split(strings.TrimSpace(string(jsonData)), "\n") {
		if line == "" {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("invalid JSON line: %v — %s", err, line)
			continue
		}
		if _, ok := m["url"]; !ok {
			t.Errorf("JSON line missing 'url' field: %s", line)
		}
		// Should NOT have bloated fields
		for _, absent := range []string{"body", "header", "raw_header", "request"} {
			if _, ok := m[absent]; ok {
				t.Errorf("JSON line should not contain field %q: %s", absent, line)
			}
		}
	}
}
