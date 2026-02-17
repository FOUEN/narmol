package scope

import (
	"os"
	"path/filepath"
	"testing"
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

func TestWildcardInclusion(t *testing.T) {
	path := createTempScopeFile(t, "*.example.com\n")
	s, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		target string
		want   bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"deep.sub.example.com", true},
		{"notexample.com", false},
		{"example.com.evil.com", false},
		{"other.com", false},
	}

	for _, tt := range tests {
		if got := s.IsInScope(tt.target); got != tt.want {
			t.Errorf("IsInScope(%q) = %v, want %v", tt.target, got, tt.want)
		}
	}
}

func TestExactInclusion(t *testing.T) {
	path := createTempScopeFile(t, "api.example.com\n")
	s, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		target string
		want   bool
	}{
		{"api.example.com", true},
		{"API.EXAMPLE.COM", true}, // case insensitive
		{"other.example.com", false},
		{"example.com", false},
	}

	for _, tt := range tests {
		if got := s.IsInScope(tt.target); got != tt.want {
			t.Errorf("IsInScope(%q) = %v, want %v", tt.target, got, tt.want)
		}
	}
}

func TestExclusions(t *testing.T) {
	content := `*.example.com
-admin.example.com
-*.staging.example.com
`
	path := createTempScopeFile(t, content)
	s, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		target string
		want   bool
	}{
		{"www.example.com", true},
		{"api.example.com", true},
		{"admin.example.com", false},        // excluded explicitly
		{"staging.example.com", false},       // excluded by wildcard
		{"dev.staging.example.com", false},   // excluded by wildcard
		{"a.b.staging.example.com", false},   // excluded by deep wildcard
		{"example.com", true},                // root not excluded
	}

	for _, tt := range tests {
		if got := s.IsInScope(tt.target); got != tt.want {
			t.Errorf("IsInScope(%q) = %v, want %v", tt.target, got, tt.want)
		}
	}
}

func TestURLStripping(t *testing.T) {
	path := createTempScopeFile(t, "*.example.com\n")
	s, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		target string
		want   bool
	}{
		{"https://sub.example.com", true},
		{"http://sub.example.com:8080", true},
		{"https://sub.example.com/path/to/page", true},
		{"https://evil.com", false},
	}

	for _, tt := range tests {
		if got := s.IsInScope(tt.target); got != tt.want {
			t.Errorf("IsInScope(%q) = %v, want %v", tt.target, got, tt.want)
		}
	}
}

func TestFilterHosts(t *testing.T) {
	content := `*.example.com
-admin.example.com
`
	path := createTempScopeFile(t, content)
	s, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}

	hosts := []string{
		"www.example.com",
		"admin.example.com",
		"api.example.com",
		"evil.com",
	}

	filtered := s.FilterHosts(hosts)
	if len(filtered) != 2 {
		t.Errorf("FilterHosts returned %d hosts, want 2: %v", len(filtered), filtered)
	}
}

func TestCommentsAndEmptyLines(t *testing.T) {
	content := `# This is a comment
*.example.com  # inline comment

# Another comment
-admin.example.com
`
	path := createTempScopeFile(t, content)
	s, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if !s.IsInScope("www.example.com") {
		t.Error("www.example.com should be in scope")
	}
	if s.IsInScope("admin.example.com") {
		t.Error("admin.example.com should NOT be in scope")
	}
}

func TestEmptyScopeFileError(t *testing.T) {
	path := createTempScopeFile(t, "# only comments\n\n")
	_, err := LoadFromFile(path)
	if err == nil {
		t.Error("expected error for scope file with no inclusion rules")
	}
}

func TestMultipleDomains(t *testing.T) {
	content := `*.example.com
*.target.io
api.specific.org
-internal.example.com
-*.dev.target.io
`
	path := createTempScopeFile(t, content)
	s, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		target string
		want   bool
	}{
		{"www.example.com", true},
		{"app.target.io", true},
		{"api.specific.org", true},
		{"other.specific.org", false},
		{"internal.example.com", false},
		{"staging.dev.target.io", false},
		{"random.com", false},
	}

	for _, tt := range tests {
		if got := s.IsInScope(tt.target); got != tt.want {
			t.Errorf("IsInScope(%q) = %v, want %v", tt.target, got, tt.want)
		}
	}
}
