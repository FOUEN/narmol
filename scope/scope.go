package scope

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// rule represents a single scope rule (inclusion or exclusion).
type rule struct {
	pattern string // e.g. "*.example.com" or "admin.example.com"
	exclude bool   // true if this is an exclusion rule (prefixed with -)
}

// Scope enforces what targets can be audited.
// It parses a scope file with wildcards and exclusions.
//
// Format:
//
//	*.example.com          # all subdomains of example.com
//	api.otherdomain.com    # exact domain
//	-admin.example.com     # exclude this specific domain
//	-*.staging.example.com # exclude all staging subdomains
type Scope struct {
	includes []rule
	excludes []rule
}

// LoadFromFile parses a scope file and returns a Scope instance.
// Returns an error if the file cannot be read or contains no valid rules.
func LoadFromFile(path string) (*Scope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not open scope file: %w", err)
	}
	defer f.Close()

	s := &Scope{}
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Strip inline comments
		if idx := strings.Index(line, " #"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		if strings.HasPrefix(line, "-") {
			s.excludes = append(s.excludes, rule{
				pattern: strings.TrimPrefix(line, "-"),
				exclude: true,
			})
		} else {
			s.includes = append(s.includes, rule{
				pattern: line,
				exclude: false,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading scope file: %w", err)
	}

	if len(s.includes) == 0 {
		return nil, fmt.Errorf("scope file contains no inclusion rules")
	}

	return s, nil
}

// IsInScope checks whether a given target (domain/host) is within scope.
// Exclusions always take priority over inclusions.
func (s *Scope) IsInScope(target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))

	// Strip protocol if present
	if idx := strings.Index(target, "://"); idx != -1 {
		target = target[idx+3:]
	}
	// Strip port if present
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		// Make sure it's a port, not part of IPv6
		if !strings.Contains(target[idx:], "]") {
			target = target[:idx]
		}
	}
	// Strip trailing path
	if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}

	// Check exclusions first — they always win
	for _, r := range s.excludes {
		if matchPattern(r.pattern, target) {
			return false
		}
	}

	// Check inclusions
	for _, r := range s.includes {
		if matchPattern(r.pattern, target) {
			return true
		}
	}

	return false
}

// FilterHosts filters a list of hosts, returning only those in scope.
func (s *Scope) FilterHosts(hosts []string) []string {
	var filtered []string
	for _, host := range hosts {
		if s.IsInScope(host) {
			filtered = append(filtered, host)
		}
	}
	return filtered
}

// FilteredCount returns how many hosts were removed by scope filtering.
func (s *Scope) FilteredCount(original, filtered []string) int {
	return len(original) - len(filtered)
}

// Domains extracts the root target domains from the scope inclusion rules.
// For wildcards like "*.example.com", it returns "example.com".
// For exact entries like "api.specific.org", it returns "api.specific.org".
func (s *Scope) Domains() []string {
	seen := map[string]bool{}
	var domains []string
	for _, r := range s.includes {
		domain := r.pattern
		if strings.HasPrefix(domain, "*.") {
			domain = domain[2:]
		}
		domain = strings.ToLower(domain)
		if !seen[domain] {
			seen[domain] = true
			domains = append(domains, domain)
		}
	}
	return domains
}

// String returns a human-readable representation of the scope.
func (s *Scope) String() string {
	var sb strings.Builder
	sb.WriteString("Scope:\n")
	sb.WriteString("  Includes:\n")
	for _, r := range s.includes {
		sb.WriteString(fmt.Sprintf("    + %s\n", r.pattern))
	}
	if len(s.excludes) > 0 {
		sb.WriteString("  Excludes:\n")
		for _, r := range s.excludes {
			sb.WriteString(fmt.Sprintf("    - %s\n", r.pattern))
		}
	}
	return sb.String()
}

// matchPattern checks if a target matches a pattern.
// Supports:
//   - Exact match: "example.com" matches "example.com"
//   - Wildcard: "*.example.com" matches "sub.example.com", "a.b.example.com"
//   - Wildcard also matches the root: "*.example.com" matches "example.com"
func matchPattern(pattern, target string) bool {
	pattern = strings.ToLower(pattern)
	target = strings.ToLower(target)

	if pattern == target {
		return true
	}

	if strings.HasPrefix(pattern, "*.") {
		// The base domain (without wildcard prefix)
		baseDomain := pattern[2:]

		// Match the base domain itself
		if target == baseDomain {
			return true
		}

		// Match any subdomain of the base domain
		if strings.HasSuffix(target, "."+baseDomain) {
			return true
		}
	}

	return false
}
