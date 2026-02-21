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

// Load parses a scope definition which can be a file path or a direct string (comma-separated rules).
// Returns a Scope instance.
func Load(input string) (*Scope, error) {
	s := &Scope{}

	// Check if input is a file
	info, err := os.Stat(input)
	isFile := err == nil && !info.IsDir()

	if isFile {
		f, err := os.Open(input)
		if err != nil {
			return nil, fmt.Errorf("could not open scope file: %w", err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			processLine(s, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading scope file: %w", err)
		}
	} else {
		// Treat as direct string (comma-separated if needed)
		parts := strings.Split(input, ",")
		for _, part := range parts {
			processLine(s, part)
		}
	}

	if len(s.includes) == 0 {
		return nil, fmt.Errorf("scope contains no inclusion rules")
	}

	return s, nil
}

func processLine(s *Scope, line string) {
	line = strings.TrimSpace(line)

	// Skip empty lines and comments
	if line == "" || strings.HasPrefix(line, "#") {
		return
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
		domain := strings.TrimPrefix(r.pattern, "*.")
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

// HasWildcard checks if the scope includes a wildcard rule for the given domain.
// Used to prevent subdomain enumeration on single-host targets.
func (s *Scope) HasWildcard(target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))

	// Direct check: if the target itself is a wildcard pattern in includes?
	// No, the input target is "example.com". We check if our rules have "*.example.com"

	// Better logic: iterate includes, check if any include starts with "*." AND matches the target as base.
	for _, r := range s.includes {
		if strings.HasPrefix(r.pattern, "*.") {
			baseDomain := r.pattern[2:] // remove "*."
			// If target IS the base domain (example.com), then yes, we have a wildcard for it.
			if target == baseDomain {
				return true
			}
			// If target is a subdomain (sub.example.com), and we have *.example.com rule,
			// then yes, it's covered by wildcard.
			if strings.HasSuffix(target, "."+baseDomain) {
				return true
			}
		}
	}
	return false
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
