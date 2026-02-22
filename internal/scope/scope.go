package scope

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// rule represents a single scope rule (inclusion or exclusion).
type rule struct {
	pattern string // e.g. "*.example.com", "admin.example.com", "10.0.0.1", "192.168.1.0/24"
	exclude bool   // true if this is an exclusion rule (prefixed with -)
	ip      net.IP // non-nil if this is a single IP rule
	cidr    *net.IPNet // non-nil if this is a CIDR rule
}

// Scope enforces what targets can be audited.
// It parses a scope file with wildcards, exclusions, IPs and CIDRs.
//
// Format:
//
//	*.example.com          # all subdomains of example.com
//	api.otherdomain.com    # exact domain
//	-admin.example.com     # exclude this specific domain
//	-*.staging.example.com # exclude all staging subdomains
//	10.0.0.1               # single IP
//	192.168.1.0/24         # CIDR range
//	-10.0.0.5              # exclude specific IP
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

	exclude := false
	pattern := line
	if strings.HasPrefix(line, "-") {
		exclude = true
		pattern = strings.TrimPrefix(line, "-")
	}

	r := rule{pattern: pattern, exclude: exclude}

	// Try to parse as CIDR (e.g. 192.168.1.0/24)
	if _, cidr, err := net.ParseCIDR(pattern); err == nil {
		r.cidr = cidr
	} else if ip := net.ParseIP(pattern); ip != nil {
		// Try to parse as single IP
		r.ip = ip
	}

	if exclude {
		s.excludes = append(s.excludes, r)
	} else {
		s.includes = append(s.includes, r)
	}
}

// IsInScope checks whether a given target (domain/host/IP) is within scope.
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
	// Strip brackets from IPv6
	target = strings.Trim(target, "[]")

	// Check if target is an IP address
	targetIP := net.ParseIP(target)

	// Check exclusions first — they always win
	for _, r := range s.excludes {
		if matchRule(r, target, targetIP) {
			return false
		}
	}

	// Check inclusions
	for _, r := range s.includes {
		if matchRule(r, target, targetIP) {
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
// IP and CIDR rules are excluded.
func (s *Scope) Domains() []string {
	seen := map[string]bool{}
	var domains []string
	for _, r := range s.includes {
		if r.ip != nil || r.cidr != nil {
			continue
		}
		domain := strings.TrimPrefix(r.pattern, "*.")
		domain = strings.ToLower(domain)
		if !seen[domain] {
			seen[domain] = true
			domains = append(domains, domain)
		}
	}
	return domains
}

// IPs returns all IP and CIDR inclusion rules as strings.
func (s *Scope) IPs() []string {
	var ips []string
	for _, r := range s.includes {
		if r.ip != nil || r.cidr != nil {
			ips = append(ips, r.pattern)
		}
	}
	return ips
}

// HasIPs returns true if the scope contains any IP or CIDR inclusion rules.
func (s *Scope) HasIPs() bool {
	for _, r := range s.includes {
		if r.ip != nil || r.cidr != nil {
			return true
		}
	}
	return false
}

// String returns a human-readable representation of the scope.
func (s *Scope) String() string {
	var sb strings.Builder
	sb.WriteString("Scope:\n")
	sb.WriteString("  Includes:\n")
	for _, r := range s.includes {
		label := "domain"
		if r.cidr != nil {
			label = "cidr"
		} else if r.ip != nil {
			label = "ip"
		}
		sb.WriteString(fmt.Sprintf("    + %s (%s)\n", r.pattern, label))
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

// matchRule checks if a target matches a rule.
// Handles IP rules, CIDR rules, and domain patterns.
func matchRule(r rule, target string, targetIP net.IP) bool {
	// CIDR rule: check if target IP falls within the range
	if r.cidr != nil {
		return targetIP != nil && r.cidr.Contains(targetIP)
	}
	// IP rule: check if target IP matches exactly
	if r.ip != nil {
		return targetIP != nil && r.ip.Equal(targetIP)
	}
	// Domain pattern matching
	return matchPattern(r.pattern, target)
}

// matchPattern checks if a target matches a domain pattern.
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
