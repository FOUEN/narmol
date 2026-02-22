package headers

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FOUEN/narmol/internal/scope"
	"github.com/FOUEN/narmol/internal/workflows"
)

func init() {
	workflows.Register(&HeadersWorkflow{})
}

// HeadersWorkflow audits security headers, CORS, cookies, and SSL/TLS config.
// All checks use pure stdlib — no external tools.
type HeadersWorkflow struct{}

func (w *HeadersWorkflow) Name() string { return "headers" }

func (w *HeadersWorkflow) Description() string {
	return "Security audit: headers (HSTS, CSP, X-Frame), CORS, cookies, SSL/TLS config. Pure stdlib."
}

// headerResult is the JSON output format.
type headerResult struct {
	URL      string `json:"url"`
	Category string `json:"category"` // "header", "cors", "cookie", "tls"
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

func (r headerResult) summary() string {
	return fmt.Sprintf("[%s-%s] %s — %s", strings.ToUpper(r.Category), strings.ToUpper(r.Severity), r.URL, r.Detail)
}

// requiredHeaders are security headers that should be present.
var requiredHeaders = []struct {
	Name     string
	Severity string
}{
	{"Strict-Transport-Security", "medium"},
	{"X-Content-Type-Options", "low"},
	{"X-Frame-Options", "medium"},
	{"Content-Security-Policy", "medium"},
	{"Referrer-Policy", "low"},
	{"Permissions-Policy", "low"},
}

// weakCiphers contains TLS cipher suites considered insecure.
var weakCiphers = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:             "RC4-SHA",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:        "3DES-CBC-SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:         "RSA-AES128-CBC-SHA",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:         "RSA-AES256-CBC-SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:      "RSA-AES128-CBC-SHA256",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:       "ECDHE-RC4-SHA",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:  "ECDHE-3DES-CBC-SHA",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:     "ECDHE-ECDSA-RC4-SHA",
}

func (w *HeadersWorkflow) Run(domain string, s *scope.Scope, opts workflows.OutputOptions) error {
	if !s.IsInScope(domain) {
		return fmt.Errorf("domain %s is not in scope", domain)
	}

	hosts := []string{domain}

	// ── Output files ──────────────────────────────────────────────────
	var textFile, jsonFile *os.File
	var err error
	if opts.TextFile != "" {
		textFile, err = os.OpenFile(opts.TextFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open text output: %w", err)
		}
		defer textFile.Close()
	}
	if opts.JSONFile != "" {
		jsonFile, err = os.OpenFile(opts.JSONFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open JSON output: %w", err)
		}
		defer jsonFile.Close()
	}

	seen := &sync.Map{}
	emit := func(r headerResult) bool {
		key := r.Category + ":" + r.URL + ":" + r.Detail
		if _, loaded := seen.LoadOrStore(key, true); loaded {
			return false
		}
		if textFile == nil && jsonFile == nil {
			fmt.Println(r.summary())
		}
		if textFile != nil {
			fmt.Fprintln(textFile, r.summary())
		}
		if jsonFile != nil {
			if js, jErr := json.Marshal(r); jErr == nil {
				fmt.Fprintln(jsonFile, string(js))
			}
		}
		return true
	}

	// Ensure hosts have scheme
	var targets []string
	for _, h := range hosts {
		if !strings.HasPrefix(h, "http://") && !strings.HasPrefix(h, "https://") {
			targets = append(targets, "https://"+h)
		} else {
			targets = append(targets, h)
		}
	}

	var headerCount, tlsCount int64
	var wg sync.WaitGroup

	// Run header/CORS/cookie checks and TLS checks in parallel
	wg.Add(1)
	go func() {
		defer wg.Done()
		headerCount = w.runHeaderChecks(targets, emit)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		tlsCount = w.runTLSChecks(targets, emit)
	}()

	wg.Wait()

	// ── Summary ───────────────────────────────────────────────────────
	if opts.TextFile != "" {
		fmt.Printf("[+] Text results saved to: %s\n", opts.TextFile)
	}
	if opts.JSONFile != "" {
		fmt.Printf("[+] JSON results saved to: %s\n", opts.JSONFile)
	}
	fmt.Printf("[+] Workflow 'headers' completed — %d header issues, %d TLS issues\n", headerCount, tlsCount)
	return nil
}

// runHeaderChecks checks security headers, CORS, and cookies.
func (w *HeadersWorkflow) runHeaderChecks(hosts []string, emit func(headerResult) bool) int64 {
	fmt.Printf("[*] Checking security headers on %d hosts...\n", len(hosts))

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
			DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		},
	}

	var count int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			req, err := http.NewRequest("GET", h, nil)
			if err != nil {
				return
			}
			req.Header.Set("Origin", "https://evil.com")
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			// Missing security headers
			for _, hdr := range requiredHeaders {
				if resp.Header.Get(hdr.Name) == "" {
					if emit(headerResult{URL: h, Category: "header", Severity: hdr.Severity, Detail: "Missing " + hdr.Name}) {
						atomic.AddInt64(&count, 1)
					}
				}
			}

			// CORS misconfiguration
			acao := resp.Header.Get("Access-Control-Allow-Origin")
			if acao == "*" || acao == "https://evil.com" {
				if emit(headerResult{URL: h, Category: "cors", Severity: "high", Detail: fmt.Sprintf("CORS misconfiguration: ACAO=%s", acao)}) {
					atomic.AddInt64(&count, 1)
				}
			}
			acac := resp.Header.Get("Access-Control-Allow-Credentials")
			if acac == "true" && (acao == "*" || acao == "https://evil.com") {
				if emit(headerResult{URL: h, Category: "cors", Severity: "critical", Detail: "CORS with credentials: origin reflected + Allow-Credentials: true"}) {
					atomic.AddInt64(&count, 1)
				}
			}

			// Insecure cookies
			for _, cookie := range resp.Cookies() {
				var issues []string
				if !cookie.Secure && strings.HasPrefix(h, "https://") {
					issues = append(issues, "missing Secure")
				}
				if !cookie.HttpOnly {
					issues = append(issues, "missing HttpOnly")
				}
				if cookie.SameSite == http.SameSiteNoneMode || cookie.SameSite == 0 {
					issues = append(issues, "missing/weak SameSite")
				}
				if len(issues) > 0 {
					if emit(headerResult{URL: h, Category: "cookie", Severity: "low", Detail: fmt.Sprintf("Cookie '%s': %s", cookie.Name, strings.Join(issues, ", "))}) {
						atomic.AddInt64(&count, 1)
					}
				}
			}
		}(host)
	}

	wg.Wait()
	total := atomic.LoadInt64(&count)
	fmt.Printf("[+] Security header checks done — %d issues\n", total)
	return total
}

// runTLSChecks checks TLS protocol version, weak ciphers, cert validity.
func (w *HeadersWorkflow) runTLSChecks(hosts []string, emit func(headerResult) bool) int64 {
	var httpsHosts []string
	for _, h := range hosts {
		if strings.HasPrefix(h, "https://") {
			httpsHosts = append(httpsHosts, h)
		}
	}
	if len(httpsHosts) == 0 {
		return 0
	}

	fmt.Printf("[*] Checking TLS config on %d HTTPS hosts...\n", len(httpsHosts))

	var count int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for _, host := range httpsHosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			parsed, err := url.Parse(h)
			if err != nil {
				return
			}
			hostname := parsed.Hostname()
			port := parsed.Port()
			if port == "" {
				port = "443"
			}
			addr := net.JoinHostPort(hostname, port)

			conn, err := tls.DialWithDialer(
				&net.Dialer{Timeout: 5 * time.Second},
				"tcp", addr,
				&tls.Config{InsecureSkipVerify: true},
			)
			if err != nil {
				return
			}
			defer conn.Close()

			state := conn.ConnectionState()

			// Protocol version
			switch state.Version {
			case tls.VersionTLS10:
				if emit(headerResult{URL: h, Category: "tls", Severity: "high", Detail: "TLS 1.0 supported (deprecated, vulnerable to BEAST/POODLE)"}) {
					atomic.AddInt64(&count, 1)
				}
			case tls.VersionTLS11:
				if emit(headerResult{URL: h, Category: "tls", Severity: "medium", Detail: "TLS 1.1 supported (deprecated)"}) {
					atomic.AddInt64(&count, 1)
				}
			}

			// Weak cipher suite
			if name, weak := weakCiphers[state.CipherSuite]; weak {
				if emit(headerResult{URL: h, Category: "tls", Severity: "high", Detail: fmt.Sprintf("Weak cipher suite: %s", name)}) {
					atomic.AddInt64(&count, 1)
				}
			}

			// Certificate checks
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				now := time.Now()

				if now.After(cert.NotAfter) {
					if emit(headerResult{URL: h, Category: "tls", Severity: "high", Detail: fmt.Sprintf("Certificate expired: %s", cert.NotAfter.Format("2006-01-02"))}) {
						atomic.AddInt64(&count, 1)
					}
				}
				if now.Before(cert.NotAfter) && cert.NotAfter.Before(now.Add(30*24*time.Hour)) {
					if emit(headerResult{URL: h, Category: "tls", Severity: "medium", Detail: fmt.Sprintf("Certificate expiring soon: %s", cert.NotAfter.Format("2006-01-02"))}) {
						atomic.AddInt64(&count, 1)
					}
				}
				if cert.Issuer.CommonName == cert.Subject.CommonName {
					pool := x509.NewCertPool()
					pool.AddCert(cert)
					if _, verifyErr := cert.Verify(x509.VerifyOptions{Roots: pool}); verifyErr == nil {
						if emit(headerResult{URL: h, Category: "tls", Severity: "medium", Detail: "Self-signed certificate"}) {
							atomic.AddInt64(&count, 1)
						}
					}
				}
				if err := cert.VerifyHostname(hostname); err != nil {
					if emit(headerResult{URL: h, Category: "tls", Severity: "high", Detail: fmt.Sprintf("Certificate hostname mismatch: cert for %s", strings.Join(cert.DNSNames, ", "))}) {
						atomic.AddInt64(&count, 1)
					}
				}
			}
		}(host)
	}

	wg.Wait()
	total := atomic.LoadInt64(&count)
	fmt.Printf("[+] TLS checks done — %d issues\n", total)
	return total
}
