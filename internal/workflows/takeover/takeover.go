package takeover

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/FOUEN/narmol/internal/scope"
	"github.com/FOUEN/narmol/internal/workflows"
)

func init() {
	workflows.Register(&TakeoverWorkflow{})
}

// TakeoverWorkflow checks subdomains for potential subdomain takeover.
// Resolves CNAME records and checks if the target service is abandoned/claimable.
type TakeoverWorkflow struct{}

func (w *TakeoverWorkflow) Name() string { return "takeover" }

func (w *TakeoverWorkflow) Description() string {
	return "Subdomain takeover detection: resolve CNAMEs and check for abandoned services."
}

// takeoverResult is the JSON output format.
type takeoverResult struct {
	Subdomain string `json:"subdomain"`
	CNAME     string `json:"cname"`
	Service   string `json:"service"`
	Severity  string `json:"severity"`
	Detail    string `json:"detail"`
}

func (r takeoverResult) summary() string {
	return fmt.Sprintf("[%s] %s → %s (%s) — %s", strings.ToUpper(r.Severity), r.Subdomain, r.CNAME, r.Service, r.Detail)
}

// vulnerableServices maps CNAME patterns to service names that may be vulnerable to takeover.
var vulnerableServices = []struct {
	Pattern string
	Service string
	Detail  string
}{
	// Cloud providers
	{".s3.amazonaws.com", "AWS S3", "S3 bucket may be claimable"},
	{".s3-website", "AWS S3 Website", "S3 website bucket may be claimable"},
	{".elasticbeanstalk.com", "AWS Elastic Beanstalk", "Environment may be claimable"},
	{".cloudfront.net", "AWS CloudFront", "Distribution may be claimable"},
	// Azure
	{".azurewebsites.net", "Azure App Service", "App may be claimable"},
	{".cloudapp.azure.com", "Azure Cloud App", "Cloud app may be claimable"},
	{".azurefd.net", "Azure Front Door", "Front door may be claimable"},
	{".blob.core.windows.net", "Azure Blob", "Blob storage may be claimable"},
	{".trafficmanager.net", "Azure Traffic Manager", "Traffic manager may be claimable"},
	{".azure-api.net", "Azure API Management", "API management may be claimable"},
	// Google
	{".storage.googleapis.com", "Google Cloud Storage", "Bucket may be claimable"},
	{".appspot.com", "Google App Engine", "App may be claimable"},
	// Hosting / PaaS
	{".herokuapp.com", "Heroku", "Heroku app may be claimable"},
	{".herokudns.com", "Heroku DNS", "Heroku DNS may be claimable"},
	{".github.io", "GitHub Pages", "GitHub Pages may be claimable"},
	{".netlify.app", "Netlify", "Netlify site may be claimable"},
	{".netlify.com", "Netlify", "Netlify site may be claimable"},
	{".vercel.app", "Vercel", "Vercel deployment may be claimable"},
	{".now.sh", "Vercel (legacy)", "Vercel deployment may be claimable"},
	{".surge.sh", "Surge.sh", "Surge site may be claimable"},
	{".firebaseapp.com", "Firebase", "Firebase app may be claimable"},
	{".web.app", "Firebase Hosting", "Firebase hosting may be claimable"},
	{".fly.dev", "Fly.io", "Fly app may be claimable"},
	// CDN
	{".fastly.net", "Fastly", "Fastly service may be claimable"},
	{".ghost.io", "Ghost", "Ghost blog may be claimable"},
	{".myshopify.com", "Shopify", "Shopify store may be claimable"},
	{".pantheonsite.io", "Pantheon", "Pantheon site may be claimable"},
	{".zendesk.com", "Zendesk", "Zendesk instance may be claimable"},
	{".teamwork.com", "Teamwork", "Teamwork instance may be claimable"},
	{".helpjuice.com", "Helpjuice", "Helpjuice instance may be claimable"},
	{".helpscoutdocs.com", "HelpScout", "HelpScout docs may be claimable"},
	{".statuspage.io", "Statuspage", "Statuspage may be claimable"},
	{".uservoice.com", "UserVoice", "UserVoice instance may be claimable"},
	{".freshdesk.com", "Freshdesk", "Freshdesk instance may be claimable"},
	// Buckets / Storage
	{".digitaloceanspaces.com", "DigitalOcean Spaces", "Space may be claimable"},
	{".backblazeb2.com", "Backblaze B2", "Bucket may be claimable"},
	// Misc
	{".wordpress.com", "WordPress.com", "WordPress site may be claimable"},
	{".tumblr.com", "Tumblr", "Tumblr blog may be claimable"},
	{".cargocollective.com", "Cargo", "Cargo site may be claimable"},
	{".bitbucket.io", "Bitbucket", "Bitbucket pages may be claimable"},
	{".readme.io", "ReadMe", "ReadMe docs may be claimable"},
	{".tictail.com", "Tictail", "Tictail store may be claimable"},
	{".ngrok.io", "ngrok", "ngrok tunnel may be claimable"},
	{".unbouncepages.com", "Unbounce", "Unbounce page may be claimable"},
}

func (w *TakeoverWorkflow) Run(domain string, s *scope.Scope, opts workflows.OutputOptions) error {
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

	fmt.Printf("[*] Checking %d hosts for subdomain takeover...\n", len(hosts))

	var count int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, 30)

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Strip scheme if present
			hostname := h
			if idx := strings.Index(hostname, "://"); idx != -1 {
				hostname = hostname[idx+3:]
			}
			hostname = strings.TrimRight(hostname, "/")

			// Resolve CNAME
			cname, err := net.LookupCNAME(hostname)
			if err != nil || cname == "" || cname == hostname+"." {
				return // no CNAME or self-referencing
			}
			cname = strings.TrimRight(cname, ".")

			// Check if CNAME points to a vulnerable service
			for _, svc := range vulnerableServices {
				if strings.Contains(cname, svc.Pattern) || strings.HasSuffix(cname, svc.Pattern) {
					// Verify: check if the CNAME resolves (NXDOMAIN = likely takeover)
					_, lookupErr := net.LookupHost(cname)
					severity := "medium"
					detail := svc.Detail
					if lookupErr != nil {
						severity = "high"
						detail = svc.Detail + " (NXDOMAIN — strong indicator)"
					}

					result := takeoverResult{
						Subdomain: hostname,
						CNAME:     cname,
						Service:   svc.Service,
						Severity:  severity,
						Detail:    detail,
					}
					atomic.AddInt64(&count, 1)

					if textFile == nil && jsonFile == nil {
						fmt.Println(result.summary())
					}
					if textFile != nil {
						fmt.Fprintln(textFile, result.summary())
					}
					if jsonFile != nil {
						if js, jErr := json.Marshal(result); jErr == nil {
							fmt.Fprintln(jsonFile, string(js))
						}
					}
					break
				}
			}
		}(host)
	}

	wg.Wait()

	// ── Summary ───────────────────────────────────────────────────────
	total := atomic.LoadInt64(&count)
	if opts.TextFile != "" {
		fmt.Printf("[+] Text results saved to: %s\n", opts.TextFile)
	}
	if opts.JSONFile != "" {
		fmt.Printf("[+] JSON results saved to: %s\n", opts.JSONFile)
	}
	fmt.Printf("[+] Workflow 'takeover' completed — %d potential takeovers found\n", total)
	return nil
}
