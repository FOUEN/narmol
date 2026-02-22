package main

import (
	"github.com/FOUEN/narmol/internal/cli"

	// Side-effect imports: register tools and workflows at init time.
	_ "github.com/FOUEN/narmol/internal/runner"
	_ "github.com/FOUEN/narmol/internal/workflows/active"
	_ "github.com/FOUEN/narmol/internal/workflows/alive"
	_ "github.com/FOUEN/narmol/internal/workflows/crawl"
	_ "github.com/FOUEN/narmol/internal/workflows/full"
	_ "github.com/FOUEN/narmol/internal/workflows/gitexpose"
	_ "github.com/FOUEN/narmol/internal/workflows/headers"
	_ "github.com/FOUEN/narmol/internal/workflows/recon"
	_ "github.com/FOUEN/narmol/internal/workflows/secrets"
	_ "github.com/FOUEN/narmol/internal/workflows/subdomains"
	_ "github.com/FOUEN/narmol/internal/workflows/takeover"
	_ "github.com/FOUEN/narmol/internal/workflows/techdetect"
	_ "github.com/FOUEN/narmol/internal/workflows/urls"
	_ "github.com/FOUEN/narmol/internal/workflows/web"
)

func main() {
	cli.Run()
}
