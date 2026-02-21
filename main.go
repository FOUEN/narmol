package main

import (
	"github.com/FOUEN/narmol/internal/cli"

	// Side-effect imports: register tools and workflows at init time.
	_ "github.com/FOUEN/narmol/internal/runner"
	_ "github.com/FOUEN/narmol/internal/workflows/active"
)

func main() {
	cli.Run()
}
