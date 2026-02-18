package main

import (
	"narmol/cli"

	// Side-effect imports: register tools and workflows at init time.
	_ "narmol/runner"
	_ "narmol/workflows/active"
)

func main() {
	cli.Run()
}
