package cli

import "github.com/FOUEN/narmol/internal/updater"

// RunUpdate handles the "narmol update" subcommand.
// It updates all tool sources, patches them, and rebuilds the binary automatically.
func RunUpdate() {
	updater.SelfUpdate()
}
