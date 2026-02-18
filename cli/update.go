package cli

import "narmol/updater"

// RunUpdate handles the "narmol update" subcommand.
func RunUpdate() {
	updater.UpdateAll("tools")
}
