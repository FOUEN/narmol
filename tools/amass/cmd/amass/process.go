// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package amass

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/engine/api/graphql/client"
)

func engineIsRunning() bool {
	c := client.NewClient("http://127.0.0.1:4000/graphql")

	if _, err := c.SessionStats(uuid.New()); err != nil && err.Error() == "invalid session token" {
		return true
	}
	return false
}

// engineCmdArgs returns the arguments needed to launch the engine subprocess.
// When running inside a wrapper (e.g., narmol), os.Executable() differs from
// os.Args[0], so we must include the tool name ("amass") as a prefix argument.
func engineCmdArgs(execPath string) []string {
	execBase := strings.TrimSuffix(filepath.Base(execPath), filepath.Ext(filepath.Base(execPath)))
	argv0Base := strings.TrimSuffix(filepath.Base(os.Args[0]), filepath.Ext(filepath.Base(os.Args[0])))

	if !strings.EqualFold(execBase, argv0Base) {
		// Running inside a wrapper: e.g. narmol amass engine
		return []string{argv0Base, "engine"}
	}
	return []string{"engine"}
}

func startEngine() error {
	p, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	if p == "" {
		return fmt.Errorf("executable path is empty")
	}

	cmd := initCmd(p, engineCmdArgs(p))
	if cmd == nil {
		return fmt.Errorf("failed to initialize command for %s", p)
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Stdin = os.Stdin

	cmd.Dir, err = os.Getwd()
	if err != nil {
		return err
	}

	return cmd.Start()
}
