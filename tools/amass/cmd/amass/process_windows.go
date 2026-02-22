//go:build windows

// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package amass

import (
	"os/exec"
	"syscall"
)

func initCmd(p string, args []string) *exec.Cmd {
	cmdArgs := append([]string{"/C", "start", p}, args...)
	cmd := exec.Command("cmd", cmdArgs...)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}

	return cmd
}
