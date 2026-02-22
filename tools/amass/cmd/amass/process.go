// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package amass

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	amassengine "github.com/owasp-amass/amass/v5/engine"
	"github.com/owasp-amass/amass/v5/engine/api/graphql/client"
	"github.com/owasp-amass/amass/v5/internal/tools"
)

// engineInstance holds the in-process engine so it can be shut down later.
var engineInstance *amassengine.Engine

func engineIsRunning() bool {
	c := client.NewClient("http://127.0.0.1:4000/graphql")

	if _, err := c.SessionStats(uuid.New()); err != nil && err.Error() == "invalid session token" {
		return true
	}
	return false
}

// startEngineInProcess starts the Amass collection engine in the current
// process as background goroutines. No subprocess is spawned.
func startEngineInProcess() error {
	l, err := engineLogger()
	if err != nil {
		return fmt.Errorf("failed to create engine logger: %w", err)
	}

	e, err := amassengine.NewEngine(l)
	if err != nil {
		return fmt.Errorf("failed to start engine: %w", err)
	}
	engineInstance = e
	return nil
}

// shutdownEngine gracefully shuts down the in-process engine if running.
func shutdownEngine() {
	if engineInstance != nil {
		engineInstance.Shutdown()
		engineInstance = nil
	}
}

// waitForEngine polls the GraphQL endpoint until the engine responds or times out.
func waitForEngine() error {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()

	for range 120 { // 120 × 500ms = 60s max
		<-t.C
		if engineIsRunning() {
			return nil
		}
	}
	return fmt.Errorf("the Amass engine did not respond within the timeout period")
}

// engineLogger creates a logger for the engine, mirroring the logic in
// the engine CLI workflow.
func engineLogger() (*slog.Logger, error) {
	filename := fmt.Sprintf("amass_engine_%s.log", time.Now().Format("2006-01-02T15:04:05"))

	if l, err := tools.NewSyslogLogger(); err == nil && l != nil {
		return l, nil
	}

	dir := config.OutputDirectory("")
	if l, err := tools.NewFileLogger(dir, filename); err == nil && l != nil {
		return l, nil
	}

	return slog.New(slog.NewTextHandler(os.Stdout, nil)), nil
}
