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

	_, err := c.SessionStats(uuid.New())
	if err != nil && err.Error() == "invalid session token" {
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

	fmt.Fprintf(os.Stderr, "[*] Starting Amass engine in-process...\n")

	type engineResult struct {
		engine *amassengine.Engine
		err    error
	}

	ch := make(chan engineResult, 1)
	go func() {
		e, err := amassengine.NewEngine(l)
		ch <- engineResult{engine: e, err: err}
	}()

	// Wait up to 2 minutes for the engine to start (plugin loading can be slow)
	select {
	case res := <-ch:
		if res.err != nil {
			return fmt.Errorf("failed to start engine: %w", res.err)
		}
		engineInstance = res.engine
		fmt.Fprintf(os.Stderr, "[+] Amass engine started\n")
		return nil
	case <-time.After(2 * time.Minute):
		return fmt.Errorf("engine startup timed out after 2 minutes (plugins may be unreachable)")
	}
}

// shutdownEngine gracefully shuts down the in-process engine if running.
func shutdownEngine() {
	if engineInstance != nil {
		engineInstance.Shutdown()
		engineInstance = nil
	}
}

// waitForEngine polls the GraphQL endpoint until the engine responds or times out.
// Only needed when checking for an externally-started engine.
func waitForEngine() error {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()

	for range 20 { // 20 × 500ms = 10s max
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
