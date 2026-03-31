// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin && !cgo
// +build darwin,!cgo

package gump

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type DarwinScanner struct{}

func GetScanner() Scanner { return &DarwinScanner{} }

func (ds *DarwinScanner) FindPID() (int, error) {
	cmd := exec.Command("bash", "-c", "ps ax -o pid,comm | grep 'Runner.Worker' | grep -v grep | awk '{print $1}' | head -1")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("ps lookup failed: %w", err)
	}
	pidStr := strings.TrimSpace(out.String())
	if pidStr == "" {
		return 0, fmt.Errorf("Runner.Worker process not found")
	}
	return strconv.Atoi(pidStr)
}

func (ds *DarwinScanner) ScanWithStats(pid int, results chan<- Result) (ScanStats, error) {
	return ScanStats{}, ds.Scan(pid, results)
}

func (ds *DarwinScanner) Scan(pid int, results chan<- Result) error {
	dumpFile := fmt.Sprintf("core.%d", pid)
	defer os.Remove(dumpFile)

	args := []string{"--batch", "-o", "process attach --pid " + strconv.Itoa(pid), "-o", "process save-core '" + dumpFile + "'", "-o", "quit"}
	if err := exec.Command("lldb", args...).Run(); err != nil {
		return fmt.Errorf("lldb failed: %v", err)
	}

	f, err := os.Open(dumpFile)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := make([]byte, 50*1024*1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			ScanChunk(buf[:n], results)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}
