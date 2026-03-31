// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows
// +build windows

package gump

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

type WindowsScanner struct{}

func GetScanner() Scanner { return &WindowsScanner{} }

var (
	modKernel32           = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess       = modKernel32.NewProc("OpenProcess")
	procReadProcessMemory = modKernel32.NewProc("ReadProcessMemory")
	procVirtualQueryEx    = modKernel32.NewProc("VirtualQueryEx")
	procCloseHandle       = modKernel32.NewProc("CloseHandle")
)

const (
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_READ           = 0x0010
	MEM_COMMIT                = 0x1000
	PAGE_NOACCESS             = 0x01
	PAGE_GUARD                = 0x100
)

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress, AllocationBase uintptr
	AllocationProtect           uint32
	PartitionId                 uint16
	_                           [2]byte
	RegionSize                  uintptr
	State, Protect, Type        uint32
}

func (ws *WindowsScanner) FindPID() (int, error) {
	cmd := exec.Command("powershell", "-Command", "(Get-Process 'Runner.Worker' -ErrorAction SilentlyContinue).Id")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(out.String()))
}

func (ws *WindowsScanner) ScanWithStats(pid int, results chan<- Result) (ScanStats, error) {
	return ScanStats{}, ws.Scan(pid, results)
}

func (ws *WindowsScanner) Scan(pid int, results chan<- Result) error {
	hProcess, _, _ := procOpenProcess.Call(uintptr(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ), 0, uintptr(pid))
	if hProcess == 0 {
		return fmt.Errorf("failed to OpenProcess")
	}
	defer procCloseHandle.Call(hProcess)

	var address uintptr = 0
	var mbi MEMORY_BASIC_INFORMATION
	mbiSize := unsafe.Sizeof(mbi)
	maxChunkSize := uintptr(20 * 1024 * 1024)

	for {
		if ret, _, _ := procVirtualQueryEx.Call(hProcess, address, uintptr(unsafe.Pointer(&mbi)), mbiSize); ret == 0 {
			break
		}

		if mbi.State == MEM_COMMIT && (mbi.Protect&PAGE_NOACCESS) == 0 && (mbi.Protect&PAGE_GUARD) == 0 {
			readSize := mbi.RegionSize
			if readSize > maxChunkSize {
				readSize = maxChunkSize
			}
			buffer := make([]byte, readSize)
			var bytesRead uintptr
			if s, _, _ := procReadProcessMemory.Call(hProcess, address, uintptr(unsafe.Pointer(&buffer[0])), readSize, uintptr(unsafe.Pointer(&bytesRead))); s != 0 && bytesRead > 0 {
				ScanChunk(buffer[:bytesRead], results)
			}
		}
		address += mbi.RegionSize
	}
	return nil
}
