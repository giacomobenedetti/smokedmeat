// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin && cgo
// +build darwin,cgo

package gump

/*
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	mach_vm_address_t address;
	mach_vm_size_t size;
	vm_region_basic_info_data_64_t info;
} region_info_t;

static mach_port_t get_self_task() {
	return mach_task_self();
}

static kern_return_t get_task_for_pid_wrapper(int pid, mach_port_t *task) {
	return task_for_pid(mach_task_self(), pid, task);
}

static kern_return_t read_region_info(mach_port_t task, mach_vm_address_t *address, region_info_t *region) {
	mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
	mach_port_t object_name;

	kern_return_t kr = mach_vm_region(task, address, &region->size,
		VM_REGION_BASIC_INFO_64, (vm_region_info_t)&region->info, &count, &object_name);

	if (kr == KERN_SUCCESS) {
		region->address = *address;
	}
	return kr;
}

static kern_return_t read_memory(mach_port_t task, mach_vm_address_t address,
	mach_vm_size_t size, void *buffer, mach_vm_size_t *bytes_read) {
	vm_offset_t data;
	mach_msg_type_number_t data_count;

	kern_return_t kr = mach_vm_read(task, address, size, &data, &data_count);
	if (kr == KERN_SUCCESS) {
		memcpy(buffer, (void *)data, data_count);
		*bytes_read = data_count;
		mach_vm_deallocate(mach_task_self(), data, data_count);
	}
	return kr;
}
*/
import "C"

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"
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
	var task C.mach_port_t
	kr := C.get_task_for_pid_wrapper(C.int(pid), &task)
	if kr != C.KERN_SUCCESS {
		return fmt.Errorf("task_for_pid failed with code %d (5=no access, try running with sudo)", kr)
	}
	if task == 0 {
		return fmt.Errorf("task_for_pid returned null task port")
	}
	defer C.mach_port_deallocate(C.get_self_task(), task)

	var address C.mach_vm_address_t = 0
	maxChunkSize := C.mach_vm_size_t(20 * 1024 * 1024)
	buffer := make([]byte, maxChunkSize)
	regionsScanned := 0

	for {
		var region C.region_info_t
		if kr := C.read_region_info(task, &address, &region); kr != C.KERN_SUCCESS {
			break
		}

		if region.size == 0 {
			break
		}

		if region.info.protection&C.VM_PROT_READ != 0 {
			readSize := region.size
			if readSize > maxChunkSize {
				readSize = maxChunkSize
			}

			var bytesRead C.mach_vm_size_t
			if kr := C.read_memory(task, region.address, readSize,
				unsafe.Pointer(&buffer[0]), &bytesRead); kr == C.KERN_SUCCESS && bytesRead > 0 {
				ScanChunk(buffer[:bytesRead], results)
			}
		}

		regionsScanned++
		if regionsScanned > 100000 {
			return fmt.Errorf("too many regions, aborting")
		}

		address = region.address + region.size
	}

	return nil
}
