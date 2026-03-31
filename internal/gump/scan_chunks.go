// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package gump

import (
	"fmt"
	"io"
)

const (
	maxExtractedEntryLen = 32 * 1024
	maxExtractedNameLen  = 256

	readableRegionChunkSize = 4 * 1024 * 1024
	readableRegionOverlap   = 64 * 1024
)

type resultEmitter struct {
	results chan<- Result
	seen    map[string]struct{}
}

func newResultEmitter(results chan<- Result) *resultEmitter {
	return &resultEmitter{
		results: results,
		seen:    make(map[string]struct{}),
	}
}

func (re *resultEmitter) emit(result Result) {
	if result.Raw == "" {
		return
	}

	key := fmt.Sprintf("%d:%s", result.Type, result.Raw)
	if _, ok := re.seen[key]; ok {
		return
	}

	re.seen[key] = struct{}{}
	re.results <- result
}

func scanReadableRegion(reader io.ReaderAt, start, size int64, chunkSize, overlap int, scan func([]byte)) (bytesRead int64, readErrors int) {
	if size <= 0 || scan == nil {
		return 0, 0
	}

	if chunkSize <= 0 {
		chunkSize = readableRegionChunkSize
	}
	if overlap < 0 {
		overlap = 0
	}
	if overlap >= chunkSize {
		overlap = chunkSize / 2
	}

	buf := make([]byte, chunkSize)
	var offset int64

	for offset < size {
		readSize := chunkSize
		remaining := size - offset
		if remaining < int64(readSize) {
			readSize = int(remaining)
		}
		if readSize <= 0 {
			break
		}

		n, err := reader.ReadAt(buf[:readSize], start+offset)
		if n > 0 {
			bytesRead += int64(n)
			scan(buf[:n])
		}

		if err != nil && err != io.EOF {
			readErrors++
		}
		if n <= 0 || offset+int64(n) >= size {
			break
		}

		advance := n - overlap
		if advance <= 0 {
			advance = n
		}
		offset += int64(advance)
	}

	return bytesRead, readErrors
}
