// Copyright 2026 PolitePixels Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This project stands against fascism, authoritarianism, and all forms of
// oppression. We built this to empower people, not to enable those who would
// strip others of their rights and dignity.

//go:build unix || (js && wasm) || wasip1

package safedisk

import (
	"io/fs"
	"os"
	"syscall"
)

// linkCount returns the number of hard links to an opened file.
//
// Takes info (fs.FileInfo) which is the result of Stat on the opened file, so the count
// comes from fstat on its descriptor.
//
// Returns uint64 which is the link count.
// Returns bool which is false when the count is not available.
func linkCount(_ *os.File, info fs.FileInfo) (uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(stat.Nlink), true
}
