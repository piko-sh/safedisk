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

//go:build windows

package safedisk

import (
	"io/fs"
	"os"
	"syscall"
)

// linkCount returns the number of hard links to an opened file, read with
// GetFileInformationByHandle on its handle.
//
// Takes file (*os.File) which is the opened file.
//
// Returns uint64 which is the link count.
// Returns bool which is false when the count could not be read.
func linkCount(file *os.File, _ fs.FileInfo) (uint64, bool) {
	conn, err := file.SyscallConn()
	if err != nil {
		return 0, false
	}

	var data syscall.ByHandleFileInformation
	var infoErr error
	controlErr := conn.Control(func(handle uintptr) {
		infoErr = syscall.GetFileInformationByHandle(syscall.Handle(handle), &data)
	})
	if controlErr != nil || infoErr != nil {
		return 0, false
	}
	return uint64(data.NumberOfLinks), true
}
