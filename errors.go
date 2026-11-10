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

package safedisk

import (
	"errors"
	"io/fs"
	"os"
	"sync"
	"syscall"
)

const (
	// osEscapeMessage is the text of the os package's unexported escape error. It is used
	// only when the error value itself could not be learnt from a probe.
	osEscapeMessage = "path escapes from parent"
)

var (
	// ErrReadOnly is returned when a write operation is attempted on a read-only sandbox, or
	// when a sub-sandbox would be opened with a wider mode than its parent. It also matches
	// fs.ErrPermission with errors.Is.
	ErrReadOnly error = &sandboxError{
		kind:    fs.ErrPermission,
		message: "safedisk: sandbox is read-only",
	}

	// ErrClosed is returned when an operation is attempted on a closed sandbox, including
	// through the fs.FS returned by Sandbox.FS. It also matches fs.ErrClosed with
	// errors.Is.
	ErrClosed error = &sandboxError{
		kind:    fs.ErrClosed,
		message: "safedisk: sandbox is closed",
	}

	// ErrPathNotAllowed is returned when a Factory is asked to create a sandbox for a path
	// outside its allowed paths. It also matches fs.ErrPermission with errors.Is.
	ErrPathNotAllowed error = &sandboxError{
		kind:    fs.ErrPermission,
		message: "safedisk: path is not in allowed paths",
	}

	// ErrMultipleLinks is returned when a sandbox created with WithRequireSingleLink is
	// asked to open a file that has more than one hard link, or whose link count cannot be
	// read, or to create a hard link. It also matches fs.ErrPermission with errors.Is.
	ErrMultipleLinks error = &sandboxError{
		kind:    fs.ErrPermission,
		message: "safedisk: file has more than one hard link",
	}

	// ErrSymlinkNotAllowed is returned when a sandbox created with WithNoSymlinks is asked
	// to follow or create a symbolic link. It also matches fs.ErrPermission with errors.Is.
	ErrSymlinkNotAllowed error = &sandboxError{
		kind:    fs.ErrPermission,
		message: "safedisk: symbolic links are not allowed in this sandbox",
	}

	// errEscapesRoot marks the escapes that safedisk refuses itself, before os.Root is
	// consulted. IsEscape reports it alongside the os package's own escape error.
	errEscapesRoot = errors.New("escapes sandbox root")

	// errNotDirectory is returned when a no-op sub-sandbox is requested for a path that is
	// not a directory.
	errNotDirectory = errors.New("safedisk: not a directory")

	// errEmptyPath is returned when an empty path is given.
	errEmptyPath = errors.New("safedisk: path cannot be empty")

	// errTempFileExhausted is returned when CreateTemp fails to find a unique filename after
	// the maximum number of attempts.
	errTempFileExhausted = errors.New("safedisk: failed to create temp file after maximum attempts")

	// ErrFileExceedsLimit is returned by ReadFileLimit when the target file is larger than
	// the supplied byte cap. Surfaced as an exported sentinel so callers can use errors.Is
	// to distinguish "file too large" from "missing", "permission denied", and other
	// underlying I/O failures.
	ErrFileExceedsLimit = errors.New("safedisk: file exceeds size limit")

	// ErrInvalidLimit is returned by ReadFileLimit when the supplied byte cap is
	// non-positive.
	ErrInvalidLimit = errors.New("safedisk: limit must be positive")

	// osEscape holds the os package's escape error once it has been learnt.
	osEscape escapeDetector
)

// sandboxError is a safedisk sentinel that also matches a standard fs error, so callers
// that only know the fs sentinels still classify it correctly.
type sandboxError struct {
	// kind is the standard fs error that this error also matches with errors.Is.
	kind error

	// message is the text returned by Error.
	message string
}

// Error returns the error text.
//
// Returns string which is the message prefixed with "safedisk".
func (e *sandboxError) Error() string {
	return e.message
}

// Unwrap returns the standard fs error that this error also matches.
//
// Returns error which is fs.ErrPermission or fs.ErrClosed.
func (e *sandboxError) Unwrap() error {
	return e.kind
}

// escapeDetector learns the os package's unexported escape error by provoking it.
//
// The os package returns one unexported value, created with errors.New, whenever os.Root
// refuses a path that would leave the root. Go does not export it, so it is captured from
// an os.Root that refuses two different escaping names and then compared by identity.
type escapeDetector struct {
	// sentinel is the learnt escape error, or nil until a probe has succeeded.
	sentinel error

	// mu guards sentinel.
	mu sync.Mutex
}

// learn records the escape error by probing root, unless it is already known.
//
// Takes root (*os.Root) which is an open root to probe. It is not closed.
//
// Safe for concurrent use.
func (d *escapeDetector) learn(root *os.Root) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.sentinel == nil {
		d.sentinel = probeEscapeError(root)
	}
}

// get returns the escape error, probing a root in the temporary directory or the working
// directory when no sandbox has taught it yet.
//
// Returns error which is the os package's escape error, or nil when no probe succeeded.
//
// Safe for concurrent use.
func (d *escapeDetector) get() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, directory := range []string{os.TempDir(), currentDir} {
		if d.sentinel != nil {
			break
		}
		root, err := os.OpenRoot(directory)
		if err != nil {
			continue
		}
		d.sentinel = probeEscapeError(root)
		_ = root.Close()
	}

	return d.sentinel
}

// IsEscape reports whether err shows that a path was refused because it would leave a
// sandbox.
//
// Takes err (error) which is the error to check.
//
// Returns bool which is true if err, or any error it wraps, is an escape refusal.
func IsEscape(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errEscapesRoot) {
		return true
	}

	if sentinel := osEscape.get(); sentinel != nil {
		return errors.Is(err, sentinel)
	}

	for current := err; current != nil; current = errors.Unwrap(current) {
		if current.Error() == osEscapeMessage {
			return true
		}
	}
	return false
}

// IsNotExist reports whether the error shows that a file or directory does not exist.
//
// This is a wrapper around os.IsNotExist to avoid needing to import the os package
// separately.
//
// Takes err (error) which is the error to check.
//
// Returns bool which is true if err shows the file does not exist.
func IsNotExist(err error) bool {
	return os.IsNotExist(err)
}

// isExist reports whether the error shows that a file or directory already exists.
//
// This is a wrapper around os.IsExist so callers do not need to import the os package.
//
// Takes err (error) which is the error to check.
//
// Returns bool which is true if the error indicates the file already exists.
func isExist(err error) bool {
	return os.IsExist(err)
}

// isPermission reports whether the error shows a permission problem.
//
// This is a wrapper around os.IsPermission so callers do not need to import the os
// package.
//
// Takes err (error) which is the error to check.
//
// Returns bool which is true if the error indicates a permission problem.
func isPermission(err error) bool {
	return os.IsPermission(err)
}

// probeEscapeError provokes the os package's escape error from root.
//
// Takes root (*os.Root) which is an open root. Neither probe touches the filesystem,
// because os.Root refuses both names while splitting the path.
//
// Returns error which is the escape error, or nil when the two probes disagree or return
// something that is plainly not the escape error.
func probeEscapeError(root *os.Root) error {
	_, absoluteErr := root.Lstat("/")
	_, parentErr := root.Lstat("..")

	absoluteCause := pathErrorCause(absoluteErr)
	parentCause := pathErrorCause(parentErr)
	if absoluteCause == nil || parentCause == nil || !errors.Is(absoluteCause, parentCause) {
		return nil
	}

	if _, isErrno := errors.AsType[syscall.Errno](absoluteCause); isErrno {
		return nil
	}
	for _, standard := range []error{fs.ErrNotExist, fs.ErrExist, fs.ErrPermission, fs.ErrInvalid, fs.ErrClosed} {
		if errors.Is(absoluteCause, standard) {
			return nil
		}
	}
	return absoluteCause
}

// pathErrorCause returns the error wrapped by a *fs.PathError.
//
// Takes err (error) which is the error to inspect.
//
// Returns error which is the wrapped cause, or nil when err is not a *fs.PathError.
func pathErrorCause(err error) error {
	pathErr, isPathErr := errors.AsType[*fs.PathError](err)
	if !isPathErr {
		return nil
	}
	return pathErr.Err
}
