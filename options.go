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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	// opOpen is the operation name used in errors for refused opens.
	opOpen = "open"
)

// Option configures a sandbox created with NewSandboxWithOptions or
// NewNoOpSandboxWithOptions. Both options are off by default.
type Option func(*sandboxOptions)

// sandboxOptions holds the settings chosen with Option values.
type sandboxOptions struct {
	// requireSingleLink refuses to open a file that has more than one hard link.
	requireSingleLink bool

	// noSymlinks refuses to follow any symbolic link.
	noSymlinks bool
}

// openPolicy applies a sandbox's options to one path or one opened file.
type openPolicy struct {
	// lstat returns information about a sandbox-relative path without following a final
	// symbolic link.
	lstat func(name string) (fs.FileInfo, error)

	// options holds the sandbox's settings.
	options sandboxOptions
}

// checkPath refuses a path that passes through a symbolic link when symbolic links are
// not allowed.
//
// Takes name (string) which is the cleaned sandbox-relative path.
// Takes followFinal (bool) which is true when the operation would follow a symbolic link
// in the final component, so that component is examined too.
//
// Returns error wrapping ErrSymlinkNotAllowed when a component is a symbolic link.
func (p openPolicy) checkPath(name string, followFinal bool) error {
	if !p.options.noSymlinks {
		return nil
	}

	clean := filepath.Clean(name)
	if clean == currentDir {
		return nil
	}

	parts := strings.Split(clean, string(filepath.Separator))
	if !followFinal {
		parts = parts[:len(parts)-1]
	}

	current := ""
	for _, part := range parts {
		current = filepath.Join(current, part)
		info, err := p.lstat(current)
		if err != nil {
			return nil
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return &fs.PathError{Op: "resolve", Path: current, Err: ErrSymlinkNotAllowed}
		}
	}
	return nil
}

// openFlags adjusts open flags so that a file is not truncated before its link count has
// been checked.
//
// Takes flag (int) which is the caller's open flags.
//
// Returns int which is the flags to open with.
// Returns bool which is true when the file must be truncated after the check.
func (p openPolicy) openFlags(flag int) (int, bool) {
	writes := flag&(os.O_WRONLY|os.O_RDWR) != 0
	if p.options.requireSingleLink && writes && flag&os.O_TRUNC != 0 {
		return flag &^ os.O_TRUNC, true
	}
	return flag, false
}

// afterOpen checks a file that has just been opened, then truncates it if openFlags
// deferred that.
//
// Takes name (string) which is the cleaned sandbox-relative path that was opened.
// Takes file (*os.File) which is the opened file.
// Takes truncate (bool) which is true when the file must now be truncated.
//
// Returns error wrapping ErrSymlinkNotAllowed or ErrMultipleLinks when the file is
// refused, or the error from the check or the truncation.
func (p openPolicy) afterOpen(name string, file *os.File, truncate bool) error {
	if p.options.noSymlinks {
		if err := p.verifyOpenedPath(name, file); err != nil {
			return err
		}
	}
	if p.options.requireSingleLink {
		if err := checkSingleLink(name, file); err != nil {
			return err
		}
	}
	if truncate {
		if err := file.Truncate(0); err != nil {
			return fmt.Errorf("truncating %q after checking its links: %w", name, err)
		}
	}
	return nil
}

// verifyOpenedPath confirms after an open that name is not a symbolic link and still
// names the file that was opened. This narrows, but does not close, the window in which
// another process could swap the final component for a symbolic link.
//
// Takes name (string) which is the cleaned sandbox-relative path that was opened.
// Takes file (*os.File) which is the opened file.
//
// Returns error wrapping ErrSymlinkNotAllowed when name is a symbolic link or names a
// different file, or the error from either stat call.
func (p openPolicy) verifyOpenedPath(name string, file *os.File) error {
	if filepath.Clean(name) == currentDir {
		return nil
	}

	pathInfo, err := p.lstat(name)
	if err != nil {
		return err
	}
	if pathInfo.Mode()&fs.ModeSymlink != 0 {
		return &fs.PathError{Op: opOpen, Path: name, Err: ErrSymlinkNotAllowed}
	}

	openedInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(pathInfo, openedInfo) {
		return &fs.PathError{Op: opOpen, Path: name, Err: ErrSymlinkNotAllowed}
	}
	return nil
}

// WithRequireSingleLink makes a sandbox refuse to open any file, other than a directory,
// that has more than one hard link.
//
// On Windows the count comes from GetFileInformationByHandle on the open handle. Plan 9
// has no hard links, so every file has one. On any other platform where the count cannot
// be read, the file is refused.
//
// Returns Option which enables the check.
func WithRequireSingleLink() Option {
	return func(options *sandboxOptions) {
		options.requireSingleLink = true
	}
}

// WithNoSymlinks makes a sandbox refuse to follow any symbolic link, including links that
// stay inside the sandbox.
//
// Returns Option which enables the check.
func WithNoSymlinks() Option {
	return func(options *sandboxOptions) {
		options.noSymlinks = true
	}
}

// applyOptions collects Option values into sandboxOptions.
//
// Takes options ([]Option) which are applied in order. Nil values are ignored.
//
// Returns sandboxOptions which holds the resulting settings.
func applyOptions(options []Option) sandboxOptions {
	var settings sandboxOptions
	for _, option := range options {
		if option != nil {
			option(&settings)
		}
	}
	return settings
}

// checkSingleLink refuses an opened file, other than a directory, with more than one hard
// link.
//
// Takes name (string) which is the sandbox-relative path, used in the error.
// Takes file (*os.File) which is the opened file.
//
// Returns error wrapping ErrMultipleLinks when the file has more than one link or its
// count cannot be read, or the error from stat.
func checkSingleLink(name string, file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.IsDir() {
		return nil
	}

	count, known := linkCount(file, info)
	if !known {
		return &fs.PathError{Op: opOpen, Path: name, Err: fmt.Errorf("%w: the link count is unavailable on this platform", ErrMultipleLinks)}
	}
	if count > 1 {
		return &fs.PathError{Op: opOpen, Path: name, Err: ErrMultipleLinks}
	}
	return nil
}
