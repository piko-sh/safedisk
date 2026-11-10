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
	"io/fs"
	"path/filepath"
)

// sandboxFS is the fs.FS returned by Sandbox.FS.
type sandboxFS struct {
	// fsys is the backing file system, such as the result of os.Root.FS.
	fsys fs.FS

	// checkClosed returns ErrClosed when the owning sandbox has been closed.
	checkClosed func() error

	// open opens a file through the sandbox, or is nil to use fsys directly.
	open func(name string) (*File, error)

	// policy checks paths for symbolic links when the sandbox refuses them.
	policy openPolicy
}

// openOnlyFS exposes only Open, so that fs.ReadFile reads through sandboxFS.Open.
type openOnlyFS struct {
	// fsys is the sandbox view to open files through.
	fsys *sandboxFS
}

var (
	_ fs.StatFS = (*sandboxFS)(nil)

	_ fs.ReadFileFS = (*sandboxFS)(nil)

	_ fs.ReadDirFS = (*sandboxFS)(nil)

	_ fs.ReadLinkFS = (*sandboxFS)(nil)
)

// Open opens the named file for reading.
//
// Takes name (string) which is a slash-separated path valid for fs.FS.
//
// Returns fs.File which is the opened file.
// Returns error when the sandbox is closed, the name is invalid or refused, or the
// backing file system fails.
func (f *sandboxFS) Open(name string) (fs.File, error) {
	if err := f.check("open", name); err != nil {
		return nil, err
	}
	if f.open == nil {
		return f.fsys.Open(name)
	}
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}

	file, err := f.open(filepath.FromSlash(name))
	if err != nil {
		return nil, err
	}
	return file.file, nil
}

// Stat returns information about the named file, following symbolic links.
//
// Takes name (string) which is a slash-separated path valid for fs.FS.
//
// Returns fs.FileInfo which describes the file.
// Returns error when the sandbox is closed, the path is refused, or the backing file
// system fails.
func (f *sandboxFS) Stat(name string) (fs.FileInfo, error) {
	if err := f.checkPath("stat", name, true); err != nil {
		return nil, err
	}
	return fs.Stat(f.fsys, name)
}

// ReadFile reads the named file in full.
//
// Takes name (string) which is a slash-separated path valid for fs.FS.
//
// Returns []byte which holds the file's contents.
// Returns error when the sandbox is closed, the file is refused, or the backing file
// system fails.
func (f *sandboxFS) ReadFile(name string) ([]byte, error) {
	if err := f.check("readfile", name); err != nil {
		return nil, err
	}
	if f.open != nil {
		return fs.ReadFile(openOnlyFS{fsys: f}, name)
	}
	return fs.ReadFile(f.fsys, name)
}

// ReadDir reads the named directory, sorted by file name.
//
// Takes name (string) which is a slash-separated path valid for fs.FS.
//
// Returns []fs.DirEntry which holds the directory's entries.
// Returns error when the sandbox is closed, the path is refused, or the backing file
// system fails.
func (f *sandboxFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if err := f.checkPath("readdir", name, true); err != nil {
		return nil, err
	}
	return fs.ReadDir(f.fsys, name)
}

// ReadLink returns the stored target of the named symbolic link.
//
// Takes name (string) which is a slash-separated path valid for fs.FS.
//
// Returns string which is the link's target, unresolved.
// Returns error when the sandbox is closed, the path is refused, or the backing file
// system fails.
func (f *sandboxFS) ReadLink(name string) (string, error) {
	if err := f.checkPath("readlink", name, false); err != nil {
		return "", err
	}
	return fs.ReadLink(f.fsys, name)
}

// Lstat returns information about the named file without following a final symbolic
// link.
//
// Takes name (string) which is a slash-separated path valid for fs.FS.
//
// Returns fs.FileInfo which describes the file.
// Returns error when the sandbox is closed, the path is refused, or the backing file
// system fails.
func (f *sandboxFS) Lstat(name string) (fs.FileInfo, error) {
	if err := f.checkPath("lstat", name, false); err != nil {
		return nil, err
	}
	return fs.Lstat(f.fsys, name)
}

// check refuses a call once the owning sandbox is closed.
//
// Takes op (string) which names the operation for the error.
// Takes name (string) which is the path for the error.
//
// Returns error which is a *fs.PathError wrapping ErrClosed, or nil while the sandbox is
// open.
func (f *sandboxFS) check(op, name string) error {
	if err := f.checkClosed(); err != nil {
		return &fs.PathError{Op: op, Path: name, Err: err}
	}
	return nil
}

// checkPath refuses a call once the sandbox is closed, or when a valid name passes
// through a symbolic link the sandbox refuses. Invalid names are left for the backing
// file system to reject.
//
// Takes op (string) which names the operation for the error.
// Takes name (string) which is a slash-separated path.
// Takes followFinal (bool) which is true when the call follows a final symbolic link.
//
// Returns error wrapping ErrClosed or ErrSymlinkNotAllowed, or nil.
func (f *sandboxFS) checkPath(op, name string, followFinal bool) error {
	if err := f.check(op, name); err != nil {
		return err
	}
	if !fs.ValidPath(name) {
		return nil
	}
	return f.policy.checkPath(filepath.FromSlash(name), followFinal)
}

// Open opens the named file through the sandbox view.
//
// Takes name (string) which is a slash-separated path valid for fs.FS.
//
// Returns fs.File which is the opened file.
// Returns error when sandboxFS.Open fails.
func (o openOnlyFS) Open(name string) (fs.File, error) {
	return o.fsys.Open(name)
}

// newSandboxFS builds the fs.FS returned by Sandbox.FS.
//
// Takes fsys (fs.FS) which is the backing file system.
// Takes checkClosed (func() error) which reports a closed sandbox.
// Takes options (sandboxOptions) which are the sandbox's settings.
// Takes policy (openPolicy) which checks paths for the sandbox.
// Takes open (func(string) (*File, error)) which opens a file through the sandbox.
//
// Returns fs.FS which uses fsys directly when no option is set, so that the default view
// is unchanged, and opens through the sandbox otherwise.
func newSandboxFS(
	fsys fs.FS,
	checkClosed func() error,
	options sandboxOptions,
	policy openPolicy,
	open func(name string) (*File, error),
) fs.FS {
	view := &sandboxFS{fsys: fsys, checkClosed: checkClosed, open: nil, policy: policy}
	if options.requireSingleLink || options.noSymlinks {
		view.open = open
	}
	return view
}
