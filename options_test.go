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
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type optionConstructor struct {
	name string
	create func(directory string, mode Mode, options ...Option) (Sandbox, error)
}

func optionConstructors() []optionConstructor {
	return []optionConstructor{
		{name: "os", create: NewSandboxWithOptions},
		{name: "noop", create: NewNoOpSandboxWithOptions},
	}
}

func linkTree(t *testing.T) string {
	t.Helper()

	directory := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(directory, "single.txt"), []byte("single"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(directory, "linked.txt"), []byte("linked"), 0o600))
	require.NoError(t, os.Link(filepath.Join(directory, "linked.txt"), filepath.Join(directory, "alias.txt")))
	require.NoError(t, os.Mkdir(filepath.Join(directory, "dir"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(directory, "dir", "b.txt"), []byte("b"), 0o600))
	return directory
}

func symlinkTree(t *testing.T) string {
	t.Helper()

	directory := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	require.NoError(t, os.WriteFile(outside, []byte("outside"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(directory, "a.txt"), []byte("a"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(directory, "dir"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(directory, "dir", "b.txt"), []byte("b"), 0o600))
	require.NoError(t, os.Symlink("a.txt", filepath.Join(directory, "to-a")))
	require.NoError(t, os.Symlink(outside, filepath.Join(directory, "to-outside")))
	require.NoError(t, os.Symlink("dir", filepath.Join(directory, "dirlink")))
	return directory
}

func assertMultipleLinks(t *testing.T, err error) {
	t.Helper()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMultipleLinks)
	assert.ErrorIs(t, err, fs.ErrPermission)
}

func assertSymlinkRefused(t *testing.T, err error, what string) {
	t.Helper()

	require.Error(t, err, what)
	assert.ErrorIs(t, err, ErrSymlinkNotAllowed, what)
	assert.ErrorIs(t, err, fs.ErrPermission, what)
}

func TestOptions_DefaultsAreOff(t *testing.T) {
	t.Parallel()

	for _, constructor := range sandboxConstructors() {
		t.Run(constructor.name, func(t *testing.T) {
			t.Parallel()

			directory := linkTree(t)
			require.NoError(t, os.Symlink("single.txt", filepath.Join(directory, "to-single")))
			require.NoError(t, os.Symlink("dir", filepath.Join(directory, "dirlink")))

			sandbox, err := constructor.create(directory, ModeReadWrite)
			require.NoError(t, err)
			defer func() { _ = sandbox.Close() }()

			content, err := sandbox.ReadFile("alias.txt")
			require.NoError(t, err, "hard links are read by default")
			assert.Equal(t, "linked", string(content))

			content, err = sandbox.ReadFile("to-single")
			require.NoError(t, err, "symbolic links inside are followed by default")
			assert.Equal(t, "single", string(content))

			content, err = sandbox.ReadFile("dirlink/b.txt")
			require.NoError(t, err)
			assert.Equal(t, "b", string(content))

			require.NoError(t, sandbox.Symlink("single.txt", "new-link"))
			require.NoError(t, sandbox.Link("single.txt", "new-hard"))
			require.NoError(t, sandbox.WriteFile("alias.txt", []byte("rewritten"), 0o600))

			content, err = fs.ReadFile(sandbox.FS(), "to-single")
			require.NoError(t, err)
			assert.Equal(t, "single", string(content))
		})
	}

	factory, err := NewFactory(FactoryConfig{CWD: t.TempDir(), Enabled: true})
	require.NoError(t, err)
	impl, ok := factory.(*factoryImpl)
	require.True(t, ok)
	assert.Empty(t, impl.sandboxOptions())
	assert.Equal(t, sandboxOptions{}, applyOptions(nil))
	assert.Equal(t, sandboxOptions{}, applyOptions([]Option{nil}))
}

func TestOptions_RequireSingleLink_RefusesHardLinks(t *testing.T) {
	t.Parallel()

	for _, constructor := range optionConstructors() {
		t.Run(constructor.name, func(t *testing.T) {
			t.Parallel()

			directory := linkTree(t)
			sandbox, err := constructor.create(directory, ModeReadWrite, WithRequireSingleLink())
			require.NoError(t, err)
			defer func() { _ = sandbox.Close() }()

			for _, name := range []string{"linked.txt", "alias.txt"} {
				_, err = sandbox.Open(name)
				assertMultipleLinks(t, err)
				_, err = sandbox.ReadFile(name)
				assertMultipleLinks(t, err)
				_, _, err = sandbox.ReadFileLimit(name, 100)
				assertMultipleLinks(t, err)
				_, err = sandbox.OpenFile(name, os.O_RDWR|os.O_TRUNC, 0)
				assertMultipleLinks(t, err)
				_, err = sandbox.Create(name)
				assertMultipleLinks(t, err)
				assertMultipleLinks(t, sandbox.WriteFile(name, []byte("x"), 0o600))
				assertMultipleLinks(t, sandbox.Chmod(name, 0o644))
				_, err = fs.ReadFile(sandbox.FS(), name)
				assertMultipleLinks(t, err)
				_, err = sandbox.FS().Open(name)
				assertMultipleLinks(t, err)
			}

			content, err := os.ReadFile(filepath.Join(directory, "linked.txt"))
			require.NoError(t, err)
			assert.Equal(t, "linked", string(content), "a refused truncating open must not truncate")

			assertMultipleLinks(t, sandbox.Link("single.txt", "second.txt"))
			_, statErr := os.Lstat(filepath.Join(directory, "second.txt"))
			assert.True(t, os.IsNotExist(statErr))

			content, err = sandbox.ReadFile("single.txt")
			require.NoError(t, err)
			assert.Equal(t, "single", string(content))
			entries, err := sandbox.ReadDir("dir")
			require.NoError(t, err, "directories always have several links and are allowed")
			assert.Len(t, entries, 1)
		})
	}
}

func TestOptions_RequireSingleLink_TruncatesAfterCheck(t *testing.T) {
	t.Parallel()

	for _, constructor := range optionConstructors() {
		t.Run(constructor.name, func(t *testing.T) {
			t.Parallel()

			directory := linkTree(t)
			sandbox, err := constructor.create(directory, ModeReadWrite, WithRequireSingleLink())
			require.NoError(t, err)
			defer func() { _ = sandbox.Close() }()

			require.NoError(t, sandbox.WriteFile("single.txt", []byte("new"), 0o600))
			content, err := sandbox.ReadFile("single.txt")
			require.NoError(t, err)
			assert.Equal(t, "new", string(content), "the old content is truncated")

			handle, err := sandbox.Create("created.txt")
			require.NoError(t, err)
			require.NoError(t, handle.Close())

			require.NoError(t, sandbox.WriteFileAtomic("atomic.txt", []byte("atomic"), 0o600))
			content, err = sandbox.ReadFile("atomic.txt")
			require.NoError(t, err)
			assert.Equal(t, "atomic", string(content))
		})
	}
}

func TestOptions_RequireSingleLink_HardLinkToOutsideFile(t *testing.T) {
	t.Parallel()

	sandboxDirectory := t.TempDir()
	outsideFile := filepath.Join(t.TempDir(), "secret.txt")
	require.NoError(t, os.WriteFile(outsideFile, []byte("outside"), 0o600))
	if err := os.Link(outsideFile, filepath.Join(sandboxDirectory, "planted.txt")); err != nil {
		t.Skipf("this filesystem does not allow the hard link: %v", err)
	}

	unprotected, err := NewSandbox(sandboxDirectory, ModeReadWrite)
	require.NoError(t, err)
	defer func() { _ = unprotected.Close() }()
	content, err := unprotected.ReadFile("planted.txt")
	require.NoError(t, err, "os.Root alone cannot see that the file is also outside")
	assert.Equal(t, "outside", string(content))

	for _, constructor := range optionConstructors() {
		sandbox, err := constructor.create(sandboxDirectory, ModeReadWrite, WithRequireSingleLink())
		require.NoError(t, err)

		_, err = sandbox.ReadFile("planted.txt")
		assertMultipleLinks(t, err)
		assertMultipleLinks(t, sandbox.WriteFile("planted.txt", []byte("overwritten"), 0o600))
		_, err = fs.ReadFile(sandbox.FS(), "planted.txt")
		assertMultipleLinks(t, err)
		require.NoError(t, sandbox.Close())
	}

	content, err = os.ReadFile(outsideFile)
	require.NoError(t, err)
	assert.Equal(t, "outside", string(content), "the outside file must be untouched")
}

func TestOptions_LinkCount(t *testing.T) {
	t.Parallel()

	directory := linkTree(t)
	for name, want := range map[string]uint64{"single.txt": 1, "linked.txt": 2} {
		file, err := os.Open(filepath.Join(directory, name))
		require.NoError(t, err)
		info, err := file.Stat()
		require.NoError(t, err)
		count, known := linkCount(file, info)
		require.True(t, known)
		assert.Equal(t, want, count, name)
		require.NoError(t, file.Close())
	}
}

func TestOptions_NoSymlinks_RefusesEveryRoute(t *testing.T) {
	t.Parallel()

	for _, constructor := range optionConstructors() {
		t.Run(constructor.name, func(t *testing.T) {
			t.Parallel()

			directory := symlinkTree(t)
			sandbox, err := constructor.create(directory, ModeReadWrite, WithNoSymlinks())
			require.NoError(t, err)
			defer func() { _ = sandbox.Close() }()

			for _, name := range []string{"to-a", "to-outside", "dirlink/b.txt"} {
				_, err = sandbox.Open(name)
				assertSymlinkRefused(t, err, "Open "+name)
				_, err = sandbox.ReadFile(name)
				assertSymlinkRefused(t, err, "ReadFile "+name)
				_, err = sandbox.Stat(name)
				assertSymlinkRefused(t, err, "Stat "+name)
				_, err = sandbox.OpenFile(name, os.O_RDWR, 0)
				assertSymlinkRefused(t, err, "OpenFile "+name)
				assertSymlinkRefused(t, sandbox.WriteFile(name, []byte("x"), 0o600), "WriteFile "+name)
				assertSymlinkRefused(t, sandbox.Chmod(name, 0o644), "Chmod "+name)
				assertSymlinkRefused(t, sandbox.Chtimes(name, time.Now(), time.Now()), "Chtimes "+name)
				assertSymlinkRefused(t, sandbox.Chown(name, -1, -1), "Chown "+name)
			}

			when := time.Now()
			middle := map[string]error{
				"Lstat":           second(sandbox.Lstat("dirlink/b.txt")),
				"Readlink":        second(sandbox.Readlink("dirlink/b.txt")),
				"Lchown":          sandbox.Lchown("dirlink/b.txt", -1, -1),
				"Remove":          sandbox.Remove("dirlink/b.txt"),
				"RemoveAll":       sandbox.RemoveAll("dirlink/b.txt"),
				"Rename from":     sandbox.Rename("dirlink/b.txt", "moved.txt"),
				"Rename to":       sandbox.Rename("a.txt", "dirlink/moved.txt"),
				"Mkdir":           sandbox.Mkdir("dirlink/new", 0o750),
				"MkdirAll":        sandbox.MkdirAll("dirlink/new/deeper", 0o750),
				"ReadDir":         second(sandbox.ReadDir("dirlink")),
				"WalkDir":         sandbox.WalkDir("dirlink/b.txt", func(string, fs.DirEntry, error) error { return nil }),
				"CreateTemp":      second(sandbox.CreateTemp("dirlink", "tmp-*")),
				"MkdirTemp":       second(sandbox.MkdirTemp("dirlink", "tmp-*")),
				"WriteFileAtomic": sandbox.WriteFileAtomic("dirlink/new.txt", []byte("x"), 0o600),
				"Link":            sandbox.Link("dirlink/b.txt", "hard.txt"),
				"Chtimes":         sandbox.Chtimes("dirlink/b.txt", when, when),
				"OpenRoot":        second(sandbox.OpenRoot("dirlink", ModeReadOnly)),
				"Symlink":         sandbox.Symlink("a.txt", "new-link"),
			}
			for what, err := range middle {
				assertSymlinkRefused(t, err, what)
			}

			content, err := os.ReadFile(filepath.Join(directory, "dir", "b.txt"))
			require.NoError(t, err)
			assert.Equal(t, "b", string(content), "nothing reached through the link may change")
			_, statErr := os.Lstat(filepath.Join(directory, "new-link"))
			assert.True(t, os.IsNotExist(statErr), "Symlink is refused in this mode")

			info, err := sandbox.Lstat("to-a")
			require.NoError(t, err, "Lstat names the link itself")
			assert.Equal(t, fs.ModeSymlink, info.Mode().Type())
			target, err := sandbox.Readlink("to-a")
			require.NoError(t, err)
			assert.Equal(t, "a.txt", target)
			require.NoError(t, sandbox.Lchown("to-a", -1, -1))
			require.NoError(t, sandbox.Rename("to-a", "renamed-link"))
			require.NoError(t, sandbox.Remove("renamed-link"))

			content, err = sandbox.ReadFile("dir/b.txt")
			require.NoError(t, err, "paths without links still work")
			assert.Equal(t, "b", string(content))
			require.NoError(t, sandbox.WriteFileAtomic("dir/c.txt", []byte("c"), 0o600))
			require.NoError(t, sandbox.MkdirAll("dir/x/y", 0o750))
		})
	}
}

func TestOptions_SubSandboxesInherit(t *testing.T) {
	t.Parallel()

	for _, constructor := range optionConstructors() {
		t.Run(constructor.name, func(t *testing.T) {
			t.Parallel()

			directory := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(directory, "child", "dir"), 0o750))
			child := filepath.Join(directory, "child")
			require.NoError(t, os.WriteFile(filepath.Join(child, "a.txt"), []byte("a"), 0o600))
			require.NoError(t, os.Link(filepath.Join(child, "a.txt"), filepath.Join(child, "alias.txt")))
			require.NoError(t, os.WriteFile(filepath.Join(child, "dir", "b.txt"), []byte("b"), 0o600))
			require.NoError(t, os.Symlink("dir", filepath.Join(child, "dirlink")))

			sandbox, err := constructor.create(directory, ModeReadWrite, WithRequireSingleLink(), WithNoSymlinks())
			require.NoError(t, err)
			defer func() { _ = sandbox.Close() }()

			sub, err := sandbox.OpenRoot("child", ModeReadWrite)
			require.NoError(t, err)
			defer func() { _ = sub.Close() }()

			_, err = sub.ReadFile("alias.txt")
			assertMultipleLinks(t, err)
			_, err = sub.ReadFile("dirlink/b.txt")
			assertSymlinkRefused(t, err, "sub-sandbox read through a symlinked directory")
			_, err = fs.ReadFile(sub.FS(), "dirlink/b.txt")
			assertSymlinkRefused(t, err, "sub-sandbox FS")
			assertSymlinkRefused(t, sub.Symlink("dir/b.txt", "new-link"), "sub-sandbox Symlink")

			grandchild, err := sub.OpenRoot("dir", ModeReadOnly)
			require.NoError(t, err)
			defer func() { _ = grandchild.Close() }()
			content, err := grandchild.ReadFile("b.txt")
			require.NoError(t, err)
			assert.Equal(t, "b", string(content))
		})
	}
}

func TestOptions_FS(t *testing.T) {
	t.Parallel()

	for _, constructor := range optionConstructors() {
		t.Run(constructor.name, func(t *testing.T) {
			t.Parallel()

			clean := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(clean, "a.txt"), []byte("a"), 0o600))
			require.NoError(t, os.MkdirAll(filepath.Join(clean, "dir", "sub"), 0o750))
			require.NoError(t, os.WriteFile(filepath.Join(clean, "dir", "sub", "c.txt"), []byte("c"), 0o600))

			sandbox, err := constructor.create(clean, ModeReadOnly, WithRequireSingleLink(), WithNoSymlinks())
			require.NoError(t, err)
			require.NoError(t, fstest.TestFS(sandbox.FS(), "a.txt", "dir/sub/c.txt"))
			require.NoError(t, sandbox.Close())

			directory := symlinkTree(t)
			require.NoError(t, os.Link(filepath.Join(directory, "a.txt"), filepath.Join(directory, "hard.txt")))
			sandbox, err = constructor.create(directory, ModeReadOnly, WithRequireSingleLink(), WithNoSymlinks())
			require.NoError(t, err)
			defer func() { _ = sandbox.Close() }()
			fsys := sandbox.FS()

			for _, name := range []string{"to-a", "to-outside", "dirlink/b.txt"} {
				_, err = fs.ReadFile(fsys, name)
				assertSymlinkRefused(t, err, "ReadFile "+name)
				_, err = fsys.Open(name)
				assertSymlinkRefused(t, err, "Open "+name)
				_, err = fs.Stat(fsys, name)
				assertSymlinkRefused(t, err, "Stat "+name)
			}
			_, err = fs.ReadDir(fsys, "dirlink")
			assertSymlinkRefused(t, err, "ReadDir dirlink")
			_, err = fs.Lstat(fsys, "dirlink/b.txt")
			assertSymlinkRefused(t, err, "Lstat dirlink/b.txt")
			_, err = fs.ReadLink(fsys, "dirlink/b.txt")
			assertSymlinkRefused(t, err, "ReadLink dirlink/b.txt")

			_, err = fs.ReadFile(fsys, "hard.txt")
			assertMultipleLinks(t, err)

			target, err := fs.ReadLink(fsys, "to-a")
			require.NoError(t, err)
			assert.Equal(t, "a.txt", target)
			_, err = fs.ReadFile(fsys, "../a.txt")
			assert.ErrorIs(t, err, fs.ErrInvalid)
		})
	}
}

func TestOptions_Factory(t *testing.T) {
	t.Parallel()

	for _, enabled := range []bool{true, false} {
		directory := linkTree(t)
		require.NoError(t, os.Symlink("single.txt", filepath.Join(directory, "to-single")))

		factory, err := NewFactory(FactoryConfig{CWD: directory, Enabled: enabled, RequireSingleLink: true, NoSymlinks: true})
		require.NoError(t, err)
		sandbox, err := factory.Create("locked", directory, ModeReadOnly)
		require.NoError(t, err)

		_, err = sandbox.ReadFile("alias.txt")
		assertMultipleLinks(t, err)
		_, err = sandbox.ReadFile("to-single")
		assertSymlinkRefused(t, err, "factory sandbox")
		require.NoError(t, sandbox.Close())
	}
}

func TestOptions_VerifyOpenedPath(t *testing.T) {
	t.Parallel()

	directory := symlinkTree(t)
	root, err := os.OpenRoot(directory)
	require.NoError(t, err)
	defer func() { _ = root.Close() }()
	policy := openPolicy{lstat: root.Lstat, options: sandboxOptions{noSymlinks: true}}

	file, err := root.Open("a.txt")
	require.NoError(t, err)
	defer func() { _ = file.Close() }()

	require.NoError(t, policy.verifyOpenedPath("a.txt", file))
	assert.ErrorIs(t, policy.verifyOpenedPath("to-a", file), ErrSymlinkNotAllowed,
		"a path that became a symbolic link after the open is refused")
	assert.ErrorIs(t, policy.verifyOpenedPath(filepath.Join("dir", "b.txt"), file), ErrSymlinkNotAllowed,
		"a path that names a different file from the one opened is refused")
	assert.ErrorIs(t, policy.verifyOpenedPath("missing", file), fs.ErrNotExist)
	require.NoError(t, policy.verifyOpenedPath(".", file))
}

func TestOptions_Errors(t *testing.T) {
	t.Parallel()

	assert.ErrorIs(t, ErrMultipleLinks, fs.ErrPermission)
	assert.ErrorIs(t, ErrSymlinkNotAllowed, fs.ErrPermission)
	assert.False(t, errors.Is(ErrMultipleLinks, ErrSymlinkNotAllowed))
	assert.False(t, IsEscape(ErrSymlinkNotAllowed))
	assert.Equal(t, "safedisk: file has more than one hard link", ErrMultipleLinks.Error())
	assert.Equal(t, "safedisk: symbolic links are not allowed in this sandbox", ErrSymlinkNotAllowed.Error())
}

func second[T any](_ T, err error) error {
	return err
}
