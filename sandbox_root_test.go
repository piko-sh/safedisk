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
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type escapeFixture struct {
	sandboxDirectory string
	outsideDirectory string
	outsideFile string
}

func newEscapeFixture(t *testing.T) escapeFixture {
	t.Helper()

	fixture := escapeFixture{
		sandboxDirectory: t.TempDir(),
		outsideDirectory: t.TempDir(),
	}
	fixture.outsideFile = filepath.Join(fixture.outsideDirectory, "secret.txt")
	require.NoError(t, os.WriteFile(fixture.outsideFile, []byte("outside"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(fixture.sandboxDirectory, "inside.txt"), []byte("inside"), 0o600))
	require.NoError(t, os.Symlink(fixture.outsideDirectory, filepath.Join(fixture.sandboxDirectory, "out")))
	return fixture
}

func (f escapeFixture) open(t *testing.T, mode Mode) Sandbox {
	t.Helper()

	sandbox, err := NewSandbox(f.sandboxDirectory, mode)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sandbox.Close() })
	return sandbox
}

func (f escapeFixture) requireOutsideUntouched(t *testing.T, names ...string) {
	t.Helper()

	content, err := os.ReadFile(f.outsideFile)
	require.NoError(t, err)
	require.Equal(t, "outside", string(content))

	for _, name := range names {
		_, err := os.Lstat(filepath.Join(f.outsideDirectory, name))
		require.True(t, os.IsNotExist(err), "%q must not appear outside the sandbox", name)
	}
	_, err = os.Lstat(filepath.Join(filepath.Dir(f.sandboxDirectory), "escaped"))
	require.True(t, os.IsNotExist(err), "nothing may appear beside the sandbox")
}

func TestOSSandbox_Symlink(t *testing.T) {
	t.Parallel()

	fixture := newEscapeFixture(t)
	sandbox := fixture.open(t, ModeReadWrite)

	require.NoError(t, sandbox.Symlink("inside.txt", "relative-link"))
	content, err := sandbox.ReadFile("relative-link")
	require.NoError(t, err)
	assert.Equal(t, "inside", string(content))

	target, err := sandbox.Readlink("relative-link")
	require.NoError(t, err)
	assert.Equal(t, "inside.txt", target)
}

func TestOSSandbox_Symlink_LinkLocationIsConfined(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		newname string
	}{
		{name: "parent", newname: "../escaped"},
		{name: "nested parent", newname: "a/../../escaped"},
		{name: "through symlinked directory", newname: "out/escaped"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fixture := newEscapeFixture(t)
			sandbox := fixture.open(t, ModeReadWrite)

			err := sandbox.Symlink("inside.txt", tc.newname)
			require.Error(t, err)
			assert.True(t, IsEscape(err), "want an escape error, got %v", err)
			fixture.requireOutsideUntouched(t, "escaped")
		})
	}
}

func TestOSSandbox_Symlink_AbsoluteNameStaysInside(t *testing.T) {
	t.Parallel()

	fixture := newEscapeFixture(t)
	sandbox := fixture.open(t, ModeReadWrite)

	require.NoError(t, sandbox.Symlink("inside.txt", "/absolute-link"))

	info, err := os.Lstat(filepath.Join(fixture.sandboxDirectory, "absolute-link"))
	require.NoError(t, err)
	assert.Equal(t, fs.ModeSymlink, info.Mode().Type())
}

func TestOSSandbox_Symlink_TargetOutsideIsStoredButNotFollowed(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		target func(escapeFixture) string
	}{
		{name: "absolute target", target: func(f escapeFixture) string { return f.outsideFile }},
		{name: "relative parent target", target: func(f escapeFixture) string {
			relative, err := filepath.Rel(f.sandboxDirectory, f.outsideFile)
			if err != nil {
				panic(err)
			}
			return relative
		}},
		{name: "target through symlinked directory", target: func(escapeFixture) string { return "out/secret.txt" }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fixture := newEscapeFixture(t)
			sandbox := fixture.open(t, ModeReadWrite)
			target := tc.target(fixture)

			require.NoError(t, sandbox.Symlink(target, "planted"))

			stored, err := sandbox.Readlink("planted")
			require.NoError(t, err)
			assert.Equal(t, target, stored, "the target is stored unresolved")

			_, err = sandbox.ReadFile("planted")
			require.Error(t, err)
			assert.True(t, IsEscape(err), "reading through the link must be refused, got %v", err)

			err = sandbox.WriteFile("planted", []byte("overwritten"), 0o600)
			require.Error(t, err)
			assert.True(t, IsEscape(err), "writing through the link must be refused, got %v", err)

			_, err = fs.ReadFile(sandbox.FS(), "planted")
			require.Error(t, err)

			fixture.requireOutsideUntouched(t)
		})
	}
}

func TestOSSandbox_Link(t *testing.T) {
	t.Parallel()

	fixture := newEscapeFixture(t)
	sandbox := fixture.open(t, ModeReadWrite)

	require.NoError(t, sandbox.Link("inside.txt", "hard.txt"))

	original, err := sandbox.Stat("inside.txt")
	require.NoError(t, err)
	linked, err := sandbox.Stat("hard.txt")
	require.NoError(t, err)
	assert.True(t, os.SameFile(original, linked))
}

func TestOSSandbox_Link_EscapesAreRefused(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		oldname string
		newname string
		created string
	}{
		{name: "new name in parent", oldname: "inside.txt", newname: "../escaped"},
		{name: "new name through symlinked directory", oldname: "inside.txt", newname: "out/escaped", created: "escaped"},
		{name: "old name in parent", oldname: "../outside.txt", newname: "stolen"},
		{name: "old name through symlinked directory", oldname: "out/secret.txt", newname: "stolen"},
		{name: "old name nested parent", oldname: "a/../../secret.txt", newname: "stolen"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fixture := newEscapeFixture(t)
			sandbox := fixture.open(t, ModeReadWrite)

			err := sandbox.Link(tc.oldname, tc.newname)
			require.Error(t, err)
			assert.True(t, IsEscape(err), "want an escape error, got %v", err)

			if tc.created != "" {
				fixture.requireOutsideUntouched(t, tc.created)
			} else {
				fixture.requireOutsideUntouched(t)
			}
			_, statErr := os.Lstat(filepath.Join(fixture.sandboxDirectory, "stolen"))
			assert.True(t, os.IsNotExist(statErr), "no link to an outside file may appear inside")
		})
	}
}

func TestOSSandbox_Readlink_EscapesAreRefused(t *testing.T) {
	t.Parallel()

	fixture := newEscapeFixture(t)
	require.NoError(t, os.Symlink("anywhere", filepath.Join(fixture.outsideDirectory, "outside-link")))
	sandbox := fixture.open(t, ModeReadOnly)

	for _, name := range []string{"../outside-link", "out/outside-link", "a/../../outside-link"} {
		_, err := sandbox.Readlink(name)
		require.Error(t, err, name)
		assert.True(t, IsEscape(err), "%q: want an escape error, got %v", name, err)
	}

	target, err := sandbox.Readlink("out")
	require.NoError(t, err, "the link itself lives inside the sandbox")
	assert.Equal(t, fixture.outsideDirectory, target)
}

func TestOSSandbox_Chtimes(t *testing.T) {
	t.Parallel()

	fixture := newEscapeFixture(t)
	sandbox := fixture.open(t, ModeReadWrite)
	when := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)

	require.NoError(t, sandbox.Chtimes("inside.txt", when, when))

	info, err := sandbox.Stat("inside.txt")
	require.NoError(t, err)
	assert.True(t, info.ModTime().Equal(when))
}

func TestOSSandbox_Chtimes_EscapesAreRefused(t *testing.T) {
	t.Parallel()

	fixture := newEscapeFixture(t)
	require.NoError(t, os.Symlink(fixture.outsideFile, filepath.Join(fixture.sandboxDirectory, "to-secret")))
	before, err := os.Stat(fixture.outsideFile)
	require.NoError(t, err)

	sandbox := fixture.open(t, ModeReadWrite)
	when := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)

	for _, name := range []string{"../secret.txt", "out/secret.txt", "to-secret", "a/../../secret.txt"} {
		err := sandbox.Chtimes(name, when, when)
		require.Error(t, err, name)
		assert.True(t, IsEscape(err), "%q: want an escape error, got %v", name, err)
	}

	after, err := os.Stat(fixture.outsideFile)
	require.NoError(t, err)
	assert.True(t, before.ModTime().Equal(after.ModTime()), "the outside file's times must not change")
}

func TestOSSandbox_Lchown(t *testing.T) {
	t.Parallel()

	fixture := newEscapeFixture(t)
	sandbox := fixture.open(t, ModeReadWrite)

	require.NoError(t, sandbox.Lchown("inside.txt", -1, -1))
	require.NoError(t, sandbox.Lchown("out", -1, -1), "Lchown acts on the link inside, not its target")

	for _, name := range []string{"../secret.txt", "out/secret.txt", "a/../../secret.txt"} {
		err := sandbox.Lchown(name, -1, -1)
		require.Error(t, err, name)
		assert.True(t, IsEscape(err), "%q: want an escape error, got %v", name, err)
	}
}

func TestOSSandbox_Chown(t *testing.T) {
	t.Parallel()

	fixture := newEscapeFixture(t)
	require.NoError(t, os.Symlink("inside.txt", filepath.Join(fixture.sandboxDirectory, "to-inside")))
	require.NoError(t, os.Symlink(fixture.outsideFile, filepath.Join(fixture.sandboxDirectory, "to-secret")))
	sandbox := fixture.open(t, ModeReadWrite)

	require.NoError(t, sandbox.Chown("inside.txt", -1, -1))
	require.NoError(t, sandbox.Chown("to-inside", -1, -1), "a link that stays inside is followed")
	require.NoError(t, sandbox.Chown("inside.txt", os.Getuid(), os.Getgid()))

	for _, name := range []string{"../secret.txt", "out/secret.txt", "to-secret", "a/../../secret.txt"} {
		err := sandbox.Chown(name, -1, -1)
		require.Error(t, err, name)
		assert.True(t, IsEscape(err), "%q: want an escape error, got %v", name, err)
	}
}

func TestNoOpSandbox_Chown(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	sandbox, err := NewNoOpSandbox(directory, ModeReadWrite)
	require.NoError(t, err)
	defer func() { _ = sandbox.Close() }()
	require.NoError(t, sandbox.WriteFile("a.txt", []byte("a"), 0o600))

	require.NoError(t, sandbox.Chown("a.txt", -1, -1))
	err = sandbox.Chown("../a.txt", -1, -1)
	require.Error(t, err)
	assert.True(t, IsEscape(err))
}

func TestOSSandbox_OpenRoot(t *testing.T) {
	t.Parallel()

	fixture := newEscapeFixture(t)
	sandbox := fixture.open(t, ModeReadWrite)
	require.NoError(t, sandbox.MkdirAll("child/nested", 0o750))
	require.NoError(t, sandbox.WriteFile("child/nested/file.txt", []byte("data"), 0o600))

	child, err := sandbox.OpenRoot("child", ModeReadWrite)
	require.NoError(t, err)
	t.Cleanup(func() { _ = child.Close() })

	assert.Equal(t, filepath.Join(fixture.sandboxDirectory, "child"), child.Root())
	assert.Equal(t, ModeReadWrite, child.Mode())
	assert.False(t, child.IsNoOp())

	content, err := child.ReadFile("nested/file.txt")
	require.NoError(t, err)
	assert.Equal(t, "data", string(content))

	require.NoError(t, child.WriteFile("written.txt", []byte("from child"), 0o600))
	content, err = sandbox.ReadFile("child/written.txt")
	require.NoError(t, err)
	assert.Equal(t, "from child", string(content))
}

func TestOSSandbox_OpenRoot_EscapesAreRefused(t *testing.T) {
	t.Parallel()

	fixture := newEscapeFixture(t)
	sandbox := fixture.open(t, ModeReadWrite)

	for _, directory := range []string{"..", "../..", "out", "a/../.."} {
		child, err := sandbox.OpenRoot(directory, ModeReadOnly)
		require.Error(t, err, directory)
		assert.Nil(t, child)
		assert.True(t, IsEscape(err), "%q: want an escape error, got %v", directory, err)
	}

	child, err := sandbox.OpenRoot(fixture.outsideDirectory, ModeReadOnly)
	require.Error(t, err, "an absolute path is taken relative to the sandbox, where it does not exist")
	assert.Nil(t, child)
	assert.True(t, errors.Is(err, fs.ErrNotExist), "got %v", err)
}

func TestOSSandbox_OpenRoot_ChildCannotEscapeParent(t *testing.T) {
	t.Parallel()

	fixture := newEscapeFixture(t)
	sandbox := fixture.open(t, ModeReadWrite)
	require.NoError(t, sandbox.Mkdir("child", 0o750))
	require.NoError(t, os.Symlink("..", filepath.Join(fixture.sandboxDirectory, "child", "up")))
	require.NoError(t, os.Symlink(fixture.outsideDirectory, filepath.Join(fixture.sandboxDirectory, "child", "out")))

	child, err := sandbox.OpenRoot("child", ModeReadWrite)
	require.NoError(t, err)
	t.Cleanup(func() { _ = child.Close() })

	for _, name := range []string{"../inside.txt", "up/inside.txt", "out/secret.txt", "../out/secret.txt"} {
		_, err := child.ReadFile(name)
		require.Error(t, err, name)
		assert.True(t, IsEscape(err), "%q: want an escape error, got %v", name, err)
	}

	err = child.Rename("../inside.txt", "moved.txt")
	require.Error(t, err)
	assert.True(t, IsEscape(err))

	grandchild, err := child.OpenRoot("up", ModeReadOnly)
	require.Error(t, err)
	assert.Nil(t, grandchild)
	assert.True(t, IsEscape(err))

	_, err = sandbox.Stat("inside.txt")
	require.NoError(t, err, "the parent's file must be untouched")
	fixture.requireOutsideUntouched(t)
}

func TestOSSandbox_OpenRoot_CannotWidenMode(t *testing.T) {
	t.Parallel()

	fixture := newEscapeFixture(t)
	require.NoError(t, os.Mkdir(filepath.Join(fixture.sandboxDirectory, "child"), 0o750))

	readOnly := fixture.open(t, ModeReadOnly)
	child, err := readOnly.OpenRoot("child", ModeReadWrite)
	require.Error(t, err)
	assert.Nil(t, child)
	assert.ErrorIs(t, err, ErrReadOnly)

	readWrite := fixture.open(t, ModeReadWrite)
	narrowed, err := readWrite.OpenRoot("child", ModeReadOnly)
	require.NoError(t, err)
	t.Cleanup(func() { _ = narrowed.Close() })

	assert.True(t, narrowed.IsReadOnly())
	assert.ErrorIs(t, narrowed.WriteFile("file.txt", nil, 0o600), ErrReadOnly)

	sameMode, err := readOnly.OpenRoot("child", ModeReadOnly)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sameMode.Close() })
	assert.True(t, sameMode.IsReadOnly())
}

func TestOSSandbox_OpenRoot_Lifetime(t *testing.T) {
	t.Parallel()

	fixture := newEscapeFixture(t)
	sandbox, err := NewSandbox(fixture.sandboxDirectory, ModeReadWrite)
	require.NoError(t, err)
	require.NoError(t, sandbox.Mkdir("child", 0o750))

	child, err := sandbox.OpenRoot("child", ModeReadWrite)
	require.NoError(t, err)
	t.Cleanup(func() { _ = child.Close() })

	require.NoError(t, sandbox.Close())

	_, err = sandbox.OpenRoot("child", ModeReadOnly)
	assert.ErrorIs(t, err, ErrClosed)

	require.NoError(t, child.WriteFile("still-open.txt", []byte("ok"), 0o600), "the child has its own handle")
	require.NoError(t, child.Close())
	assert.ErrorIs(t, child.WriteFile("closed.txt", nil, 0o600), ErrClosed)
}

func TestOSSandbox_OpenRoot_NotADirectory(t *testing.T) {
	t.Parallel()

	fixture := newEscapeFixture(t)
	sandbox := fixture.open(t, ModeReadOnly)

	_, err := sandbox.OpenRoot("inside.txt", ModeReadOnly)
	require.Error(t, err)

	_, err = sandbox.OpenRoot("missing", ModeReadOnly)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestOSSandbox_FS_PassesTestFS(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	sandbox, err := NewSandbox(directory, ModeReadWrite)
	require.NoError(t, err)
	defer func() { _ = sandbox.Close() }()

	require.NoError(t, sandbox.WriteFile("a.txt", []byte("a"), 0o600))
	require.NoError(t, sandbox.MkdirAll("dir/sub", 0o750))
	require.NoError(t, sandbox.WriteFile("dir/b.txt", []byte("b"), 0o600))
	require.NoError(t, sandbox.WriteFile("dir/sub/c.txt", []byte("c"), 0o600))
	require.NoError(t, sandbox.Symlink("a.txt", "link"))

	require.NoError(t, fstest.TestFS(sandbox.FS(), "a.txt", "dir/b.txt", "dir/sub/c.txt", "link"))
}

func TestOSSandbox_FS_IsConfined(t *testing.T) {
	t.Parallel()

	fixture := newEscapeFixture(t)
	require.NoError(t, os.Symlink(fixture.outsideFile, filepath.Join(fixture.sandboxDirectory, "to-secret")))
	sandbox := fixture.open(t, ModeReadOnly)
	fsys := sandbox.FS()

	_, err := fs.ReadFile(fsys, "../secret.txt")
	assert.ErrorIs(t, err, fs.ErrInvalid, "fs.FS names may not contain ..")

	_, err = fs.ReadFile(fsys, "/etc/passwd")
	assert.ErrorIs(t, err, fs.ErrInvalid, "fs.FS names may not be rooted")

	for _, name := range []string{"out/secret.txt", "to-secret"} {
		_, err = fs.ReadFile(fsys, name)
		require.Error(t, err, name)
		assert.True(t, IsEscape(err), "%q: want an escape error, got %v", name, err)

		_, err = fs.Stat(fsys, name)
		require.Error(t, err, name)
		assert.True(t, IsEscape(err), "%q: want an escape error, got %v", name, err)
	}

	_, err = fs.ReadDir(fsys, "out")
	require.Error(t, err)
	assert.True(t, IsEscape(err), "got %v", err)

	target, err := fs.ReadLink(fsys, "out")
	require.NoError(t, err)
	assert.Equal(t, fixture.outsideDirectory, target)
}

func TestSandbox_FS_Closed(t *testing.T) {
	t.Parallel()

	for _, constructor := range sandboxConstructors() {
		t.Run(constructor.name, func(t *testing.T) {
			t.Parallel()

			directory := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(directory, "a.txt"), []byte("a"), 0o600))
			require.NoError(t, os.Symlink("a.txt", filepath.Join(directory, "link")))

			sandbox, err := constructor.create(directory, ModeReadOnly)
			require.NoError(t, err)
			fsys := sandbox.FS()
			require.NoError(t, sandbox.Close())

			_, err = fsys.Open("a.txt")
			assertClosed(t, err)
			_, err = fs.ReadFile(fsys, "a.txt")
			assertClosed(t, err)
			_, err = fs.Stat(fsys, "a.txt")
			assertClosed(t, err)
			_, err = fs.ReadDir(fsys, ".")
			assertClosed(t, err)
			_, err = fs.ReadLink(fsys, "link")
			assertClosed(t, err)
			_, err = fs.Lstat(fsys, "link")
			assertClosed(t, err)
		})
	}
}

func TestFile_OSFile(t *testing.T) {
	t.Parallel()

	for _, constructor := range sandboxConstructors() {
		t.Run(constructor.name, func(t *testing.T) {
			t.Parallel()

			directory := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(directory, "a.txt"), []byte("abc"), 0o600))

			sandbox, err := constructor.create(directory, ModeReadOnly)
			require.NoError(t, err)
			defer func() { _ = sandbox.Close() }()

			handle, err := sandbox.Open("a.txt")
			require.NoError(t, err)
			file, ok := handle.(*File)
			require.True(t, ok, "the sandbox returns *File")

			osFile := file.OSFile()
			require.NotNil(t, osFile)
			assert.Equal(t, handle.Fd(), osFile.Fd(), "the same open file is returned")

			buffer := make([]byte, 3)
			_, err = osFile.Read(buffer)
			require.NoError(t, err)
			assert.Equal(t, "abc", string(buffer))

			_, err = osFile.Write([]byte("x"))
			require.Error(t, err, "a file opened for reading stays read-only")

			require.NoError(t, osFile.Close())
			assert.Error(t, handle.Close(), "closing the *os.File closes the handle")

			content, err := os.ReadFile(filepath.Join(directory, "a.txt"))
			require.NoError(t, err)
			assert.Equal(t, "abc", string(content))
		})
	}

	assert.Nil(t, (&File{}).OSFile())
}

func TestSandbox_NewMethods_ReadOnly(t *testing.T) {
	t.Parallel()

	for _, constructor := range sandboxConstructors() {
		t.Run(constructor.name, func(t *testing.T) {
			t.Parallel()

			directory := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(directory, "a.txt"), []byte("a"), 0o600))
			require.NoError(t, os.Mkdir(filepath.Join(directory, "dir"), 0o750))

			sandbox, err := constructor.create(directory, ModeReadOnly)
			require.NoError(t, err)
			defer func() { _ = sandbox.Close() }()

			when := time.Now()
			assertReadOnly(t, sandbox.Symlink("a.txt", "link"))
			assertReadOnly(t, sandbox.Link("a.txt", "hard"))
			assertReadOnly(t, sandbox.Chtimes("a.txt", when, when))
			assertReadOnly(t, sandbox.Lchown("a.txt", -1, -1))
			assertReadOnly(t, sandbox.Chown("a.txt", -1, -1))
			_, err = sandbox.OpenRoot("dir", ModeReadWrite)
			assertReadOnly(t, err)

			entries, err := os.ReadDir(directory)
			require.NoError(t, err)
			assert.Len(t, entries, 2, "nothing may be created")

			_, err = sandbox.Readlink("a.txt")
			require.Error(t, err)
			assert.NotErrorIs(t, err, ErrReadOnly, "Readlink only reads")

			child, err := sandbox.OpenRoot("dir", ModeReadOnly)
			require.NoError(t, err)
			require.NoError(t, child.Close())
		})
	}
}

func TestSandbox_NewMethods_Closed(t *testing.T) {
	t.Parallel()

	for _, constructor := range sandboxConstructors() {
		for _, mode := range []Mode{ModeReadOnly, ModeReadWrite} {
			t.Run(constructor.name+"/"+mode.String(), func(t *testing.T) {
				t.Parallel()

				directory := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(directory, "a.txt"), []byte("a"), 0o600))
				require.NoError(t, os.Mkdir(filepath.Join(directory, "dir"), 0o750))

				sandbox, err := constructor.create(directory, mode)
				require.NoError(t, err)
				require.NoError(t, sandbox.Close())

				when := time.Now()
				assertClosed(t, sandbox.Symlink("a.txt", "link"))
				assertClosed(t, sandbox.Link("a.txt", "hard"))
				assertClosed(t, sandbox.Chtimes("a.txt", when, when))
				assertClosed(t, sandbox.Lchown("a.txt", -1, -1))
				assertClosed(t, sandbox.Chown("a.txt", -1, -1))
				_, err = sandbox.Readlink("a.txt")
				assertClosed(t, err)
				_, err = sandbox.OpenRoot("dir", ModeReadOnly)
				assertClosed(t, err)

				_, err = sandbox.Open("a.txt")
				assertClosed(t, err)
				_, err = sandbox.ReadFile("a.txt")
				assertClosed(t, err)
				_, err = sandbox.Stat("a.txt")
				assertClosed(t, err)
				_, err = sandbox.ReadDir(".")
				assertClosed(t, err)
				assertClosed(t, sandbox.WriteFile("b.txt", nil, 0o600))
				assertClosed(t, sandbox.WriteFileAtomic("b.txt", nil, 0o600))
				assertClosed(t, sandbox.Rename("a.txt", "b.txt"))
			})
		}
	}
}

func TestSandbox_ReadOnly_ExistingRoutes(t *testing.T) {
	t.Parallel()

	for _, constructor := range sandboxConstructors() {
		t.Run(constructor.name, func(t *testing.T) {
			t.Parallel()

			directory := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(directory, "a.txt"), []byte("a"), 0o600))

			sandbox, err := constructor.create(directory, ModeReadOnly)
			require.NoError(t, err)
			defer func() { _ = sandbox.Close() }()

			_, err = sandbox.Create("b.txt")
			assertReadOnly(t, err)
			_, err = sandbox.OpenFile("a.txt", os.O_RDWR, 0)
			assertReadOnly(t, err)
			assertReadOnly(t, sandbox.WriteFile("b.txt", nil, 0o600))
			assertReadOnly(t, sandbox.WriteFileAtomic("b.txt", nil, 0o600))
			assertReadOnly(t, sandbox.Mkdir("d", 0o750))
			assertReadOnly(t, sandbox.MkdirAll("d/e", 0o750))
			assertReadOnly(t, sandbox.Remove("a.txt"))
			assertReadOnly(t, sandbox.RemoveAll("a.txt"))
			assertReadOnly(t, sandbox.Rename("a.txt", "b.txt"))
			assertReadOnly(t, sandbox.Chmod("a.txt", 0o644))
			_, err = sandbox.CreateTemp(".", "tmp-*")
			assertReadOnly(t, err)
			_, err = sandbox.MkdirTemp(".", "tmp-*")
			assertReadOnly(t, err)
		})
	}
}

func TestNoOpSandbox_NewMethods(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	sandbox, err := NewNoOpSandbox(directory, ModeReadWrite)
	require.NoError(t, err)
	defer func() { _ = sandbox.Close() }()

	require.NoError(t, sandbox.WriteFile("a.txt", []byte("a"), 0o600))
	require.NoError(t, sandbox.MkdirAll("dir/sub", 0o750))
	require.NoError(t, sandbox.WriteFile("dir/b.txt", []byte("b"), 0o600))

	require.NoError(t, sandbox.Symlink("a.txt", "link"))
	target, err := sandbox.Readlink("link")
	require.NoError(t, err)
	assert.Equal(t, "a.txt", target)

	require.NoError(t, sandbox.Link("a.txt", "hard"))
	original, err := sandbox.Stat("a.txt")
	require.NoError(t, err)
	linked, err := sandbox.Stat("hard")
	require.NoError(t, err)
	assert.True(t, os.SameFile(original, linked))

	when := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	require.NoError(t, sandbox.Chtimes("a.txt", when, when))
	info, err := sandbox.Stat("a.txt")
	require.NoError(t, err)
	assert.True(t, info.ModTime().Equal(when))

	require.NoError(t, sandbox.Lchown("link", -1, -1))

	child, err := sandbox.OpenRoot("dir", ModeReadOnly)
	require.NoError(t, err)
	defer func() { _ = child.Close() }()
	assert.True(t, child.IsNoOp())
	assert.True(t, child.IsReadOnly())
	assert.Equal(t, filepath.Join(directory, "dir"), child.Root())
	content, err := child.ReadFile("b.txt")
	require.NoError(t, err)
	assert.Equal(t, "b", string(content))

	_, err = sandbox.OpenRoot("a.txt", ModeReadOnly)
	assert.ErrorIs(t, err, errNotDirectory)
	_, err = sandbox.OpenRoot("missing", ModeReadOnly)
	assert.ErrorIs(t, err, fs.ErrNotExist)

	require.NoError(t, fstest.TestFS(sandbox.FS(), "a.txt", "dir/b.txt", "hard", "link"))
}

func TestNoOpSandbox_NewMethods_LexicalEscapes(t *testing.T) {
	t.Parallel()

	sandboxDirectory := t.TempDir()
	outsideDirectory := t.TempDir()
	outsideFile := filepath.Join(outsideDirectory, "secret.txt")
	require.NoError(t, os.WriteFile(outsideFile, []byte("outside"), 0o600))
	escape, err := filepath.Rel(sandboxDirectory, outsideFile)
	require.NoError(t, err)

	sandbox, err := NewNoOpSandbox(sandboxDirectory, ModeReadWrite)
	require.NoError(t, err)
	defer func() { _ = sandbox.Close() }()
	require.NoError(t, sandbox.WriteFile("a.txt", []byte("a"), 0o600))

	when := time.Now()
	errs := []error{
		sandbox.Symlink("a.txt", "../escaped"),
		sandbox.Link("a.txt", "../escaped"),
		sandbox.Link(escape, "stolen"),
		sandbox.Chtimes(escape, when, when),
		sandbox.Lchown(escape, -1, -1),
		sandbox.Chown(escape, -1, -1),
	}
	_, readlinkErr := sandbox.Readlink("../link")
	_, openRootErr := sandbox.OpenRoot("..", ModeReadOnly)
	errs = append(errs, readlinkErr, openRootErr)

	for i, err := range errs {
		require.Error(t, err, "case %d", i)
		assert.True(t, IsEscape(err), "case %d: want an escape error, got %v", i, err)
		assert.Contains(t, err.Error(), "escapes sandbox root")
	}

	_, statErr := os.Lstat(filepath.Join(filepath.Dir(sandboxDirectory), "escaped"))
	assert.True(t, os.IsNotExist(statErr))
	_, statErr = os.Lstat(filepath.Join(sandboxDirectory, "stolen"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestSandbox_IsNoOp(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()

	confined, err := NewSandbox(directory, ModeReadOnly)
	require.NoError(t, err)
	defer func() { _ = confined.Close() }()
	assert.False(t, confined.IsNoOp())

	noOp, err := NewNoOpSandbox(directory, ModeReadOnly)
	require.NoError(t, err)
	defer func() { _ = noOp.Close() }()
	assert.True(t, noOp.IsNoOp())

	for _, enabled := range []bool{true, false} {
		factory, err := NewFactory(FactoryConfig{CWD: directory, Enabled: enabled})
		require.NoError(t, err)
		sandbox, err := factory.Create("test", directory, ModeReadOnly)
		require.NoError(t, err)
		assert.Equal(t, !enabled, sandbox.IsNoOp(), "Enabled=%v", enabled)
		require.NoError(t, sandbox.Close())
	}

	mock := NewMockSandbox("/mock", ModeReadOnly)
	assert.False(t, mock.IsNoOp())
	mock.NoOp = true
	assert.True(t, mock.IsNoOp())
}

func TestErrors_MatchStandardErrors(t *testing.T) {
	t.Parallel()

	assert.ErrorIs(t, ErrReadOnly, fs.ErrPermission)
	assert.ErrorIs(t, ErrPathNotAllowed, fs.ErrPermission)
	assert.ErrorIs(t, ErrClosed, fs.ErrClosed)
	assert.NotErrorIs(t, ErrReadOnly, ErrClosed)
	assert.NotErrorIs(t, ErrPathNotAllowed, ErrReadOnly)

	assert.Equal(t, "safedisk: sandbox is read-only", ErrReadOnly.Error())
	assert.Equal(t, "safedisk: sandbox is closed", ErrClosed.Error())
	assert.Equal(t, "safedisk: path is not in allowed paths", ErrPathNotAllowed.Error())
}

func TestIsEscape(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	sandbox, err := NewSandbox(directory, ModeReadWrite)
	require.NoError(t, err)
	defer func() { _ = sandbox.Close() }()

	_, osErr := sandbox.Open("../x")
	require.Error(t, osErr)
	assert.True(t, IsEscape(osErr), "os.Root escape: %v", osErr)

	renameErr := sandbox.Rename("x", "../x")
	require.Error(t, renameErr)
	assert.True(t, IsEscape(renameErr), "safedisk's own refusal: %v", renameErr)

	assert.True(t, IsEscape(wrapTwice(osErr)), "wrapped escapes are found")

	_, missingErr := sandbox.Open("missing")
	assert.False(t, IsEscape(missingErr))
	assert.False(t, IsEscape(nil))
	assert.False(t, IsEscape(fs.ErrNotExist))
	assert.False(t, IsEscape(ErrReadOnly))
	assert.False(t, IsEscape(errors.New("path escapes elsewhere")))
}

func TestIsEscape_ProbeLearnsTheOSError(t *testing.T) {
	t.Parallel()

	sentinel := osEscape.get()
	require.NotNil(t, sentinel, "the probe must find the os escape error")
	assert.Equal(t, osEscapeMessage, sentinel.Error(), "Go has changed the escape error text; check IsEscape")

	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = root.Close() }()
	_, err = root.Open("../x")
	assert.ErrorIs(t, err, sentinel)

	assert.Nil(t, pathErrorCause(errors.New("plain")))
	assert.Nil(t, probeEscapeError(closedRoot(t)), "a closed root must not teach a wrong error")
}

func TestFactory_ErrorsHaveOnePrefix(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	factory, err := NewFactory(FactoryConfig{CWD: directory, Enabled: true})
	require.NoError(t, err)

	_, err = factory.Create("uploads", t.TempDir(), ModeReadOnly)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPathNotAllowed)
	assert.ErrorIs(t, err, fs.ErrPermission)
	assert.Equal(t, 1, strings.Count(err.Error(), "safedisk:"), "got %q", err.Error())
	assert.Contains(t, err.Error(), `"uploads"`)

	_, err = factory.Create("uploads", "", ModeReadOnly)
	require.Error(t, err)
	assert.ErrorIs(t, err, errEmptyPath)
	assert.Equal(t, 1, strings.Count(err.Error(), "safedisk:"), "got %q", err.Error())

	defer func() {
		recovered := recover()
		require.NotNil(t, recovered)
		message, ok := recovered.(string)
		require.True(t, ok)
		assert.Equal(t, 1, strings.Count(message, "safedisk:"), "got %q", message)
		assert.Contains(t, message, "uploads")
	}()
	factory.MustCreate("uploads", "/not/allowed", ModeReadOnly)
}

func TestFactory_EmptyAllowListAllowsOnlyWorkingDirectory(t *testing.T) {
	t.Parallel()

	workingDirectory := t.TempDir()
	elsewhere := t.TempDir()

	factories := map[string]func() (Factory, error){
		"NewFactory":    func() (Factory, error) { return NewFactory(FactoryConfig{CWD: workingDirectory, Enabled: true}) },
		"NewCLIFactory": func() (Factory, error) { return NewCLIFactory(workingDirectory) },
	}

	for name, create := range factories {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			factory, err := create()
			require.NoError(t, err)

			assert.Equal(t, []string{workingDirectory}, factory.AllowedPaths())
			assert.True(t, factory.IsPathAllowed(workingDirectory))
			assert.True(t, factory.IsPathAllowed(filepath.Join(workingDirectory, "sub")))
			assert.False(t, factory.IsPathAllowed(elsewhere))

			_, err = factory.Create("test", elsewhere, ModeReadOnly)
			assert.ErrorIs(t, err, ErrPathNotAllowed)
		})
	}
}

type sandboxConstructor struct {
	name string
	create func(directory string, mode Mode) (Sandbox, error)
}

func sandboxConstructors() []sandboxConstructor {
	return []sandboxConstructor{
		{name: "os", create: NewSandbox},
		{name: "noop", create: NewNoOpSandbox},
	}
}

func assertReadOnly(t *testing.T, err error) {
	t.Helper()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrReadOnly)
	assert.ErrorIs(t, err, fs.ErrPermission)
}

func assertClosed(t *testing.T, err error) {
	t.Helper()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClosed)
	assert.ErrorIs(t, err, fs.ErrClosed)
}

func wrapTwice(err error) error {
	return errors.Join(errors.New("context"), &fs.PathError{Op: "outer", Path: "p", Err: err})
}

func closedRoot(t *testing.T) *os.Root {
	t.Helper()

	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, root.Close())
	return root
}
