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
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockSandbox_SymlinkAndReadlink(t *testing.T) {
	t.Parallel()

	mock := NewMockSandbox("/mock", ModeReadWrite)
	mock.AddFile("a.txt", []byte("a"))

	require.NoError(t, mock.Symlink("/outside/target", "link"))
	target, err := mock.Readlink("link")
	require.NoError(t, err)
	assert.Equal(t, "/outside/target", target, "the target is stored as given")

	assert.ErrorIs(t, mock.Symlink("x", "link"), fs.ErrExist)
	assert.ErrorIs(t, mock.Symlink("x", "a.txt"), fs.ErrExist)

	_, err = mock.Readlink("a.txt")
	assert.ErrorIs(t, err, fs.ErrInvalid)
	_, err = mock.Readlink("missing")
	assert.ErrorIs(t, err, fs.ErrNotExist)

	require.NoError(t, mock.Remove("link"))
	_, err = mock.Readlink("link")
	assert.ErrorIs(t, err, fs.ErrNotExist)

	assert.Equal(t, 3, mock.CallCounts["Symlink"])
	assert.Equal(t, 4, mock.CallCounts["Readlink"])
}

func TestMockSandbox_Symlink_ZeroValueMock(t *testing.T) {
	t.Parallel()

	mock := &MockSandbox{CallCounts: map[string]int{}, mode: ModeReadWrite}
	require.NoError(t, mock.Symlink("target", "link"))
	target, err := mock.Readlink("link")
	require.NoError(t, err)
	assert.Equal(t, "target", target)
}

func TestMockSandbox_Link(t *testing.T) {
	t.Parallel()

	mock := NewMockSandbox("/mock", ModeReadWrite)
	original := mock.AddFile("a.txt", []byte("a"))

	require.NoError(t, mock.Link("a.txt", "hard.txt"))
	assert.Same(t, original, mock.GetFile("hard.txt"), "both names share one handle")

	assert.ErrorIs(t, mock.Link("missing", "other"), fs.ErrNotExist)
	assert.ErrorIs(t, mock.Link("a.txt", "hard.txt"), fs.ErrExist)
}

func TestMockSandbox_ChtimesAndLchown(t *testing.T) {
	t.Parallel()

	mock := NewMockSandbox("/mock", ModeReadWrite)
	mock.AddFile("a.txt", []byte("a"))
	require.NoError(t, mock.Symlink("a.txt", "link"))

	when := time.Now()
	require.NoError(t, mock.Chtimes("a.txt", when, when))
	require.NoError(t, mock.Lchown("link", 1, 1))
	require.NoError(t, mock.Chown("a.txt", 1, 1))
	assert.ErrorIs(t, mock.Chown("missing", 1, 1), fs.ErrNotExist)
	assert.ErrorIs(t, mock.Chtimes("missing", when, when), fs.ErrNotExist)
	assert.ErrorIs(t, mock.Lchown("missing", 1, 1), fs.ErrNotExist)
}

func TestMockSandbox_NewMethods_ReadOnly(t *testing.T) {
	t.Parallel()

	mock := NewMockSandbox("/mock", ModeReadOnly)
	mock.AddFile("a.txt", []byte("a"))

	when := time.Now()
	assertReadOnly(t, mock.Symlink("a.txt", "link"))
	assertReadOnly(t, mock.Link("a.txt", "hard"))
	assertReadOnly(t, mock.Chtimes("a.txt", when, when))
	assertReadOnly(t, mock.Lchown("a.txt", 1, 1))
	assertReadOnly(t, mock.Chown("a.txt", 1, 1))
	_, err := mock.OpenRoot("dir", ModeReadWrite)
	assertReadOnly(t, err)

	assert.Nil(t, mock.GetFile("hard"))
	_, err = mock.Readlink("link")
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestMockSandbox_NewMethods_InjectedErrors(t *testing.T) {
	t.Parallel()

	injected := errors.New("injected")
	mock := NewMockSandbox("/mock", ModeReadWrite)
	mock.AddFile("a.txt", []byte("a"))
	mock.SymlinkErr = injected
	mock.LinkErr = injected
	mock.ReadlinkErr = injected
	mock.ChtimesErr = injected
	mock.LchownErr = injected
	mock.ChownErr = injected
	mock.OpenRootErr = injected

	when := time.Now()
	assert.ErrorIs(t, mock.Symlink("a.txt", "link"), injected)
	assert.ErrorIs(t, mock.Link("a.txt", "hard"), injected)
	_, err := mock.Readlink("link")
	assert.ErrorIs(t, err, injected)
	assert.ErrorIs(t, mock.Chtimes("a.txt", when, when), injected)
	assert.ErrorIs(t, mock.Lchown("a.txt", 1, 1), injected)
	assert.ErrorIs(t, mock.Chown("a.txt", 1, 1), injected)
	_, err = mock.OpenRoot("dir", ModeReadOnly)
	assert.ErrorIs(t, err, injected)
}

func TestMockSandbox_OpenRoot(t *testing.T) {
	t.Parallel()

	mock := NewMockSandbox("/mock", ModeReadWrite)
	mock.NoOp = true
	shared := mock.AddFile("dir/a.txt", []byte("a"))
	mock.AddFile("dir/sub/b.txt", []byte("b"))
	mock.AddFile("dirt.txt", []byte("not beneath dir"))
	mock.AddFile("top.txt", []byte("top"))
	require.NoError(t, mock.Symlink("a.txt", "dir/link"))

	child, err := mock.OpenRoot("dir/", ModeReadOnly)
	require.NoError(t, err)
	childMock, ok := child.(*MockSandbox)
	require.True(t, ok)

	assert.Equal(t, "/mock/dir", child.Root())
	assert.True(t, child.IsReadOnly())
	assert.True(t, child.IsNoOp(), "NoOp is inherited")
	assert.Same(t, shared, childMock.GetFile("a.txt"))
	assert.NotNil(t, childMock.GetFile("sub/b.txt"))
	assert.Nil(t, childMock.GetFile("t.txt"), "a sibling with a shared prefix is not included")
	assert.Nil(t, childMock.GetFile("../top.txt"))
	target, err := child.Readlink("link")
	require.NoError(t, err)
	assert.Equal(t, "a.txt", target)

	assertReadOnly(t, child.WriteFile("new.txt", nil, 0o600))

	whole, err := mock.OpenRoot(".", ModeReadWrite)
	require.NoError(t, err)
	assert.NotNil(t, whole.(*MockSandbox).GetFile("top.txt"))
}

func TestMockSandbox_OpenRoot_EscapesAreRefused(t *testing.T) {
	t.Parallel()

	mock := NewMockSandbox("/mock", ModeReadWrite)

	for _, directory := range []string{"..", "../sibling", "a/../..", "/etc", ""} {
		child, err := mock.OpenRoot(directory, ModeReadOnly)
		require.Error(t, err, directory)
		assert.Nil(t, child)
		assert.True(t, IsEscape(err), "%q: want an escape error, got %v", directory, err)
	}
}

func TestMockSandbox_FS(t *testing.T) {
	t.Parallel()

	mock := NewMockSandbox("/mock", ModeReadWrite)
	mock.AddFile("a.txt", []byte("a"))
	mock.AddFile("dir/b.txt", []byte("b"))
	require.NoError(t, mock.MkdirAll("empty", 0o750))
	require.NoError(t, mock.Symlink("a.txt", "link"))

	fsys := mock.FS()
	require.NoError(t, fstest.TestFS(fsys, "a.txt", "dir/b.txt", "link"))

	content, err := fs.ReadFile(fsys, "link")
	require.NoError(t, err)
	assert.Equal(t, "a", string(content))

	info, err := fs.Stat(fsys, "empty")
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	mock.AddFile("later.txt", []byte("later"))
	content, err = fs.ReadFile(fsys, "later.txt")
	require.NoError(t, err, "the view sees later changes")
	assert.Equal(t, "later", string(content))

	_, err = fs.ReadFile(fsys, "../a.txt")
	assert.ErrorIs(t, err, fs.ErrInvalid)
	assert.Equal(t, 1, mock.CallCounts["FS"])
}
