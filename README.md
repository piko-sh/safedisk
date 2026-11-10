# safedisk

**Sandboxed filesystem access** for Go, built on `os.Root`.

Every path an application opens from configuration, user input or a build manifest is a chance
for `../` traversal, a symlink that points outside the intended directory, or a race between
checking a path and opening it. `safedisk` puts each directory an application touches behind a
`Sandbox` rooted with `os.Root`, which refuses any access that would leave it. A `Factory`
restricts which directories may be sandboxed at all.

Module `piko.sh/safedisk`. Go 1.27. Apache-2.0. No dependencies outside the standard library.

## Install

```sh
go get piko.sh/safedisk
```

## Usage

```go
package main

import (
	"fmt"
	"log"

	"piko.sh/safedisk"
)

func main() {
	factory, err := safedisk.NewFactory(safedisk.FactoryConfig{
		CWD:          "",
		AllowedPaths: []string{"/var/lib/app"},
		Enabled:      true,
	})
	if err != nil {
		log.Fatal(err)
	}

	sandbox, err := factory.Create("uploads", "/var/lib/app/uploads", safedisk.ModeReadWrite)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = sandbox.Close() }()

	if err := sandbox.WriteFileAtomic("report.txt", []byte("hello"), 0o600); err != nil {
		log.Fatal(err)
	}

	data, err := sandbox.ReadFile("report.txt")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(data))

	_, err = sandbox.ReadFile("../../etc/passwd") // refused: escapes the sandbox
	fmt.Println(err)
}
```

## What it provides

- **`Sandbox`**: an `os`-like API (`Open`, `ReadFile`, `ReadFileLimit`, `WriteFile`,
  `WriteFileAtomic`, `OpenFile`, `Create`, `Mkdir(All)`, `Remove(All)`, `Rename`, `Chmod`,
  `Chtimes`, `Chown`, `Lchown`, `Symlink`, `Link`, `Readlink`, `Stat`, `Lstat`, `ReadDir`, `WalkDir`,
  `CreateTemp`, `MkdirTemp`) confined to one directory, in `ModeReadOnly` or `ModeReadWrite`.
- **Sub-sandboxes and `fs.FS`**: `OpenRoot` opens a directory as a sandbox of its own, with the
  same mode or a stricter one, and `FS` gives a read-only `fs.FS` view.
- **`Factory`** (`NewFactory`, `NewCLIFactory`): creates sandboxes only for allowed paths, with
  the working directory always permitted.
- **Optional hardening**: `WithRequireSingleLink` rejects files with multiple hard links and
  `WithNoSymlinks` rejects symbolic-link traversal. Both are off by default; use the
  `WithOptions` constructors or the matching `FactoryConfig` fields. The symlink check is
  not atomic; see the [option documentation](options.go) for details.
- **Bounded reads**: `ReadFile` caps at `DefaultReadFileMaxBytes` (256 MiB) and
  `ReadFileLimit` takes an explicit cap, both returning `ErrFileExceedsLimit` when exceeded.
- **Atomic writes**: `WriteFileAtomic` writes a temporary file and renames it within the
  sandbox.
- **No-op mode**: `FactoryConfig.Enabled = false` (or `NewNoOpSandbox`) gives the same API
  with only lexical path checks, for development only.
- **Test doubles**: `MockSandbox` and `MockFileHandle` keep files in memory.

All `Sandbox` methods and the `Factory` are safe for concurrent use. Individual file handles
follow `os.File` rules. Failures to close a handle after an operation has finished are reported
through `slog.Default` at warning level.

## Development

```sh
go test -race ./...
golangci-lint run
```

safedisk was originally developed as part of the [Piko](https://github.com/piko-sh/piko) web
framework.
