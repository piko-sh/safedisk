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

// Package safedisk provides sandboxed filesystem operations using os.Root.
//
// Acts as a boundary for an application's filesystem operations by confining each
// [Sandbox] to one directory. Paths are resolved by os.Root, which refuses access outside
// the root, including through symbolic links.
//
// Sandboxes can be created in read-only or read-write mode. The [Factory] restricts
// sandboxes to allowed paths, with the current working directory always implicitly
// permitted. Atomic file writes are supported via CreateTemp followed by Rename within
// the same sandbox.
//
// Optional [WithRequireSingleLink] and [WithNoSymlinks] settings reject files with multiple
// hard links and symbolic-link traversal. Both are off by default and can be set through
// [FactoryConfig] or the constructors that accept options. The symlink check is not atomic.
//
// All [Sandbox] methods and the [Factory] are safe for concurrent use. Individual [File]
// handles should not be shared without external synchronisation, consistent with standard
// [os.File] behaviour.
//
// When Enabled is false in [FactoryConfig], the factory creates no-op sandboxes that
// provide the same API with only lexical path checks. Do not use no-op mode in
// production where security is required.
//
// Failures to close a handle after an operation has finished are reported through
// slog.Default at warning level, since they cannot change the operation's result.
package safedisk
