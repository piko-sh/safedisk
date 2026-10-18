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
	"log/slog"
)

// warnCloseFailure reports a handle that failed to close after the operation that
// opened it had finished.
//
// The failure cannot change the operation's result, so it is logged rather than
// returned. The logger is resolved from slog.Default on every call, so a host that
// replaces the default logger after start-up still receives these warnings.
//
// Takes message (string) which describes the operation that left the handle open.
// Takes key (string) which names the attribute that carries the path.
// Takes name (string) which is the path of the handle.
// Takes err (error) which is the error returned by Close.
func warnCloseFailure(message, key, name string, err error) {
	slog.Default().Warn(message, slog.Any("error", err), slog.String(key, name), slog.String("component", "safedisk"))
}
