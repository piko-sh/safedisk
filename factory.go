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
	"path/filepath"
	"strings"
	"sync"
)

// Factory creates sandboxes with validated paths. It restricts sandbox creation to paths
// within the allowed list, preventing malicious or accidental access to sensitive
// directories.
type Factory interface {
	// Create creates a new sandbox for the given path. The path must be the working
	// directory, a configured allowed path, or beneath one of them.
	//
	// Takes purpose (string) which is a descriptive name for logging.
	// Takes path (string) which is the directory to sandbox.
	// Takes mode (Mode) which specifies whether to allow write operations.
	//
	// Returns Sandbox which is the sandboxed filesystem.
	// Returns error when the path is not allowed or sandbox creation fails.
	Create(purpose string, path string, mode Mode) (Sandbox, error)

	// MustCreate works like Create but panics on error. Use only during application startup
	// when failure cannot be recovered.
	//
	// Takes purpose (string) which describes why the sandbox is needed.
	// Takes path (string) which is the root directory for the sandbox.
	// Takes mode (Mode) which sets the sandbox restrictions.
	//
	// Returns Sandbox which is the created sandbox ready for use.
	MustCreate(purpose string, path string, mode Mode) Sandbox

	// IsPathAllowed checks if a path would be allowed for sandbox creation.
	//
	// Takes path (string) the path to check.
	//
	// Returns bool true if the path is allowed.
	IsPathAllowed(path string) bool

	// AllowedPaths returns the list of paths that are allowed.
	//
	// Returns []string which always holds the working directory first, followed by the
	// configured allowed paths. It is never empty.
	AllowedPaths() []string
}

// FactoryConfig configures the sandbox factory.
type FactoryConfig struct {
	// CWD is the current working directory, which is always allowed. If empty, it is
	// detected automatically.
	CWD string

	// AllowedPaths is a list of paths, made absolute during factory creation, that can be
	// sandboxed together with everything beneath them.
	//
	// The working directory is always added, so an empty list allows only the working
	// directory and its descendants. There is no setting that allows every path.
	AllowedPaths []string

	// Enabled controls whether sandboxing uses os.Root (true) or NoOpSandbox (false), where
	// false provides no actual security and only basic path validation (default: true).
	Enabled bool

	// RequireSingleLink makes every sandbox refuse to open a file with more than one hard
	// link, as WithRequireSingleLink does. It is off by default.
	RequireSingleLink bool

	// NoSymlinks makes every sandbox refuse to follow or create symbolic links, as
	// WithNoSymlinks does. It is off by default.
	NoSymlinks bool
}

// factoryImpl is the default implementation of the Factory interface.
type factoryImpl struct {
	// allowedPaths holds absolute paths that limit where file operations can occur.
	allowedPaths []string

	// config holds the sandbox factory settings.
	config FactoryConfig

	// mu guards factory fields for safe concurrent access.
	mu sync.RWMutex
}

// Create creates a new sandbox for the given path.
//
// Takes purpose (string) which describes the sandbox's intended use.
// Takes path (string) which specifies the filesystem path to sandbox.
// Takes mode (Mode) which sets the access mode for the sandbox.
//
// Returns Sandbox which is either a real sandbox or a no-op implementation depending on
// the factory configuration.
// Returns error when path is empty or invalid, or wrapping ErrPathNotAllowed when the
// path is not within the allowed paths.
func (f *factoryImpl) Create(purpose string, path string, mode Mode) (Sandbox, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: sandbox %q", errEmptyPath, purpose)
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("safedisk: sandbox %q: invalid path %q: %w", purpose, path, err)
	}

	if !f.checkPathAllowed(absPath) {
		return nil, fmt.Errorf("%w: sandbox %q: %q is not within allowed paths %v", ErrPathNotAllowed, purpose, absPath, f.AllowedPaths())
	}

	options := f.sandboxOptions()
	if f.config.Enabled {
		return NewSandboxWithOptions(absPath, mode, options...)
	}

	return NewNoOpSandboxWithOptions(absPath, mode, options...)
}

// MustCreate is like Create but panics on error.
//
// Takes purpose (string) which describes the sandbox's intended use.
// Takes path (string) which specifies the directory path for the sandbox.
// Takes mode (Mode) which defines the sandbox behaviour mode.
//
// Returns Sandbox which is the created sandbox instance.
//
// Panics when sandbox creation fails.
func (f *factoryImpl) MustCreate(purpose string, path string, mode Mode) Sandbox {
	sandbox, err := f.Create(purpose, path, mode)
	if err != nil {
		panic(fmt.Sprintf("%v (creating sandbox for %s at %q)", err, purpose, path))
	}
	return sandbox
}

// IsPathAllowed checks if a path would be allowed for sandbox creation.
//
// Takes path (string) which specifies the file path to check.
//
// Returns bool which is true if the path is allowed, false otherwise.
func (f *factoryImpl) IsPathAllowed(path string) bool {
	if path == "" {
		return false
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	return f.checkPathAllowed(absPath)
}

// AllowedPaths returns the list of configured allowed paths.
//
// Returns []string which is a copy of the allowed paths to prevent mutation.
//
// Safe for concurrent use.
func (f *factoryImpl) AllowedPaths() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	paths := make([]string, len(f.allowedPaths))
	copy(paths, f.allowedPaths)
	return paths
}

// sandboxOptions converts the factory configuration into sandbox options.
//
// Returns []Option which holds an Option for each setting that is switched on.
func (f *factoryImpl) sandboxOptions() []Option {
	var options []Option
	if f.config.RequireSingleLink {
		options = append(options, WithRequireSingleLink())
	}
	if f.config.NoSymlinks {
		options = append(options, WithNoSymlinks())
	}
	return options
}

// checkPathAllowed checks if an absolute path is within the allowed paths.
//
// Takes absPath (string) which is the path to check.
//
// Returns bool which is true if the path is allowed, false otherwise.
//
// Safe for concurrent use; protected by a read lock on the factory.
func (f *factoryImpl) checkPathAllowed(absPath string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	for _, allowed := range f.allowedPaths {
		if isWithinOrEqual(allowed, absPath) {
			return true
		}
	}

	return false
}

// NewFactory creates a new sandbox factory with the given settings.
//
// Takes config (FactoryConfig) which specifies the factory settings.
//
// Returns Factory which is the configured factory ready for use.
// Returns error when the configuration contains an invalid path or when the current
// working directory cannot be determined.
func NewFactory(config FactoryConfig) (Factory, error) {
	cwd := config.CWD
	if cwd == "" {
		var err error
		cwd, err = filepath.Abs(".")
		if err != nil {
			return nil, fmt.Errorf("safedisk: failed to get current working directory: %w", err)
		}
	} else {
		var err error
		cwd, err = filepath.Abs(cwd)
		if err != nil {
			return nil, fmt.Errorf("safedisk: invalid CWD path: %w", err)
		}
	}

	var allowedPaths []string
	seen := make(map[string]bool)

	seen[cwd] = true
	allowedPaths = append(allowedPaths, cwd)

	for _, p := range config.AllowedPaths {
		if p == "" {
			continue
		}

		absPath, err := filepath.Abs(p)
		if err != nil {
			return nil, fmt.Errorf("safedisk: invalid allowed path %q: %w", p, err)
		}

		if !seen[absPath] {
			seen[absPath] = true
			allowedPaths = append(allowedPaths, absPath)
		}
	}

	return &factoryImpl{
		allowedPaths: allowedPaths,
		config:       config,
		mu:           sync.RWMutex{},
	}, nil
}

// NewCLIFactory creates a factory suitable for CLI tools and standalone commands. It
// enables os.Root sandboxing, uses the given working directory, and configures no further
// allowed paths, so it creates sandboxes only for the working directory and the
// directories beneath it.
//
// Takes cwd (string) which is the working directory for the factory. When empty, the
// current working directory is detected automatically.
//
// Returns Factory which creates sandboxes only within the working directory.
// Returns error when factory creation fails.
func NewCLIFactory(cwd string) (Factory, error) {
	return NewFactory(FactoryConfig{
		CWD:               cwd,
		AllowedPaths:      nil,
		Enabled:           true,
		RequireSingleLink: false,
		NoSymlinks:        false,
	})
}

// newDefaultFactory creates a factory with default settings. Sandboxing is enabled and
// the current working directory is detected automatically.
//
// Returns Factory which is configured with default sandboxing settings.
// Returns error when the working directory cannot be detected.
func newDefaultFactory() (Factory, error) {
	return NewFactory(FactoryConfig{
		CWD:               "",
		AllowedPaths:      nil,
		Enabled:           true,
		RequireSingleLink: false,
		NoSymlinks:        false,
	})
}

// isWithinOrEqual checks if a path is equal to or inside a parent directory.
//
// Takes parent (string) which is the directory path to check against.
// Takes path (string) which is the path to test.
//
// Returns bool which is true if path equals parent or is inside it.
func isWithinOrEqual(parent, path string) bool {
	parent = filepath.Clean(parent)
	path = filepath.Clean(path)

	if path == parent {
		return true
	}

	prefix := parent
	if prefix[len(prefix)-1] != filepath.Separator {
		prefix += string(filepath.Separator)
	}

	return strings.HasPrefix(path, prefix)
}
