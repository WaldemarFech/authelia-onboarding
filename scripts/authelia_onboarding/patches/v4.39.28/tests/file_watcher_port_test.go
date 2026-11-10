//go:build linux

// SPDX-FileCopyrightText: 2026 Authelia Onboarding contributors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-crypt/crypt/algorithm/argon2"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

func TestPortWatcherAtomicReplaceThenImmediateDisable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.yml")
	hasher, err := argon2.New(argon2.WithM(8), argon2.WithT(1), argon2.WithP(1), argon2.WithK(32), argon2.WithS(16))
	require.NoError(t, err)
	digest, err := hasher.Hash("synthetic-test-password")
	require.NoError(t, err)
	data := func(disabled bool, group string) []byte {
		return []byte(fmt.Sprintf("users:\n  alice:\n    displayname: Alice\n    email: alice@example.invalid\n    password: '%s'\n    disabled: %t\n    groups: [%s]\n", digest.Encode(), disabled, group))
	}
	require.NoError(t, os.WriteFile(path, data(false, "initial"), 0600))
	provider := authentication.NewFileUserProvider(&schema.AuthenticationBackendFile{Path: path, Password: schema.DefaultPasswordConfig})
	require.NoError(t, provider.StartupCheck())
	ok, err := provider.CheckUserPassword("alice", "synthetic-test-password")
	require.NoError(t, err)
	require.True(t, ok)

	watcher, err := NewFileWatcher("users", path, provider, logrus.NewEntry(logrus.New()))
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- watcher.Run() }()
	t.Cleanup(func() { watcher.Shutdown(); <-done })
	replace := func(contents []byte) {
		file, createErr := os.CreateTemp(dir, ".replace-*")
		require.NoError(t, createErr)
		require.NoError(t, file.Chmod(0600))
		_, writeErr := file.Write(contents)
		require.NoError(t, writeErr)
		require.NoError(t, file.Close())
		require.NoError(t, os.Rename(file.Name(), path))
	}

	start := time.Now()
	replace(data(false, "students"))
	require.Eventually(t, func() bool {
		details, e := provider.GetDetails("alice")
		return e == nil && strings.Join(details.Groups, ",") == "students"
	}, time.Second, time.Millisecond*5, "watcher did not load the first replacement")
	require.Less(t, time.Since(start), 400*time.Millisecond, "test cannot exercise the historical reload cooldown")
	replace(data(true, "students"))
	require.Eventually(t, func() bool {
		_, e := provider.CheckUserPassword("alice", "synthetic-test-password")
		return errors.Is(e, authentication.ErrUserNotFound)
	}, time.Second*2, time.Millisecond*5, "watcher did not revoke the disabled account")
}
