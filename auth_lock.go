package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Conflicts must not be treated as a retryable disk-save failure: the process no
// longer owns the credential revision (or the official lease) it started with.
type authConflictError struct{ reason string }

func (e *authConflictError) Error() string {
	return "authentication store conflict: " + e.reason + "; reload credentials or re-login"
}
func authConflict(reason string) error { return &authConflictError{reason: reason} }
func isAuthConflict(err error) bool {
	var conflict *authConflictError
	return errors.As(err, &conflict)
}

type credentialLeaseOptions struct {
	heartbeat, stale, retry, wait time.Duration
	// Narrow filesystem seam for deterministic stale-reclaim/heartbeat races.
	lstat func(string) (os.FileInfo, error)
}

func (o credentialLeaseOptions) defaults() credentialLeaseOptions {
	if o.heartbeat <= 0 {
		o.heartbeat = 10 * time.Second
	}
	if o.stale <= 0 {
		o.stale = 120 * time.Second
	}
	if o.retry <= 0 {
		o.retry = 50 * time.Millisecond
	}
	if o.wait <= 0 {
		o.wait = 30 * time.Second
	}
	if o.lstat == nil {
		o.lstat = os.Lstat
	}
	return o
}

type credentialLease struct {
	mu                                    sync.Mutex
	path, dir, marker                     string
	identity, dirIdentity, markerIdentity os.FileInfo
	mtime                                 time.Time
	options                               credentialLeaseOptions
	compromised                           error
	stop, done                            chan struct{}
	once                                  sync.Once
	releaseErr                            error
}

func checkedDirectory(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, authConflict("directory identity is unsafe")
	}
	return info, nil
}

func ensureAuthDirectory(dir string) (os.FileInfo, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return checkedDirectory(dir)
}

func acquireCredentialLease(ctx context.Context, dir string, options credentialLeaseOptions) (*credentialLease, error) {
	options = options.defaults()
	ctx, cancel := context.WithTimeout(ctx, options.wait)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dirIdentity, err := checkedDirectory(dir)
	if err != nil {
		return nil, err
	}
	marker := filepath.Join(dir, ".credential-transaction")
	f, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		err = f.Close()
	} else if errors.Is(err, os.ErrExist) {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	markerIdentity, err := os.Lstat(marker)
	if err != nil {
		return nil, err
	}
	if !markerIdentity.Mode().IsRegular() || markerIdentity.Mode().Perm() != 0600 {
		return nil, authConflict("credential transaction marker is unsafe")
	}
	path := marker + ".lock"
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		currentDir, err := checkedDirectory(dir)
		if err != nil {
			return nil, err
		}
		if !os.SameFile(dirIdentity, currentDir) {
			return nil, authConflict("auth directory changed")
		}
		err = os.Mkdir(path, 0700)
		if err == nil {
			identity, err := options.lstat(path)
			if err != nil {
				return nil, err
			}
			if !identity.IsDir() || identity.Mode()&os.ModeSymlink != 0 {
				return nil, authConflict("credential lease changed during acquisition")
			}
			lease := &credentialLease{path: path, dir: dir, marker: marker, identity: identity, dirIdentity: dirIdentity, markerIdentity: markerIdentity, mtime: identity.ModTime(), options: options, stop: make(chan struct{}), done: make(chan struct{})}
			go lease.heartbeat()
			return lease, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		info, err := options.lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, authConflict("credential lease is not a directory")
		}
		if time.Since(info.ModTime()) > options.stale {
			entries, err := os.ReadDir(path)
			if err != nil {
				return nil, err
			}
			if len(entries) != 0 {
				return nil, authConflict("stale credential lease is not empty")
			}
			again, err := options.lstat(path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if !again.IsDir() || !os.SameFile(info, again) || !again.ModTime().Equal(info.ModTime()) {
				return nil, authConflict("stale credential lease changed")
			}
			// rmdir, never RemoveAll or unlink: official proper-lockfile leases are empty.
			if err := syscall.Rmdir(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			continue
		}
		timer := time.NewTimer(options.retry)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (l *credentialLease) checkLocked() error {
	if l.compromised != nil {
		return l.compromised
	}
	fail := func() error { l.compromised = authConflict("credential lease was compromised"); return l.compromised }
	dir, err := l.options.lstat(l.dir)
	if err != nil || !dir.IsDir() || !os.SameFile(l.dirIdentity, dir) {
		return fail()
	}
	marker, err := l.options.lstat(l.marker)
	if err != nil || !marker.Mode().IsRegular() || marker.Mode().Perm() != 0600 || !os.SameFile(l.markerIdentity, marker) {
		return fail()
	}
	info, err := l.options.lstat(l.path)
	if err != nil || !info.IsDir() || !os.SameFile(l.identity, info) || !info.ModTime().Equal(l.mtime) {
		return fail()
	}
	return nil
}
func (l *credentialLease) check() error { l.mu.Lock(); defer l.mu.Unlock(); return l.checkLocked() }

func (l *credentialLease) heartbeat() {
	defer close(l.done)
	ticker := time.NewTicker(l.options.heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-ticker.C:
		}
		l.mu.Lock()
		if l.checkLocked() != nil {
			l.mu.Unlock()
			return
		}
		now := time.Now()
		err := os.Chtimes(l.path, now, now)
		info, statErr := l.options.lstat(l.path)
		if err != nil || statErr != nil || !info.IsDir() || !os.SameFile(l.identity, info) {
			l.compromised = authConflict("credential lease heartbeat failed")
			l.mu.Unlock()
			return
		}
		l.mtime = info.ModTime()
		l.mu.Unlock()
	}
}

func (l *credentialLease) release() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		close(l.stop)
		<-l.done
		l.mu.Lock()
		defer l.mu.Unlock()
		if err := l.checkLocked(); err != nil {
			l.releaseErr = err
			return
		}
		if err := syscall.Rmdir(l.path); err != nil {
			l.releaseErr = fmt.Errorf("release credential lease: %w", err)
		}
	})
	return l.releaseErr
}
