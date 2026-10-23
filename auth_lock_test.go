package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func testLeaseOptions() credentialLeaseOptions {
	return credentialLeaseOptions{heartbeat: 5 * time.Millisecond, stale: 200 * time.Millisecond, retry: time.Millisecond, wait: time.Second}
}

func TestCredentialLeaseRespectsAnotherProcess(t *testing.T) {
	if os.Getenv("QODER_SYNTHETIC_LEASE_CHILD") == "1" {
		lease, err := acquireCredentialLease(context.Background(), os.Getenv("QODER_SYNTHETIC_LEASE_DIR"), testLeaseOptions())
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintln(os.Stdout, "held")
		if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
			t.Fatal(err)
		}
		if err := lease.release(); err != nil {
			t.Fatal(err)
		}
		return
	}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCredentialLeaseRespectsAnotherProcess$")
	child.Env = []string{"QODER_SYNTHETIC_LEASE_CHILD=1", "QODER_SYNTHETIC_LEASE_DIR=" + dir}
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Process.Kill()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "held\n" {
		t.Fatalf("child acquisition: %q %v", line, err)
	}
	waitCtx, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	if lease, err := acquireCredentialLease(waitCtx, dir, testLeaseOptions()); !errors.Is(err, context.DeadlineExceeded) {
		if lease != nil {
			lease.release()
		}
		t.Fatalf("another process's lease ignored: %v", err)
	}
	if _, err := fmt.Fprintln(stdin, "release"); err != nil {
		t.Fatal(err)
	}
	stdin.Close()
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	lease, err := acquireCredentialLease(context.Background(), dir, testLeaseOptions())
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.release(); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialLeaseStaleRecheckNeverRemovesRefreshedOrSuccessorLease(t *testing.T) {
	for _, change := range []string{"heartbeat", "successor"} {
		t.Run(change, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".credential-transaction.lock")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			old := time.Now().Add(-time.Hour)
			if err := os.Chtimes(path, old, old); err != nil {
				t.Fatal(err)
			}
			calls := 0
			options := testLeaseOptions()
			options.lstat = func(p string) (os.FileInfo, error) {
				if p == path {
					calls++
					if calls == 2 {
						if change == "successor" {
							if err := os.Rename(path, path+".old"); err != nil {
								t.Fatal(err)
							}
							if err := os.Mkdir(path, 0700); err != nil {
								t.Fatal(err)
							}
						} else {
							now := time.Now()
							if err := os.Chtimes(path, now, now); err != nil {
								t.Fatal(err)
							}
						}
					}
				}
				return os.Lstat(p)
			}
			if lease, err := acquireCredentialLease(context.Background(), dir, options); !isAuthConflict(err) {
				if lease != nil {
					lease.release()
				}
				t.Fatalf("changed stale lease accepted: %v", err)
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatal("changed lease removed")
			}
		})
	}
}

func TestCredentialLeaseUsesOfficialEmptyDirectoryAndCancelableWait(t *testing.T) {
	dir := t.TempDir()
	first, err := acquireCredentialLease(context.Background(), dir, testLeaseOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer first.release()
	assertCredentialFileMode(t, filepath.Join(dir, ".credential-transaction"))
	entries, err := os.ReadDir(filepath.Join(dir, ".credential-transaction.lock"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("official lease not empty: %v %v", entries, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if second, err := acquireCredentialLease(ctx, dir, testLeaseOptions()); !errors.Is(err, context.DeadlineExceeded) || second != nil {
		t.Fatalf("wait = %v %v", second, err)
	}
	if err := first.release(); err != nil {
		t.Fatal(err)
	}
	second, err := acquireCredentialLease(context.Background(), dir, testLeaseOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer second.release()
}

func TestCredentialLeaseHeartbeatSurvivesCallerCancellation(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	lease, err := acquireCredentialLease(ctx, dir, testLeaseOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer lease.release()
	before, err := os.Stat(lease.path)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	timer := time.NewTimer(40 * time.Millisecond)
	defer timer.Stop()
	<-timer.C
	after, err := os.Stat(lease.path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().After(before.ModTime()) {
		t.Fatal("heartbeat stopped with request context")
	}
	if err := lease.check(); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialLeaseReclaimsOnlyStaleEmptyDirectories(t *testing.T) {
	for _, kind := range []string{"empty", "nonempty", "file", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".credential-transaction.lock")
			switch kind {
			case "file":
				if err := os.WriteFile(path, nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(dir, "target")
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
				symlinkOrSkipWindows(t, target, path)
			default:
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				if kind == "nonempty" {
					if err := os.WriteFile(filepath.Join(path, "owner"), nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if kind != "symlink" {
				old := time.Now().Add(-time.Hour)
				if err := os.Chtimes(path, old, old); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			lease, err := acquireCredentialLease(ctx, dir, testLeaseOptions())
			if kind == "empty" {
				if err != nil {
					t.Fatal(err)
				}
				if err := lease.release(); err != nil {
					t.Fatal(err)
				}
			} else {
				if err == nil {
					lease.release()
					t.Fatal("unsafe lease reclaimed")
				}
				if _, statErr := os.Lstat(path); statErr != nil {
					t.Fatal("unsafe lease removed")
				}
			}
		})
	}
}

func TestCredentialLeaseCompromiseAndSuccessorSafeRelease(t *testing.T) {
	for _, change := range []string{"successor", "mtime", "symlink"} {
		t.Run(change, func(t *testing.T) {
			dir := t.TempDir()
			options := testLeaseOptions()
			options.heartbeat = time.Hour
			lease, err := acquireCredentialLease(context.Background(), dir, options)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "successor":
				if err := os.Rename(lease.path, lease.path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(lease.path, 0700); err != nil {
					t.Fatal(err)
				}
			case "mtime":
				future := time.Now().Add(time.Hour)
				if err := os.Chtimes(lease.path, future, future); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(lease.path, lease.path+".old"); err != nil {
					t.Fatal(err)
				}
				symlinkOrSkipWindows(t, lease.path+".old", lease.path)
			}
			if err := lease.check(); !isAuthConflict(err) {
				t.Fatalf("compromise error = %v", err)
			}
			if err := lease.release(); !isAuthConflict(err) {
				t.Fatalf("release error = %v", err)
			}
			if _, err := os.Lstat(lease.path); err != nil {
				t.Fatal("release removed changed/successor lease")
			}
		})
	}
}

func TestCredentialLeaseRefusesUnsafeMarker(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkipWindows(t, target, filepath.Join(dir, ".credential-transaction"))
	if lease, err := acquireCredentialLease(context.Background(), dir, testLeaseOptions()); err == nil {
		lease.release()
		t.Fatal("symlink marker accepted")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "unchanged" {
		t.Fatal("marker target altered")
	}
}
