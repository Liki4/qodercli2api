package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const authBindingName = ".qoder2api-auth-binding.json"

type authBinding struct {
	Version  int    `json:"version"`
	Region   string `json:"region"`
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
}

type authFileRevision struct {
	exists   bool
	identity os.FileInfo
	digest   [32]byte
}
type authLoginIdentity struct {
	uid, method           string
	timestamp             int64
	access, refresh       string
	expiry, refreshExpiry int64
}
type authSnapshot struct {
	directory              os.FileInfo
	machine, user, binding authFileRevision
	login                  authLoginIdentity
}

// All access is under authManager.mu. A baseline is the LAST SUCCESSFUL disk
// publication/load, never the current dirty in-memory candidate.
type authStore struct {
	dir          string
	machineID    string
	expected     authBinding
	baseline     authSnapshot
	ephemeral    bool
	leaseOptions credentialLeaseOptions
	conflict     error
	// Narrow file-read seam for transient binding IO failures; nil uses the
	// regular-file/identity-checked reader shared by the credential store.
	readBindingFile func(string) ([]byte, authFileRevision, error)
}

type credentialTxn struct {
	store *authStore
	lease *credentialLease
}

func readAuthFile(path string) ([]byte, authFileRevision, error) {
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, authFileRevision{}, nil
	}
	if err != nil {
		return nil, authFileRevision{}, err
	}
	if !before.Mode().IsRegular() {
		return nil, authFileRevision{}, authConflict("credential file is not regular")
	}
	if before.Mode().Perm()&0444 == 0 {
		return nil, authFileRevision{}, fmt.Errorf("credential file is unreadable")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, authFileRevision{}, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, authFileRevision{}, err
	}
	if !os.SameFile(before, opened) {
		return nil, authFileRevision{}, authConflict("credential file changed while opening")
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, authFileRevision{}, err
	}
	after, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) || after.Size() != before.Size() {
		return nil, authFileRevision{}, authConflict("credential file changed while reading")
	}
	return data, authFileRevision{exists: true, identity: after, digest: sha256.Sum256(data)}, nil
}

func sameAuthRevision(a, b authFileRevision) bool {
	if a.exists != b.exists {
		return false
	}
	if !a.exists {
		return true
	}
	return a.digest == b.digest && os.SameFile(a.identity, b.identity) && a.identity.ModTime().Equal(b.identity.ModTime()) && a.identity.Mode() == b.identity.Mode()
}

func (s *authStore) readBinding() (authFileRevision, error) {
	readFile := s.readBindingFile
	if readFile == nil {
		readFile = readAuthFile
	}
	raw, revision, err := readFile(filepath.Join(s.dir, authBindingName))
	if err != nil {
		return revision, err
	}
	if !revision.exists {
		return revision, nil
	}
	var binding authBinding
	if err := json.Unmarshal(raw, &binding); err != nil {
		return revision, authConflict("region binding is invalid")
	}
	if binding != s.expected {
		return revision, authConflict("region or issuer binding does not match")
	}
	return revision, nil
}

func (s *authStore) snapshot() (authSnapshot, error) {
	var snap authSnapshot
	info, err := checkedDirectory(s.dir)
	if err != nil && !(s.ephemeral && errors.Is(err, os.ErrNotExist)) {
		return snap, err
	}
	snap.directory = info
	snap.binding, err = s.readBinding()
	if err != nil {
		return snap, err
	}
	if s.ephemeral {
		return snap, nil
	}
	raw, machine, err := readAuthFile(filepath.Join(s.dir, "machine_id"))
	if err != nil {
		return snap, err
	}
	if !machine.exists || len(machineCredentialKey(strings.TrimSpace(string(raw)))) != 16 || strings.TrimSpace(string(raw)) != s.machineID {
		return snap, authConflict("machine identity is missing or invalid")
	}
	snap.machine = machine
	_, snap.user, err = readAuthFile(filepath.Join(s.dir, "user"))
	return snap, err
}

func (s *authStore) check() error {
	if s.conflict != nil {
		return s.conflict
	}
	current, err := s.snapshot()
	if err == nil {
		a, b := s.baseline.directory, current.directory
		sameDirectory := (a == nil && b == nil) || (a != nil && b != nil && os.SameFile(a, b))
		if !sameDirectory || !sameAuthRevision(s.baseline.binding, current.binding) || (!s.ephemeral && (!sameAuthRevision(s.baseline.machine, current.machine) || !sameAuthRevision(s.baseline.user, current.user))) {
			err = authConflict("persisted credential revision changed")
		}
	}
	if isAuthConflict(err) {
		s.conflict = err
	}
	return err
}

func (s *authStore) begin(ctx context.Context) (*credentialTxn, error) {
	if s.conflict != nil {
		return nil, s.conflict
	}
	if s.ephemeral {
		if err := s.check(); err != nil {
			return nil, err
		}
		return &credentialTxn{store: s}, nil
	}
	lease, err := acquireCredentialLease(ctx, s.dir, s.leaseOptions)
	if err != nil {
		return nil, err
	}
	tx := &credentialTxn{store: s, lease: lease}
	if err := tx.check(); err != nil {
		return nil, errors.Join(err, tx.close())
	}
	return tx, nil
}
func (tx *credentialTxn) check() error {
	if tx == nil {
		return authConflict("credential transaction is unavailable")
	}
	if tx.lease != nil {
		if err := tx.lease.check(); err != nil {
			tx.store.conflict = err
			return err
		}
	}
	return tx.store.check()
}
func (tx *credentialTxn) close() error {
	if tx == nil {
		return nil
	}
	err := tx.lease.release()
	if isAuthConflict(err) {
		tx.store.conflict = err
	}
	return err
}

func writeExclusiveAuthFile(dir, pattern, path string, data []byte, check func() error) error {
	temp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	if err := temp.Chmod(0600); err != nil {
		return err
	}
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	// Link publishes without replacing any concurrently-created identity/metadata.
	return os.Link(temp.Name(), path)
}

func (tx *credentialTxn) installBinding() error {
	s := tx.store
	if s.ephemeral || s.baseline.binding.exists {
		return nil
	}
	if err := tx.check(); err != nil {
		return err
	}
	raw, err := json.Marshal(s.expected)
	if err != nil {
		return err
	}
	err = writeExclusiveAuthFile(s.dir, ".binding-*", filepath.Join(s.dir, authBindingName), raw, tx.check)
	if err != nil {
		return err
	}
	revision, err := s.readBinding()
	if err != nil {
		return err
	}
	s.baseline.binding = revision
	return nil
}

func (tx *credentialTxn) publish(staged *stagedCredential, ui *userInfo) error {
	if err := tx.check(); err != nil {
		return err
	}
	if tx.store.ephemeral {
		return nil
	}
	if err := tx.installBinding(); err != nil {
		return err
	}
	if err := tx.check(); err != nil {
		return err
	}
	_, revision, err := readAuthFile(staged.tempPath)
	if err != nil {
		return err
	}
	if err := staged.publish(); err != nil {
		return err
	}
	tx.store.baseline.user = revision
	tx.store.baseline.login = loginIdentity(ui)
	return nil
}

func loginIdentity(ui *userInfo) authLoginIdentity {
	if ui == nil {
		return authLoginIdentity{}
	}
	return authLoginIdentity{ui.UID, ui.LoginMethod, ui.LoginTimestamp, ui.SecurityOAuthToken, ui.RefreshToken, ui.ExpireTime, ui.RefreshTokenExpireTime}
}

func machineIDUnderLease(dir string, lease *credentialLease) (string, error) {
	path := filepath.Join(dir, "machine_id")
	raw, revision, err := readAuthFile(path)
	if err != nil {
		return "", err
	}
	if revision.exists {
		id := strings.TrimSpace(string(raw))
		if len(machineCredentialKey(id)) != 16 {
			return "", authConflict("machine identity is empty or invalid")
		}
		return id, nil
	}
	for _, name := range []string{"user", "user.daily", "user.test"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			return "", authConflict("machine identity is missing beside existing credentials")
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	id := newUUID()
	err = writeExclusiveAuthFile(dir, ".machine_id-*", path, []byte(id), func() error {
		if err := lease.check(); err != nil {
			return err
		}
		for _, name := range []string{"user", "user.daily", "user.test"} {
			if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
				return authConflict("credentials appeared before machine identity publication")
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		return nil
	})
	if errors.Is(err, os.ErrExist) {
		raw, _, err = readAuthFile(path)
		if err != nil {
			return "", err
		}
		id = strings.TrimSpace(string(raw))
		if len(machineCredentialKey(id)) != 16 {
			return "", authConflict("existing machine identity is invalid")
		}
		return id, nil
	}
	if err != nil {
		return "", err
	}
	return id, nil
}

func loadOrCreateMachineID(dir string) (id string, err error) {
	if _, err = ensureAuthDirectory(dir); err != nil {
		return "", err
	}
	lease, err := acquireCredentialLease(context.Background(), dir, credentialLeaseOptions{})
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, lease.release()) }()
	return machineIDUnderLease(dir, lease)
}
