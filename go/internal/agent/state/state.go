// Package state is what an agent keeps on disk, in its home (~/.tilder): the
// machine key and how to reach its owner. Files are written atomically and
// readable only by their owner.
package state

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/nghyane/tilder/go/internal/identity"
)

const (
	keyFile    = "identity.json"
	configFile = "config.json"
)

// Config is how this machine reaches its owner. JoinSecret is present only
// until the first successful connection, then erased: a secret that stays on
// disk is a door that stays open (the v1 agent kept its join token and
// reopened pairing on every start).
type Config struct {
	Server     string `json:"server"`
	Owner      string `json:"owner"` // identity.RootPublic text form, pinned from the join command
	JoinSecret string `json:"joinSecret,omitempty"`
}

// OwnerKey parses the pinned owner key.
func (c Config) OwnerKey() (identity.RootPublic, error) { return identity.ParseRootPublic(c.Owner) }

type keyFileV1 struct {
	Version int    `json:"version"`
	Seed    string `json:"seed"`
}

// MachineKey loads the machine key from home, creating it on first run.
func MachineKey(home string) (identity.MachinePrivate, error) {
	path := filepath.Join(home, keyFile)
	raw, readErr := os.ReadFile(path) //nolint:gosec // G304: the agent's own home
	if errors.Is(readErr, fs.ErrNotExist) {
		return createMachineKey(path)
	}
	if readErr != nil {
		return identity.MachinePrivate{}, readErr
	}
	var file keyFileV1
	if json.Unmarshal(raw, &file) != nil || file.Version != 1 {
		return identity.MachinePrivate{}, fmt.Errorf("%s is not a v1 key file", path)
	}
	seed, decodeErr := base64.RawURLEncoding.DecodeString(file.Seed)
	if decodeErr != nil {
		return identity.MachinePrivate{}, decodeErr
	}
	return identity.MachinePrivateFromSeed(seed)
}

func createMachineKey(path string) (identity.MachinePrivate, error) {
	key, err := identity.NewMachinePrivate(rand.Reader)
	if err != nil {
		return identity.MachinePrivate{}, err
	}
	body, err := json.Marshal(keyFileV1{Version: 1, Seed: base64.RawURLEncoding.EncodeToString(key.Seed())})
	if err != nil {
		return identity.MachinePrivate{}, err
	}
	return key, writeAtomic(path, body)
}

// LoadConfig reads the config; a missing file means the agent never joined.
func LoadConfig(home string) (Config, error) {
	raw, err := os.ReadFile(filepath.Join(home, configFile)) //nolint:gosec // G304: the agent's own home
	if err != nil {
		return Config{}, err
	}
	var c Config
	return c, json.Unmarshal(raw, &c)
}

// SaveConfig writes the config atomically, 0600.
func SaveConfig(home string, c Config) error {
	body, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(home, configFile), body)
}

// writeAtomic writes a temp file beside path (0600 from the first byte),
// syncs it, renames it over path and syncs the directory: a crash leaves the
// old file or the new one, never half of one.
func writeAtomic(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := privateDir(dir); err != nil {
		return fmt.Errorf("keep %s to its owner: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, werr := tmp.Write(body)
	serr := tmp.Sync()
	cerr := tmp.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(dir)
}

const revocationsFile = "revocations.json"

type revocationsFileV1 struct {
	Version   int    `json:"version"`
	Statement string `json:"statement"`
	Signature string `json:"signature"`
}

// Revocations keeps the owner's newest signed list of removed devices (ADR
// 0004) under home, so a restarted agent still refuses them before it has
// heard from the server.
type Revocations struct{ Home string }

// Load returns the stored list, if any. A file that cannot be read is an
// error, never "none": a removed device must not get in through a bad file.
func (r Revocations) Load() (statement string, signature []byte, ok bool, err error) {
	raw, err := os.ReadFile(filepath.Join(r.Home, revocationsFile)) //nolint:gosec // G304: the agent's own home
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil, false, nil
	}
	if err != nil {
		return "", nil, false, err
	}
	var file revocationsFileV1
	if json.Unmarshal(raw, &file) != nil || file.Version != 1 {
		return "", nil, false, fmt.Errorf("%s is not a v1 revocations file", revocationsFile)
	}
	sig, err := base64.RawURLEncoding.DecodeString(file.Signature)
	if err != nil {
		return "", nil, false, err
	}
	return file.Statement, sig, true, nil
}

// Save writes the list atomically and synced, before the agent acts on it.
func (r Revocations) Save(statement string, signature []byte) error {
	body, err := json.Marshal(revocationsFileV1{
		Version: 1, Statement: statement, Signature: base64.RawURLEncoding.EncodeToString(signature),
	})
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(r.Home, revocationsFile), body)
}

const connectedFile = "connected.json"

type connectedFileV1 struct {
	Version int   `json:"version"`
	AtMs    int64 `json:"at_ms"`
}

// MarkConnected records that the server welcomed the machine: the install
// script waits for this file, so an agent that cannot start or cannot get in
// is reported there instead of leaving the console waiting (ADR 0020).
func MarkConnected(home string, at time.Time) error {
	body, err := json.Marshal(connectedFileV1{Version: 1, AtMs: at.UnixMilli()})
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(home, connectedFile), body)
}
