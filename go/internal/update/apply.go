package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/nghyane/tilder/go/internal/clock"
)

// Updater checks the server for a newer release and installs it next to the
// running binary. It only ever writes the binary it runs as, its .prev copy,
// and a marker in the agent's home.
type Updater struct {
	// Base is the server as http(s)://host, where /dist/ lives.
	Base    string
	Root    ed25519.PublicKey
	Running string
	// Binary is the running executable; Asset its name in a release.
	Binary string
	Asset  string
	Home   string
	Client *http.Client
	Clock  clock.Clock
}

// markerFile says an update was just installed: the new binary must reach
// the server soon, or the old one comes back.
const markerFile = "update.json"

type marker struct {
	From string `json:"from"`
	To   string `json:"to"`
	// Starts counts the new binary's starts before it proved itself (ADR
	// 0041): one that dies before its proving timer is set never rolls back
	// by that timer.
	Starts int `json:"starts,omitempty"`
}

// ErrNotNewer means the server has nothing newer than what runs.
var ErrNotNewer = errors.New("update: nothing newer")

// The other ways Install fails, told apart so the console can say which
// (ADR 0026); ErrRelease (release.go) is the signature's.
var (
	// ErrNoReleaseKey: a dev build, which never updates.
	ErrNoReleaseKey = errors.New("update: this build has no release key")
	// ErrFetch: the server could not be read.
	ErrFetch = errors.New("update: could not fetch the release")
	// ErrMismatch: the download is not the file the release signed.
	ErrMismatch = errors.New("update: the download does not match the signed release")
)

// Install fetches and installs a newer release, if the server has one. It
// returns the version installed; the caller then restarts into it.
func (u *Updater) Install(ctx context.Context) (string, error) {
	if len(u.Root) != ed25519.PublicKeySize {
		return "", ErrNoReleaseKey
	}
	current, err := u.fetch(ctx, "/dist/current", 64)
	if err != nil {
		return "", err
	}
	version := strings.TrimSpace(string(current))
	if !Newer(version, u.Running) {
		return "", ErrNotNewer
	}
	rel, err := u.verified(ctx, version)
	if err != nil {
		return "", err
	}
	if rel.Version != version {
		return "", ErrRelease
	}
	file, ok := rel.File(u.Asset)
	if !ok {
		return "", fmt.Errorf("update: release %s has no %s", version, u.Asset)
	}
	if err := u.download(ctx, version, file); err != nil {
		return "", err
	}
	return version, nil
}

// verified is the release for version, checked against the built-in root.
func (u *Updater) verified(ctx context.Context, version string) (Release, error) {
	get := func(name string, limit int64) ([]byte, error) {
		return u.fetch(ctx, "/dist/"+version+"/"+name, limit)
	}
	keyText, err := get("signing.txt", 256)
	if err != nil {
		return Release{}, err
	}
	keySig, err := get("signing.sig", 128)
	if err != nil {
		return Release{}, err
	}
	relText, err := get("release.txt", 4096)
	if err != nil {
		return Release{}, err
	}
	relSig, err := get("release.sig", 128)
	if err != nil {
		return Release{}, err
	}
	ks, err1 := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(keySig)))
	rs, err2 := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(relSig)))
	if err1 != nil || err2 != nil {
		return Release{}, ErrRelease
	}
	return Verify(u.Root, string(keyText), ks, string(relText), rs, u.Clock.Now())
}

// download writes the binary beside the running one, checks it, keeps the
// running one as .prev, and renames the new one into place: never written
// in place (macOS kills a signed binary rewritten in place; Linux refuses to
// write a running one; Windows refuses to replace one, so it is renamed
// away first, swap.go).
func (u *Updater) download(ctx context.Context, version string, file File) error {
	body, err := u.open(ctx, "/dist/"+version+"/"+file.Name)
	if err != nil {
		return err
	}
	defer func() { _ = body.Close() }()
	unverified := u.Binary + ".unverified"
	out, err := os.OpenFile(unverified, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700) //nolint:gosec // G304: beside our own binary
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(body, file.Size+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	if err != nil || !file.SameBytes(sum, n) {
		_ = os.Remove(unverified)
		if err == nil {
			err = ErrMismatch
		}
		return err
	}
	if err := os.Chmod(unverified, 0o755); err != nil { //nolint:gosec // G302: an executable
		return err
	}
	if err := keepPrevious(u.Binary, renameRunning); err != nil {
		_ = os.Remove(unverified)
		return fmt.Errorf("keep the running binary: %w", err)
	}
	if err := writeMarker(u.Home, marker{From: u.Running, To: version}); err != nil {
		if renameRunning {
			_ = os.Rename(u.Binary+".prev", u.Binary)
		}
		return err
	}
	return putNew(u.Binary, unverified, renameRunning)
}

func (u *Updater) open(ctx context.Context, path string) (rc io.ReadCloser, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %w", ErrFetch, err)
		}
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.Base+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := u.Client.Do(req) //nolint:gosec // G704: the configured server; what it sends is checked
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("update: %s: %s", path, resp.Status)
	}
	return resp.Body, nil
}

func (u *Updater) fetch(ctx context.Context, path string, limit int64) ([]byte, error) {
	body, err := u.open(ctx, path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = body.Close() }()
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err == nil && int64(len(data)) > limit {
		err = fmt.Errorf("update: %s is too long", path)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	return data, nil
}

func writeMarker(home string, m marker) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(home, markerFile), data, 0o600)
}

// Pending reports whether this process is a just-installed update that has
// not proved itself yet (the marker names the running version).
func Pending(home, running string) bool {
	data, err := os.ReadFile(filepath.Join(home, markerFile)) //nolint:gosec // G304: the agent's own home
	if err != nil {
		return false
	}
	var m marker
	return json.Unmarshal(data, &m) == nil && m.To == running
}

// Started counts a start of the running binary while it has not proved
// itself (ADR 0041); past maxStarts it puts the previous binary back and
// reports true, for the process to exit so the service manager starts the
// old one. It runs before anything that can fail: a release that errors or
// crashes at every start never reaches the timer that would roll it back.
// The count is synced to disk before the start goes on.
func Started(home, running, binary string, maxStarts int) (bool, error) {
	data, rerr := os.ReadFile(filepath.Join(home, markerFile)) //nolint:gosec // G304: the agent's own home
	var m marker
	if rerr != nil || json.Unmarshal(data, &m) != nil || m.To != running {
		return false, nil //nolint:nilerr // no marker (or another version's): no update being proved
	}
	m.Starts++
	if m.Starts > maxStarts {
		return true, RollBack(home, binary)
	}
	return false, syncMarker(home, m)
}

// syncMarker writes the marker and syncs it, then renames it into place.
func syncMarker(home string, m marker) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := filepath.Join(home, markerFile+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // G304: the agent's own home
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(home, markerFile))
}

// Proven clears the marker: the new binary reached the server.
func Proven(home string) { _ = os.Remove(filepath.Join(home, markerFile)) }

// RollBack puts the previous binary back and clears the marker: the update
// never reached the server. The service manager then starts the old one.
func RollBack(home, binary string) error {
	Proven(home)
	return putBack(binary, renameRunning)
}
