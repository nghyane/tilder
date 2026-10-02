package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/nghyane/tilder/go/internal/clock"
	"github.com/nghyane/tilder/go/internal/service"
	"github.com/nghyane/tilder/go/internal/update"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// How often the agent asks for a newer release (ADR 0023), and how long a
// just-installed release has to reach the server before the old one comes
// back.
const (
	firstCheck  = time.Minute
	checkEvery  = 6 * time.Hour
	proveWithin = time.Minute
)

// updateGap is the least time between two checks: the console's "update
// now" cannot make the machine download again and again (ADR 0026).
const updateGap = time.Minute

// updateAsk is the console's "update now", waiting for how it went.
type updateAsk chan<- *tilderv1.UpdateResult

// askUpdate hands the console's "update now" to autoUpdate. An update already
// under way (autoUpdate not listening) is BUSY, never queued.
func askUpdate(asks chan<- updateAsk) func(ctx context.Context) *tilderv1.UpdateResult {
	return func(ctx context.Context) *tilderv1.UpdateResult {
		reply := make(chan *tilderv1.UpdateResult, 1)
		select {
		case asks <- reply:
		default:
			return &tilderv1.UpdateResult{State: tilderv1.UpdateResult_STATE_BUSY}
		}
		select {
		case r := <-reply:
			return r
		case <-ctx.Done():
			return nil
		}
	}
}

// updateResult says how a check went, with a stable code; the detail stays
// in the agent's log.
func updateResult(version string, err error) *tilderv1.UpdateResult {
	failed := func(code tilderv1.UpdateResult_Code) *tilderv1.UpdateResult {
		return &tilderv1.UpdateResult{State: tilderv1.UpdateResult_STATE_FAILED, Code: code}
	}
	switch {
	case err == nil:
		return &tilderv1.UpdateResult{State: tilderv1.UpdateResult_STATE_STARTED, Version: version}
	case errors.Is(err, update.ErrNotNewer):
		return &tilderv1.UpdateResult{State: tilderv1.UpdateResult_STATE_UP_TO_DATE}
	case errors.Is(err, update.ErrNoReleaseKey):
		return failed(tilderv1.UpdateResult_CODE_NO_RELEASE_KEY)
	case errors.Is(err, update.ErrFetch):
		return failed(tilderv1.UpdateResult_CODE_FETCH)
	case errors.Is(err, update.ErrRelease), errors.Is(err, update.ErrMismatch):
		return failed(tilderv1.UpdateResult_CODE_SIGNATURE)
	default:
		return failed(tilderv1.UpdateResult_CODE_INSTALL)
	}
}

// checker runs one check at a time, at most one per updateGap.
type checker struct {
	clk     clock.Clock
	install func(context.Context) (string, error)
	last    time.Time
}

// check installs a newer release if there is one; tooSoon reports that the
// last check was under updateGap ago, and nothing was fetched.
func (c *checker) check(ctx context.Context) (version string, tooSoon bool, err error) {
	now := c.clk.Now()
	if !c.last.IsZero() && now.Sub(c.last) < updateGap {
		return "", true, nil
	}
	c.last = now
	version, err = c.install(ctx)
	return version, false, err
}

// autoUpdate checks for a newer release now and then, and when the console
// asks (asks), and says which one it installed. A build without the release
// key never updates, and says so when asked.
func autoUpdate(ctx context.Context, server, home string, clk clock.Clock, log *slog.Logger, asks <-chan updateAsk, installed chan<- string) {
	u, err := updater(server, home, clk)
	if err != nil {
		log.Info("updates off", slog.Any("error", err))
		for {
			select {
			case <-ctx.Done():
				return
			case reply := <-asks:
				reply <- updateResult("", update.ErrNoReleaseKey)
			}
		}
	}
	c := &checker{clk: clk, install: u.Install}
	wait := firstCheck
	if every := os.Getenv("TILDER_UPDATE_EVERY"); every != "" {
		// Tests shorten the wait; nothing else sets it.
		if d, perr := time.ParseDuration(every); perr == nil {
			wait = d
		}
	}
	for {
		t := clk.NewTimer(wait, "update", "check")
		var reply updateAsk
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		case reply = <-asks:
			t.Stop()
		}
		v, tooSoon, err := c.check(ctx)
		if reply != nil {
			if tooSoon {
				reply <- &tilderv1.UpdateResult{State: tilderv1.UpdateResult_STATE_TOO_SOON}
				continue
			}
			reply <- updateResult(v, err)
		}
		switch {
		case tooSoon:
		case err == nil:
			installed <- v
			return
		case !errors.Is(err, update.ErrNotNewer):
			log.Warn("update failed", slog.Any("error", err))
		}
		if wait < checkEvery && os.Getenv("TILDER_UPDATE_EVERY") == "" {
			wait = checkEvery
		}
	}
}

// updater is this binary's updater, or why it has none.
func updater(server, home string, clk clock.Clock) (*update.Updater, error) {
	root, err := base64.RawURLEncoding.DecodeString(releaseRoot)
	if err != nil || len(root) != ed25519.PublicKeySize {
		return nil, update.ErrNoReleaseKey
	}
	base, err := httpBase(server)
	if err != nil {
		return nil, err
	}
	binary, err := os.Executable()
	if err == nil {
		binary, err = filepath.EvalSymlinks(binary)
	}
	if err != nil {
		return nil, fmt.Errorf("find this binary: %w", err)
	}
	return &update.Updater{
		Base: base, Root: root, Running: version, Binary: binary,
		Asset: "tilder-" + runtime.GOOS + "-" + runtime.GOARCH, Home: home,
		Client: &http.Client{Timeout: 5 * time.Minute}, Clock: clk,
	}, nil
}

// maxUnprovenStarts is how many times a just-installed release may start
// without proving itself before the previous one comes back (ADR 0041):
// 3 × RestartSec=5 stays well inside systemd's StartLimitBurst.
const maxUnprovenStarts = 3

// thisBinary is the running binary's real path.
func thisBinary() (string, error) {
	binary, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(binary)
}

// watchUpdate starts the proving window of a just-installed release: if it
// does not reach the server in time, the previous binary is put back and
// rolledBack fires, for the agent to restart into it. proved marks the
// release proved.
func watchUpdate(home string, clk clock.Clock, log *slog.Logger) (proved func(), rolledBack <-chan struct{}) {
	back := make(chan struct{}, 1)
	if !update.Pending(home, version) {
		return func() {}, back
	}
	binary, err := thisBinary()
	if err != nil {
		// Nothing to go back to without the path: keep the new release.
		update.Proven(home)
		return func() {}, back
	}
	t := clk.AfterFunc(proveWithin, func() {
		log.Error("the new release did not reach the server; going back to the previous one", slog.String("version", version))
		if err := update.RollBack(home, binary); err != nil {
			log.Error("could not go back", slog.Any("error", err))
			return
		}
		back <- struct{}{}
	}, "update", "prove")
	return func() {
		if t.Stop() {
			update.Proven(home)
			log.Info("the new release reached the server", slog.String("version", version))
		}
	}, back
}

// httpBase is the server's web origin, from the WebSocket URL the agent dials.
func httpBase(server string) (string, error) {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return "", errors.New("the server address is not a URL")
	}
	scheme := "https"
	if u.Scheme == "ws" {
		scheme = "http"
	}
	return scheme + "://" + u.Host, nil
}

// underService reports whether systemd, launchd or tilder's Windows
// monitor (ADR 0044) runs this process. A Terminal session on macOS sets
// XPC_SERVICE_NAME too ("0"), so only our own LaunchAgent's label counts.
func underService(getenv func(string) string) bool {
	return getenv("INVOCATION_ID") != "" || strings.HasPrefix(getenv("XPC_SERVICE_NAME"), "run.tilder.") ||
		getenv(service.HiddenEnv) != ""
}

// errRestart has main exit with restartExit: the Windows monitor starts the
// agent again only when it exits non-zero, 0 being an agent that meant to
// stop (ADR 0044).
var errRestart = errors.New("restarting into the new release")

// restartExit is EX_TEMPFAIL: "try again".
const restartExit = 75

// restart runs the new binary. Under a service manager, exiting is enough:
// systemd (Restart=always) and launchd (KeepAlive) start it again, and the
// Windows monitor on a non-zero exit. Run by hand or in the background, the
// process replaces itself (restart_unix.go, restart_windows.go).
func restart() error {
	if underService(os.Getenv) {
		if runtime.GOOS == "windows" {
			return errRestart
		}
		return nil
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	return replaceSelf(binary)
}
