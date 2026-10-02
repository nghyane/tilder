package main

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/coder/quartz"

	"github.com/nghyane/tilder/go/internal/update"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// A Terminal on macOS sets XPC_SERVICE_NAME=0: an agent run there must
// replace itself after an update, not exit and wait for a launchd that is
// not watching it.
func TestOnlyOurServiceCountsAsAService(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		invocation, xpc, monitor string
		want                     bool
	}{
		{"", "", "", false},
		{"", "0", "", false},
		{"", "application.com.apple.Terminal.1234", "", false},
		{"", "run.tilder.agent", "", true},
		{"0123abcd", "", "", true},
		// tilder's Windows monitor (ADR 0044): it starts the new release when
		// the agent exits non-zero.
		{"", "", "1", true},
	} {
		env := map[string]string{"INVOCATION_ID": tc.invocation, "XPC_SERVICE_NAME": tc.xpc, "TILDER_MONITOR": tc.monitor}
		if got := underService(func(k string) string { return env[k] }); got != tc.want {
			t.Errorf("INVOCATION_ID=%q XPC_SERVICE_NAME=%q TILDER_MONITOR=%q: under a service %v, want %v",
				tc.invocation, tc.xpc, tc.monitor, got, tc.want)
		}
	}
}

func TestUpdatesComeFromTheServersWebOrigin(t *testing.T) {
	t.Parallel()
	for server, want := range map[string]string{
		"wss://tilder.example.com/agent":  "https://tilder.example.com",
		"ws://127.0.0.1:8080/agent":       "http://127.0.0.1:8080",
		"wss://tilder.example.com:8443/x": "https://tilder.example.com:8443",
	} {
		if got, err := httpBase(server); err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", server, got, err, want)
		}
	}
	if _, err := httpBase("not a url"); err == nil {
		t.Error("a server that is not a URL was taken")
	}
}

// ADR 0026: how a check went reaches the console as a stable code, whatever
// the error's wording.
func TestAnUpdateSaysHowItWentInAStableCode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		err   error
		state tilderv1.UpdateResult_State
		code  tilderv1.UpdateResult_Code
	}{
		{nil, tilderv1.UpdateResult_STATE_STARTED, tilderv1.UpdateResult_CODE_UNSPECIFIED},
		{update.ErrNotNewer, tilderv1.UpdateResult_STATE_UP_TO_DATE, tilderv1.UpdateResult_CODE_UNSPECIFIED},
		{update.ErrNoReleaseKey, tilderv1.UpdateResult_STATE_FAILED, tilderv1.UpdateResult_CODE_NO_RELEASE_KEY},
		{fmt.Errorf("%w: %w", update.ErrFetch, errors.New("dial tcp: refused")), tilderv1.UpdateResult_STATE_FAILED, tilderv1.UpdateResult_CODE_FETCH},
		{update.ErrRelease, tilderv1.UpdateResult_STATE_FAILED, tilderv1.UpdateResult_CODE_SIGNATURE},
		{update.ErrMismatch, tilderv1.UpdateResult_STATE_FAILED, tilderv1.UpdateResult_CODE_SIGNATURE},
		{errors.New("rename: permission denied"), tilderv1.UpdateResult_STATE_FAILED, tilderv1.UpdateResult_CODE_INSTALL},
	} {
		r := updateResult("0.7.0", tc.err)
		if r.GetState() != tc.state || r.GetCode() != tc.code {
			t.Errorf("%v: %v %v, want %v %v", tc.err, r.GetState(), r.GetCode(), tc.state, tc.code)
		}
	}
}

// Two checks are at least a minute apart, however often the button is
// pressed: the second fetches nothing.
func TestChecksAreAMinuteApart(t *testing.T) {
	t.Parallel()
	clk := quartz.NewMock(t)
	installs := 0
	c := &checker{clk: clk, install: func(context.Context) (string, error) {
		installs++
		return "", update.ErrNotNewer
	}}
	if _, soon, _ := c.check(t.Context()); soon {
		t.Fatal("the first check was too soon")
	}
	clk.Advance(30 * time.Second)
	if _, soon, _ := c.check(t.Context()); !soon || installs != 1 {
		t.Fatalf("30 s later: too soon %v, %d installs", soon, installs)
	}
	clk.Advance(31 * time.Second)
	if _, soon, _ := c.check(t.Context()); soon || installs != 2 {
		t.Fatalf("61 s later: too soon %v, %d installs", soon, installs)
	}
}

// An update under way (nobody listening) is BUSY at once, not queued behind it.
func TestAnUpdateUnderWayIsBusy(t *testing.T) {
	t.Parallel()
	asks := make(chan updateAsk) // nobody reads: the loop is installing
	if r := askUpdate(asks)(t.Context()); r.GetState() != tilderv1.UpdateResult_STATE_BUSY {
		t.Fatalf("got %v", r)
	}
}
