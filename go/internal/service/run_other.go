//go:build !windows

package service

import (
	"context"
	"errors"
)

// HiddenEnv is the Windows monitor's; nothing here reads it.
const HiddenEnv = "TILDER_MONITOR"

var errNotWindows = errors.New("a Run value and a monitor are for Windows")

func (Manager) installRun(context.Context) error          { return errNotWindows }
func (Manager) uninstallRun(context.Context) error        { return errNotWindows }
func (Manager) statusRun(context.Context) (string, error) { return "", errNotWindows }

// Monitor runs the agent as the Windows service does; there is none here.
func (Manager) Monitor(context.Context, bool) error { return errNotWindows }
