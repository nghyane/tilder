package service

import (
	"context"
	"fmt"
	"strings"
)

// keepAfterLogout turns lingering on, so systemd keeps the owner's units
// running with no login session: without it, closing the last ssh session
// stops the agent (ADR 0030). Refused, the install still stands and the
// note says how to do it by hand; tilder never runs sudo itself.
func (m Manager) keepAfterLogout(ctx context.Context) string {
	if m.lingering(ctx) {
		return ""
	}
	out, err := m.Run(ctx, "loginctl", "enable-linger")
	if err == nil && m.lingering(ctx) {
		return "it keeps running after you log out and after a reboot (loginctl enable-linger)"
	}
	why := strings.TrimSpace(string(out))
	if why == "" && err != nil {
		why = err.Error()
	}
	return fmt.Sprintf("it stops when you log out: loginctl enable-linger was refused (%s); to keep it running, run: sudo loginctl enable-linger $USER", why)
}

func (m Manager) lingering(ctx context.Context) bool {
	out, _ := m.Run(ctx, "loginctl", "show-user", fmt.Sprint(m.Spec.UID), "--property=Linger", "--value")
	return strings.TrimSpace(string(out)) == "yes"
}
