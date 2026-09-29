//go:build unix

package state

import (
	"errors"
	"os"
)

// syncDir makes a rename durable: the directory entry itself is data.
func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: the agent's own home
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}
