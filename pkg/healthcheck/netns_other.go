//go:build !linux

package healthcheck

import (
	"errors"
	"fmt"
)

// enterNetNS is only implemented on Linux. Elsewhere dialing in a named
// network namespace fails, which the prober classifies as an error.
func enterNetNS(nsPath string) error {
	return fmt.Errorf("enter network namespace %s: %w", nsPath, errors.ErrUnsupported)
}
