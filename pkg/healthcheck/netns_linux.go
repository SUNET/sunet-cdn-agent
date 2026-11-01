package healthcheck

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// enterNetNS moves the calling OS thread into the network namespace at
// nsPath. The caller must have locked the goroutine to its thread.
func enterNetNS(nsPath string) error {
	fd, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open network namespace %s: %w", nsPath, err)
	}
	defer func() { _ = unix.Close(fd) }()

	if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("enter network namespace %s: %w", nsPath, err)
	}

	return nil
}
