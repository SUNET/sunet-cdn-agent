package healthcheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

// threadNetNS returns the network namespace of the calling OS thread.
func threadNetNS(t *testing.T) string {
	t.Helper()
	ns, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		t.Errorf("read thread network namespace: %v", err)
	}
	return ns
}

func TestDialInNetNSLeavesCallerNamespace(t *testing.T) {
	// Creating a network namespace needs root and the ip command.
	if os.Geteuid() != 0 {
		t.Skip("skipping: creating a network namespace requires root")
	}
	ipCmd, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("skipping: ip command not found")
	}

	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(ipCmd, args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
	}

	name := fmt.Sprintf("hc-test-%d", os.Getpid())
	ip("netns", "add", name)
	t.Cleanup(func() {
		if out, err := exec.Command(ipCmd, "netns", "delete", name).CombinedOutput(); err != nil {
			t.Errorf("ip netns delete %s: %v: %s", name, err, out)
		}
	})

	// Every thread starts out in this namespace and must still be in it
	// after the dials.
	before := threadNetNS(t)

	dial := dialContextInNetNS(name, &net.Dialer{})
	dialOnce := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, err := dial(ctx, "tcp", "127.0.0.1:1")
		if err == nil {
			_ = conn.Close()
		}
		return err
	}

	// Loopback is down in a new namespace, so 127.0.0.1 is unreachable
	// there, unlike in the caller's namespace. This shows the dial really
	// happens inside the namespace.
	if err := dialOnce(); !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("dial with loopback down: err = %v, want ENETUNREACH", err)
	}

	ip("-n", name, "link", "set", "lo", "up")

	for i := range 50 {
		if err := dialOnce(); !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("dial %d: err = %v, want ECONNREFUSED", i, err)
		}
	}

	// Lock 50 goroutines at the same time so that each checks a different OS
	// thread, and verify that all of those threads are still in the
	// namespace the test started in rather than in the test namespace. They
	// are held until all have checked, otherwise the scheduler could reuse
	// one thread and the same thread would be checked over and over.
	const goroutines = 50
	var read, wg sync.WaitGroup
	release := make(chan struct{})
	read.Add(goroutines)
	for range goroutines {
		wg.Go(func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if got := threadNetNS(t); got != before {
				t.Errorf("thread network namespace = %q, want %q", got, before)
			}
			read.Done()
			<-release
		})
	}
	read.Wait()
	close(release)
	wg.Wait()
}
