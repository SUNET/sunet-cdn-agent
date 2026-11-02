package healthcheck

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
)

// netnsDir is where iproute2 keeps named network namespaces.
const netnsDir = "/run/netns"

// dialFunc has the signature of net.Dialer.DialContext and
// http.Transport.DialContext.
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// dialContextInNetNS returns a DialContext function that creates its sockets
// inside the named network namespace. With an empty netns it dials in the
// caller's namespace.
//
// Each dial enters the namespace on a dedicated, locked OS thread that is
// never unlocked. When that goroutine exits, the Go runtime terminates the
// thread instead of returning it to the pool, so no other goroutine ever runs
// in the namespace. The main thread is the exception, it can't be terminated
// and would be parked forever instead, which is why an init() in package main
// locks the main goroutine to it.
//
// The address must be an IP literal: name resolution would happen on other
// goroutines, outside the namespace.
func dialContextInNetNS(netns string, d *net.Dialer) dialFunc {
	if netns == "" {
		return d.DialContext
	}

	nsPath := filepath.Join(netnsDir, netns)

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		type result struct {
			conn net.Conn
			err  error
		}

		ch := make(chan result)

		go func() {
			runtime.LockOSThread() // never unlocked: the goroutine exits and Go discards the thread

			if err := enterNetNS(nsPath); err != nil {
				ch <- result{err: err}
				return
			}

			conn, err := d.DialContext(ctx, network, address)
			ch <- result{conn: conn, err: err}
		}()

		// DialContext returns when ctx is done, so this does not outlive
		// the caller's deadline.
		r := <-ch
		return r.conn, r.err
	}
}
