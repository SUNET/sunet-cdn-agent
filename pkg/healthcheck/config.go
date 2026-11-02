// Package healthcheck lets an l4lb node probe the cache nodes and take the
// ones that are clearly not serving out of ipvs rotation.
package healthcheck

import (
	"fmt"
	"net/netip"
	"time"
)

// Mode selects what the health checker does with its decisions.
type Mode string

const (
	// ModeOff disables health checking.
	ModeOff Mode = "off"
	// ModeObserve probes, decides, logs and exports metrics, but never
	// changes ipvs weights.
	ModeObserve Mode = "observe"
	// ModeEnforce is like ModeObserve and also sets the weight of down
	// nodes to 0.
	ModeEnforce Mode = "enforce"
)

// DefaultPort is the default port of the health service on cache nodes.
const DefaultPort = 8088

// The decision rules are deliberately conservative: this is a DDoS
// protection service, and taking a stressed node out of rotation pushes its
// share of an attack onto the remaining nodes.
const (
	probeInterval = 3 * time.Second
	probeTimeout  = 2 * time.Second

	// downAfter consecutive failures are needed before a node is taken out.
	downAfter = 8
	// upAfter consecutive successes put a node that was taken out back.
	upAfter = 10
	// Nothing is taken out when more than this fraction of the other nodes
	// of the same address family is failing too, since that looks like an
	// attack or a problem on our side rather than a dead node.
	maxFailingFraction = 0.25
	// maxDown is how many nodes per address family health checking may have
	// taken out at the same time. All addresses of one node count as one.
	maxDown = 1
)

// Config is the health checker configuration.
type Config struct {
	Mode Mode
	Port uint16
	// NetNS is the network namespace to probe from, empty for the current
	// one.
	NetNS      string
	SourceIPv4 netip.Addr
	SourceIPv6 netip.Addr
}

// ParseMode parses a mode name.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(s); m {
	case ModeOff, ModeObserve, ModeEnforce:
		return m, nil
	default:
		return "", fmt.Errorf("unknown health check mode %q, must be off, observe or enforce", s)
	}
}
