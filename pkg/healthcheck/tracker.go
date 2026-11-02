package healthcheck

import (
	"maps"
	"net/netip"
	"slices"
	"strings"
)

// NodeKey identifies one address of a cache node. Each address is judged on
// its own, so an IPv6 problem only affects the IPv6 real-servers.
type NodeKey struct {
	NodeID string
	Addr   netip.Addr
}

func (k NodeKey) compare(o NodeKey) int {
	if c := strings.Compare(k.NodeID, o.NodeID); c != 0 {
		return c
	}
	return k.Addr.Compare(o.Addr)
}

// Observation is the result of probing one cache node address.
type Observation struct {
	Node     NodeKey
	NodeName string
	Outcome  Outcome
}

// TransitionKind is the kind of a Transition.
type TransitionKind string

const (
	// TransitionDown means the address was taken out of rotation.
	TransitionDown TransitionKind = "down"
	// TransitionUp means the address was put back in rotation.
	TransitionUp TransitionKind = "up"
	// TransitionBlocked means the address would have been taken out, but
	// too many other nodes are failing or too many are already out.
	TransitionBlocked TransitionKind = "blocked"
)

// Transition is a decision made by the Tracker.
type Transition struct {
	Kind     TransitionKind
	Node     NodeKey
	NodeName string
}

type nodeState struct {
	name          string
	down          bool
	blocked       bool
	failStreak    int
	successStreak int
	last          Outcome
}

// Tracker decides from probe rounds which cache node addresses are down. It
// is not safe for concurrent use.
type Tracker struct {
	nodes map[NodeKey]*nodeState
}

// NewTracker returns a Tracker where every node starts in rotation.
func NewTracker() *Tracker {
	return &Tracker{nodes: map[NodeKey]*nodeState{}}
}

// Update records one probe round, which must contain every address to track,
// and returns the decisions made.
//
// An address is taken out after downAfter consecutive failures, but only in a
// round where it failed, and only if at most maxFailingFraction of the other
// nodes of the same family are failing and fewer than maxDown other nodes
// have an address of that family out. A node's own addresses do not count
// against each other, so all addresses of a dead node can be taken out. It is
// put back after upAfter consecutive successes. Outcomes that are neither
// healthy nor failed change nothing. Addresses missing from the round are
// forgotten.
func (t *Tracker) Update(round []Observation) []Transition {
	seen := make(map[NodeKey]struct{}, len(round))
	for _, o := range round {
		seen[o.Node] = struct{}{}
		n := t.nodes[o.Node]
		if n == nil {
			n = &nodeState{}
			t.nodes[o.Node] = n
		}
		n.name = o.NodeName
		n.last = o.Outcome
		switch {
		case o.Outcome.healthy():
			n.successStreak++
			n.failStreak = 0
		case o.Outcome.failed():
			n.failStreak++
			n.successStreak = 0
		}
	}
	for k := range t.nodes {
		if _, ok := seen[k]; !ok {
			delete(t.nodes, k)
		}
	}

	// Evaluate in a fixed order so that when more nodes qualify for removal
	// than maxDown allows, it is always the ones sorted first that are taken
	// out.
	keys := make([]NodeKey, 0, len(t.nodes))
	for k := range t.nodes {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, NodeKey.compare)

	var out []Transition
	for _, k := range keys {
		n := t.nodes[k]
		emit := func(kind TransitionKind) {
			out = append(out, Transition{Kind: kind, Node: k, NodeName: n.name})
		}

		switch {
		case n.down:
			if n.successStreak >= upAfter {
				n.down = false
				emit(TransitionUp)
			}
		case n.failStreak < downAfter:
			n.blocked = false
		case !n.last.failed():
			// Keep the previous decision until there is fresh evidence.
		case t.othersHealthy(k) && t.downNodes(k) < maxDown:
			n.down = true
			n.blocked = false
			emit(TransitionDown)
		case !n.blocked:
			n.blocked = true
			emit(TransitionBlocked)
		}
	}

	return out
}

// forget drops the state of the addresses for which drop returns true.
func (t *Tracker) forget(drop func(NodeKey) bool) {
	maps.DeleteFunc(t.nodes, func(k NodeKey, _ *nodeState) bool {
		return drop(k)
	})
}

// othersHealthy reports whether at least one other node with an address of
// the same family exists and at most maxFailingFraction of them failed their
// last probe. Peers are counted per node, since a widespread problem such as
// an attack hits whole machines, and a node counts as failing if any of its
// addresses of that family failed. Extra addresses on a healthy node can then
// not make a widespread problem look local.
func (t *Tracker) othersHealthy(self NodeKey) bool {
	peers := map[string]bool{} // node ID -> failing
	for k, n := range t.nodes {
		if k.NodeID == self.NodeID || family(k.Addr) != family(self.Addr) {
			continue
		}
		peers[k.NodeID] = peers[k.NodeID] || n.last.failed()
	}

	var failing int
	for _, f := range peers {
		if f {
			failing++
		}
	}
	return len(peers) > 0 && float64(failing) <= maxFailingFraction*float64(len(peers))
}

// downNodes returns how many other nodes have an address of the same family
// as self out.
func (t *Tracker) downNodes(self NodeKey) int {
	down := map[string]struct{}{}
	for k, n := range t.nodes {
		if n.down && k.NodeID != self.NodeID && family(k.Addr) == family(self.Addr) {
			down[k.NodeID] = struct{}{}
		}
	}
	return len(down)
}

// Blocked reports per address family whether a removal is currently being
// held back.
func (t *Tracker) Blocked() map[string]bool {
	blocked := map[string]bool{"ipv4": false, "ipv6": false}
	for k, n := range t.nodes {
		if n.blocked {
			blocked[family(k.Addr)] = true
		}
	}
	return blocked
}

// Snapshot returns the addresses that are down.
func (t *Tracker) Snapshot() Snapshot {
	s := Snapshot{down: map[NodeKey]struct{}{}}
	for k, n := range t.nodes {
		if n.down {
			s.down[k] = struct{}{}
		}
	}
	return s
}

// Snapshot is a copy of the set of down cache node addresses. The zero value
// has nothing down.
type Snapshot struct {
	down map[NodeKey]struct{}
}

// Down reports whether the cache node address is down.
func (s Snapshot) Down(nodeID string, addr netip.Addr) bool {
	_, ok := s.down[NodeKey{NodeID: nodeID, Addr: addr}]
	return ok
}

func family(addr netip.Addr) string {
	if addr.Is4() {
		return "ipv4"
	}
	return "ipv6"
}
