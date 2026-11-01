package healthcheck

import (
	"fmt"
	"net/netip"
	"testing"
)

func nodeKey(i int) NodeKey {
	return NodeKey{NodeID: fmt.Sprintf("n%d", i), Addr: netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", i))}
}

// round returns one probe round for nodes 1..size where the nodes listed in
// nodes (each between 1 and size) have the given outcome and all others pass.
func round(t *testing.T, size int, outcome Outcome, nodes ...int) []Observation {
	t.Helper()
	r := make([]Observation, size)
	for i := range size {
		r[i] = Observation{Node: nodeKey(i + 1), Outcome: OutcomePass}
	}
	for _, n := range nodes {
		if n < 1 || n > size {
			t.Fatalf("node %d not in a round of %d nodes", n, size)
		}
		r[n-1].Outcome = outcome
	}
	return r
}

// update feeds the same round n times and returns all transitions.
func update(tr *Tracker, n int, r []Observation) []Transition {
	var out []Transition
	for range n {
		out = append(out, tr.Update(r)...)
	}
	return out
}

// obs returns an observation of one address of a node.
func obs(nodeID, addr string, outcome Outcome) Observation {
	return Observation{Node: NodeKey{NodeID: nodeID, Addr: netip.MustParseAddr(addr)}, Outcome: outcome}
}

func isDown(tr *Tracker, i int) bool {
	k := nodeKey(i)
	return tr.Snapshot().Down(k.NodeID, k.Addr)
}

func TestTrackerDownAfterConsecutiveFailures(t *testing.T) {
	tr := NewTracker()

	update(tr, downAfter-1, round(t, 5, OutcomeTimeout, 1))
	if isDown(tr, 1) {
		t.Fatalf("n1 down after %d failures, want in", downAfter-1)
	}

	got := tr.Update(round(t, 5, OutcomeTimeout, 1))
	if len(got) != 1 || got[0].Kind != TransitionDown || got[0].Node != nodeKey(1) {
		t.Fatalf("transitions = %+v, want n1 down", got)
	}
	if !isDown(tr, 1) {
		t.Fatal("n1 not down in snapshot")
	}
}

func TestTrackerNeutralKeepsFailureStreak(t *testing.T) {
	tr := NewTracker()

	// One failure short of being taken out.
	update(tr, downAfter-1, round(t, 5, OutcomeTimeout, 1))

	// A neutral answer does not count as a failure...
	tr.Update(round(t, 5, OutcomeNeutral, 1))
	if isDown(tr, 1) {
		t.Fatal("n1 down on a neutral round")
	}

	// ...and does not reset the streak either, so the next failure is
	// failure number downAfter.
	tr.Update(round(t, 5, OutcomeTimeout, 1))
	if !isDown(tr, 1) {
		t.Fatal("n1 not down after the next failure")
	}
}

func TestTrackerTwoNodes(t *testing.T) {
	// With two nodes the only other node is the healthy one, so the failing
	// node is taken out.
	tr := NewTracker()
	update(tr, downAfter, round(t, 2, OutcomeTimeout, 1))
	if !isDown(tr, 1) {
		t.Error("n1 not taken down while n2 is healthy")
	}

	// Both failing: nothing is taken out.
	tr = NewTracker()
	update(tr, downAfter, round(t, 2, OutcomeTimeout, 1, 2))
	if isDown(tr, 1) || isDown(tr, 2) {
		t.Error("node taken down while both nodes are failing")
	}
}

func TestTrackerTooManyFailingBlocksRemoval(t *testing.T) {
	tr := NewTracker()

	// n1 and n2 failing out of 4: for n1, 1 of 3 others is failing, which
	// is more than maxFailingFraction.
	got := update(tr, downAfter, round(t, 4, OutcomeTimeout, 1, 2))
	if isDown(tr, 1) || isDown(tr, 2) {
		t.Fatal("node taken down while too many nodes are failing")
	}
	if len(got) != 2 || got[0].Kind != TransitionBlocked || got[1].Kind != TransitionBlocked {
		t.Fatalf("transitions = %+v, want n1 and n2 blocked once each", got)
	}
	if !tr.Blocked()["ipv4"] {
		t.Error("Blocked()[ipv4] = false, want true")
	}
}

func TestTrackerMaxDownBlocksRemoval(t *testing.T) {
	tr := NewTracker()

	// Enough nodes that maxDown+1 failing ones stay within
	// maxFailingFraction, so only the maxDown limit can block.
	size := int(float64(maxDown)/maxFailingFraction) + 2

	var failing []int
	for n := 1; n <= maxDown; n++ {
		failing = append(failing, n)
	}
	update(tr, downAfter, round(t, size, OutcomeTimeout, failing...))
	for _, n := range failing {
		if !isDown(tr, n) {
			t.Fatalf("n%d not down", n)
		}
	}

	next := maxDown + 1
	update(tr, downAfter, round(t, size, OutcomeTimeout, append(failing, next)...))
	if isDown(tr, next) {
		t.Fatalf("n%d down while %d node(s) already down", next, maxDown)
	}
	if !tr.Blocked()["ipv4"] {
		t.Error("Blocked()[ipv4] = false, want true")
	}
}

func TestTrackerRecovery(t *testing.T) {
	tr := NewTracker()

	update(tr, downAfter, round(t, 5, OutcomeTimeout, 1))
	update(tr, upAfter-1, round(t, 5, OutcomePass))
	if !isDown(tr, 1) {
		t.Fatalf("n1 back after %d successes, want down", upAfter-1)
	}
	got := tr.Update(round(t, 5, OutcomePass))
	if len(got) != 1 || got[0].Kind != TransitionUp {
		t.Fatalf("transitions = %+v, want n1 up", got)
	}
}

func TestTrackerEmptyRoundForgetsNodes(t *testing.T) {
	tr := NewTracker()

	update(tr, downAfter, round(t, 5, OutcomeTimeout, 1))
	if !isDown(tr, 1) {
		t.Fatal("n1 not down")
	}

	tr.Update(nil)
	if isDown(tr, 1) {
		t.Error("n1 still down after a round without nodes")
	}
}

func TestTrackerDeadNodeWithTwoAddresses(t *testing.T) {
	tr := NewTracker()

	// d has two IPv4 addresses. When it dies both fail and both are taken
	// out: a node's own addresses do not use up each other's slot.
	//
	// The round is five healthy single-address nodes (n1..n5) plus d as a
	// sixth node with its two addresses appended.
	r := round(t, 5, OutcomePass)
	r = append(
		r,
		obs("d", "10.0.1.1", OutcomeTimeout),
		obs("d", "10.0.1.2", OutcomeTimeout),
	)
	update(tr, downAfter, r)
	snap := tr.Snapshot()
	if !snap.Down("d", netip.MustParseAddr("10.0.1.1")) || !snap.Down("d", netip.MustParseAddr("10.0.1.2")) {
		t.Fatal("not all addresses of the dead node taken out")
	}

	// Another node (n1, the first entry) failing is still blocked by
	// maxDown.
	r[0].Outcome = OutcomeTimeout
	update(tr, downAfter, r)
	if isDown(tr, 1) {
		t.Errorf("n1 down while d already is, maxDown = %d", maxDown)
	}
}

func TestTrackerPartialRecovery(t *testing.T) {
	tr := NewTracker()

	// Five healthy single-address nodes (n1..n5) plus d with two IPv4
	// addresses, both failing, so both are taken out.
	r := round(t, 5, OutcomePass)
	r = append(
		r,
		obs("d", "10.0.1.1", OutcomeTimeout),
		obs("d", "10.0.1.2", OutcomeTimeout),
	)
	update(tr, downAfter, r)

	addr1 := netip.MustParseAddr("10.0.1.1")
	addr2 := netip.MustParseAddr("10.0.1.2")
	if !tr.Snapshot().Down("d", addr1) || !tr.Snapshot().Down("d", addr2) {
		t.Fatal("not all addresses of the dead node taken out")
	}

	// The first address comes back while the second keeps failing: the
	// first is put back on its own, the second stays out.
	r[5].Outcome = OutcomePass
	update(tr, upAfter, r)
	if tr.Snapshot().Down("d", addr1) {
		t.Error("recovered address still down")
	}
	if !tr.Snapshot().Down("d", addr2) {
		t.Error("failing address put back")
	}

	// d still has an address out, so another failing node stays blocked.
	r[0].Outcome = OutcomeTimeout
	update(tr, downAfter, r)
	if isDown(tr, 1) {
		t.Errorf("n1 down while d still has an address out, maxDown = %d", maxDown)
	}
}

func TestTrackerMissingAddressStartsOver(t *testing.T) {
	tr := NewTracker()

	update(tr, downAfter, round(t, 10, OutcomeTimeout, 1))
	if !isDown(tr, 1) {
		t.Fatal("n1 not down")
	}

	// n1 is left out of the rounds, as when it is in maintenance: it is
	// forgotten and frees the removal slot, so n2 can be taken out.
	update(tr, downAfter, round(t, 10, OutcomeTimeout, 2)[1:])
	if isDown(tr, 1) {
		t.Error("n1 still down while left out of the rounds")
	}
	if !isDown(tr, 2) {
		t.Fatal("n2 not taken down while n1 is left out")
	}

	// n1 is back and still failing: it starts over, so it needs downAfter
	// new failures, and then n2 holds the slot.
	got := update(tr, downAfter, round(t, 10, OutcomeTimeout, 1, 2))
	if isDown(tr, 1) {
		t.Errorf("n1 down while n2 already is, maxDown = %d", maxDown)
	}
	if len(got) != 1 || got[0].Kind != TransitionBlocked {
		t.Errorf("transitions = %+v, want n1 blocked only after %d new failures", got, downAfter)
	}
}

func TestTrackerErrorIsNotFailure(t *testing.T) {
	tr := NewTracker()

	// Generic probe errors, such as a reset connection or a truncated
	// answer, say nothing reliable about the node.
	update(tr, downAfter, round(t, 5, OutcomeError, 1))
	if isDown(tr, 1) {
		t.Error("n1 taken down on generic probe errors")
	}
}

func TestTrackerPeersCountedPerNode(t *testing.T) {
	tr := NewTracker()

	// a and b failing, c healthy with three addresses: one of a's two peer
	// nodes is failing (50%), so a must not be taken out, even though only
	// one of four peer addresses is failing.
	r := []Observation{
		obs("a", "10.0.0.1", OutcomeTimeout),
		obs("b", "10.0.0.2", OutcomeTimeout),
		obs("c", "10.0.0.3", OutcomePass),
		obs("c", "10.0.0.4", OutcomePass),
		obs("c", "10.0.0.5", OutcomePass),
	}
	update(tr, downAfter, r)
	if tr.Snapshot().Down("a", netip.MustParseAddr("10.0.0.1")) {
		t.Error("a taken out while half of its peer nodes are failing")
	}
}
