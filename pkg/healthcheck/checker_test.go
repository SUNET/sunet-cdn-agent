package healthcheck

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
)

// testConfig returns an l4lb config with one cache node per address.
func testConfig(addrs ...string) cdntypes.L4LBNodeConfig {
	var lnc cdntypes.L4LBNodeConfig
	for i, addr := range addrs {
		lnc.CacheNodes = append(lnc.CacheNodes, cdntypes.CacheNode{
			ID:        pgtype.UUID{Bytes: [16]byte{byte(i + 1)}, Valid: true},
			Addresses: []netip.Addr{netip.MustParseAddr(addr)},
		})
	}
	return lnc
}

func newTestChecker() *Checker {
	return NewChecker(Config{Mode: ModeEnforce, Port: DefaultPort}, prometheus.NewRegistry(), zerolog.Nop())
}

// roundFor returns one probe round over targets with the given outcome.
func roundFor(targets []Target, outcome Outcome) []Observation {
	var r []Observation
	for _, t := range targets {
		r = append(r, Observation{Node: t.Node, NodeName: t.NodeName, Outcome: outcome})
	}
	return r
}

func TestCheckerRecordsOnlyCurrentTargets(t *testing.T) {
	c := newTestChecker()

	c.SetConfig(testConfig("10.0.0.1", "10.0.0.2"))
	targets, started := c.currentTargets()
	r := roundFor(targets, OutcomeTimeout)

	// The second node leaves the targets, for example by entering
	// maintenance, while the round is probing: only the first node's
	// result is recorded.
	c.SetConfig(testConfig("10.0.0.1"))
	recorded, _, _, _ := c.recordRound(started, r)
	if len(recorded) != 1 || recorded[0].Node.Addr != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("recorded = %+v, want only 10.0.0.1", recorded)
	}
	if len(c.tracker.nodes) != 1 {
		t.Errorf("tracker has %d addresses, want 1", len(c.tracker.nodes))
	}
	if got := c.tracker.nodes[recorded[0].Node].failStreak; got != 1 {
		t.Errorf("failure streak = %d, want 1", got)
	}
}

// fiveNodes is a config with five cache nodes, the second of which can be left
// out to model it entering maintenance.
func fiveNodes(withSecond bool) cdntypes.L4LBNodeConfig {
	lnc := testConfig("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5")
	if !withSecond {
		lnc.CacheNodes = slices.Delete(lnc.CacheNodes, 1, 2)
	}
	return lnc
}

func TestCheckerReaddedTargetStartsOver(t *testing.T) {
	c := newTestChecker()
	c.SetConfig(fiveNodes(true))
	targets, _ := c.currentTargets()
	second := targets[1].Node

	// Take the second node down.
	for range downAfter {
		targets, generation := c.currentTargets()
		r := roundFor(targets, OutcomePass)
		r[1].Outcome = OutcomeTimeout
		c.recordRound(generation, r)
	}
	if !c.tracker.Snapshot().Down(second.NodeID, second.Addr) {
		t.Fatal("second node not down")
	}

	// It enters and leaves maintenance without a round in between: it
	// must start over rather than keep its old down state.
	c.SetConfig(fiveNodes(false))
	c.SetConfig(fiveNodes(true))
	if c.tracker.Snapshot().Down(second.NodeID, second.Addr) {
		t.Error("re-added node still down from before it was removed")
	}
}

func TestCheckerDropsResultsFromBeforeReadd(t *testing.T) {
	c := newTestChecker()
	c.SetConfig(fiveNodes(true))
	targets, started := c.currentTargets()
	second := targets[1].Node
	r := roundFor(targets, OutcomeTimeout)

	// The second node is removed and re-added while the round is probing:
	// its result is from before it was added again and must not be recorded.
	c.SetConfig(fiveNodes(false))
	c.SetConfig(fiveNodes(true))
	recorded, _, _, _ := c.recordRound(started, r)
	if len(recorded) != 4 {
		t.Errorf("recorded %d results, want 4", len(recorded))
	}
	if _, ok := c.tracker.nodes[second]; ok {
		t.Error("result from before the node was added again was recorded")
	}
}
