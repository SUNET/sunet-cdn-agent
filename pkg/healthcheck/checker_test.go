package healthcheck

import (
	"errors"
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

// zeroWeight returns a RestoreDown loader that reports addrs at weight 0.
func zeroWeight(addrs ...string) func() (map[netip.Addr]struct{}, error) {
	return func() (map[netip.Addr]struct{}, error) {
		zero := map[netip.Addr]struct{}{}
		for _, a := range addrs {
			zero[netip.MustParseAddr(a)] = struct{}{}
		}
		return zero, nil
	}
}

func TestCheckerRestoreDown(t *testing.T) {
	c := newTestChecker()

	// The second node is in maintenance, which explains its weight 0.
	// 10.0.0.9 is not in the config at all.
	lnc := testConfig("10.0.0.1", "10.0.0.2", "10.0.0.3")
	lnc.CacheNodes[1].Maintenance = true
	c.RestoreDown(lnc, zeroWeight("10.0.0.1", "10.0.0.2", "10.0.0.9"))

	snap := c.Snapshot()
	for _, tc := range []struct {
		node int
		addr string
		down bool
	}{
		{0, "10.0.0.1", true},
		{1, "10.0.0.2", false},
		{2, "10.0.0.3", false},
	} {
		id := lnc.CacheNodes[tc.node].ID.String()
		if got := snap.Down(id, netip.MustParseAddr(tc.addr)); got != tc.down {
			t.Errorf("%s down = %v, want %v", tc.addr, got, tc.down)
		}
	}
	if len(c.tracker.nodes) != 1 {
		t.Errorf("tracker has %d addresses, want 1", len(c.tracker.nodes))
	}
}

func TestCheckerRestoreDownOnlyInEnforce(t *testing.T) {
	c := NewChecker(Config{Mode: ModeObserve, Port: DefaultPort}, prometheus.NewRegistry(), zerolog.Nop())
	lnc := testConfig("10.0.0.1")

	// The loader stands in for reading ipvs and reports 10.0.0.1 at weight
	// 0. In observe mode the weights don't come from health checking, so
	// ipvs must not be read and nothing restored.
	called := false
	c.RestoreDown(lnc, func() (map[netip.Addr]struct{}, error) {
		called = true
		return zeroWeight("10.0.0.1")()
	})
	if called {
		t.Error("ipvs weights read outside of enforce mode")
	}
	// Check the tracker directly, Snapshot is always empty outside of
	// enforce mode.
	if c.tracker.Snapshot().Down(lnc.CacheNodes[0].ID.String(), netip.MustParseAddr("10.0.0.1")) {
		t.Error("10.0.0.1 restored as down in observe mode")
	}
}

func TestCheckerRestoreDownLoadError(t *testing.T) {
	c := newTestChecker()
	lnc := testConfig("10.0.0.1")

	// The loader stands in for reading ipvs and fails. It also reports
	// 10.0.0.1 at weight 0, so ignoring the error would restore it: on an
	// error every address must start in rotation.
	c.RestoreDown(lnc, func() (map[netip.Addr]struct{}, error) {
		return map[netip.Addr]struct{}{netip.MustParseAddr("10.0.0.1"): {}}, errors.New("ipvsadm failed")
	})
	if c.Snapshot().Down(lnc.CacheNodes[0].ID.String(), netip.MustParseAddr("10.0.0.1")) {
		t.Error("10.0.0.1 restored as down although reading ipvs failed")
	}
}

func TestCheckerRestoredSurvivesStartup(t *testing.T) {
	c := newTestChecker()
	lnc := testConfig("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5")
	first := NodeKey{NodeID: lnc.CacheNodes[0].ID.String(), Addr: netip.MustParseAddr("10.0.0.1")}

	// Simulate the startup order in l4lbNodeLoop, with a probe round
	// running at the same time:
	//  1. A probe round starts. SetConfig has not been called yet, so the
	//     checker has no targets and the round probes nothing.
	//  2. The first config is fetched and 10.0.0.1 is restored as down.
	//  3. The round from step 1 finishes and is recorded.
	// Recording a round must not forget addresses it did not probe, so
	// 10.0.0.1 must still be down.
	//
	// currentTargets is how runRound starts a round, and roundFor stands in
	// for the probes, built from the targets saved in step 1.
	targets, started := c.currentTargets()
	c.RestoreDown(lnc, zeroWeight("10.0.0.1"))
	c.recordRound(started, roundFor(targets, OutcomePass))
	if !c.Snapshot().Down(first.NodeID, first.Addr) {
		t.Fatal("10.0.0.1 no longer down after recording a round that started before SetConfig, the next ipvs apply would give it weight 1")
	}

	// 4. The agent applies the config, including the ipvs rules, and then
	//    hands it to the checker with SetConfig, so 10.0.0.1 is now
	//    probed. Only SetConfig is part of this test. 10.0.0.1 passes
	//    every round and must stay down until it has passed upAfter of
	//    them.
	c.SetConfig(lnc)
	for range upAfter - 1 {
		targets, generation := c.currentTargets()
		c.recordRound(generation, roundFor(targets, OutcomePass))
	}
	if !c.Snapshot().Down(first.NodeID, first.Addr) {
		t.Fatalf("10.0.0.1 no longer down after %d successes, want down until %d", upAfter-1, upAfter)
	}
	targets, generation := c.currentTargets()
	c.recordRound(generation, roundFor(targets, OutcomePass))
	if c.Snapshot().Down(first.NodeID, first.Addr) {
		t.Errorf("10.0.0.1 still down after %d successes", upAfter)
	}
}
