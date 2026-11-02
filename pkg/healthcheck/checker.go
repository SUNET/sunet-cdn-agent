package healthcheck

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"
)

// Checker probes the cache nodes from the latest l4lb config every
// probeInterval, logs the Tracker's decisions and exports metrics. In enforce
// mode it signals on Changed when a node went down or up.
type Checker struct {
	mode    Mode
	prober  *prober
	logger  zerolog.Logger
	changed chan struct{}

	probes   *prometheus.CounterVec
	nodeDown *prometheus.GaugeVec
	blocked  *prometheus.GaugeVec
	// nodeDownSeries holds the label values of the nodeDown series set by
	// the last round, so the next round can delete the series of addresses
	// it no longer probes instead of resetting them all. Only runRound uses
	// it.
	nodeDownSeries map[nodeDownLabels]struct{}

	// mu guards the fields below.
	mu sync.Mutex
	// generation is incremented by every SetConfig. A round only records
	// results for addresses that were already targets when it started.
	generation uint64
	targets    map[NodeKey]targetInfo
	tracker    *Tracker
}

// nodeDownLabels are the label values of one nodeDown series.
type nodeDownLabels struct {
	cacheNode, address string
}

// targetInfo is what the Checker keeps about a current target address.
type targetInfo struct {
	nodeName string
	// addedIn is the generation in which the address was added to the
	// targets.
	addedIn uint64
}

// NewChecker returns a Checker that registers its metrics on reg and does
// nothing until SetConfig has been called.
func NewChecker(cfg Config, reg prometheus.Registerer, logger zerolog.Logger) *Checker {
	f := promauto.With(reg)
	return &Checker{
		mode:    cfg.Mode,
		prober:  newProber(cfg),
		logger:  logger.With().Str("mode", string(cfg.Mode)).Logger(),
		changed: make(chan struct{}, 1),
		tracker: NewTracker(),
		probes: f.NewCounterVec(prometheus.CounterOpts{
			Name: "sunet_cdn_agent_health_probes_total",
			Help: "Health probes of cache node addresses by result.",
		}, []string{"cache_node", "address", "result"}),
		nodeDown: f.NewGaugeVec(prometheus.GaugeOpts{
			Name: "sunet_cdn_agent_health_node_down",
			Help: "1 if health checking has taken the cache node address out of rotation (in observe mode: would have).",
		}, []string{"cache_node", "address"}),
		blocked: f.NewGaugeVec(prometheus.GaugeOpts{
			Name: "sunet_cdn_agent_health_removal_blocked",
			Help: "1 while a failing cache node is kept in rotation because too many nodes are failing or already out.",
		}, []string{"family"}),
	}
}

// SetConfig sets the cache nodes to probe.
func (c *Checker) SetConfig(lnc cdntypes.L4LBNodeConfig) {
	list := targetsFromConfig(lnc)
	c.mu.Lock()
	defer c.mu.Unlock()

	c.generation++
	targets := make(map[NodeKey]targetInfo, len(list))
	for _, t := range list {
		addedIn := c.generation
		if old, ok := c.targets[t.Node]; ok {
			addedIn = old.addedIn
		}
		targets[t.Node] = targetInfo{nodeName: t.NodeName, addedIn: addedIn}
	}
	c.targets = targets

	// Forget removed addresses right away, so one that is removed and
	// re-added, for example by entering and leaving maintenance, starts
	// over even if no round was recorded in between.
	c.tracker.forget(func(k NodeKey) bool {
		_, ok := targets[k]
		return !ok
	})
}

// currentTargets returns the current targets and the generation they belong
// to, read under the same lock so they always match. The targets are sorted
// by address so rounds are built in a stable order.
func (c *Checker) currentTargets() ([]Target, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	targets := make([]Target, 0, len(c.targets))
	for node, info := range c.targets {
		targets = append(targets, Target{Node: node, NodeName: info.nodeName})
	}
	slices.SortFunc(targets, func(a, b Target) int {
		return a.Node.compare(b.Node)
	})
	return targets, c.generation
}

// Changed receives a value after a node went down or up in enforce mode.
// Signals are coalesced and sending never blocks.
func (c *Checker) Changed() <-chan struct{} {
	return c.changed
}

// Snapshot returns the down addresses to apply to ipvs, which is nothing
// outside of enforce mode.
func (c *Checker) Snapshot() Snapshot {
	if c.mode != ModeEnforce {
		return Snapshot{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tracker.Snapshot()
}

// recordRound feeds round to the tracker. generation is the value of
// c.generation when the round started. SetConfig may have replaced the
// targets while the round was probing, so results are only kept for
// addresses that have been targets since before the round started. A node
// that has just entered maintenance then can't count as a healthy peer, and a
// node that was removed and added again starts over instead of being judged
// on a result from before it was removed. Results for the other addresses
// are kept, so their streaks stay consecutive. It returns the round that was
// recorded.
func (c *Checker) recordRound(generation uint64, round []Observation) ([]Observation, []Transition, Snapshot, map[string]bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	round = slices.DeleteFunc(round, func(o Observation) bool {
		info, ok := c.targets[o.Node]
		return !ok || info.addedIn > generation
	})
	return round, c.tracker.Update(round), c.tracker.Snapshot(), c.tracker.Blocked()
}

// Run probes every probeInterval until ctx is done.
func (c *Checker) Run(ctx context.Context) {
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.runRound(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (c *Checker) runRound(ctx context.Context) {
	targets, generation := c.currentTargets()

	// With no targets (the config has no cache nodes) the round is empty but
	// still processed, so cache nodes removed from the config are forgotten.
	round := make([]Observation, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Go(func() {
			round[i] = c.prober.probe(ctx, t)
		})
	}
	wg.Wait()

	// Probes cut short by shutdown say nothing about the nodes.
	if ctx.Err() != nil {
		return
	}

	round, transitions, snapshot, blocked := c.recordRound(generation, round)

	// Update the nodeDown series in place and only delete the ones for
	// addresses no longer probed, so a concurrent scrape never misses a
	// series that is still there.
	series := make(map[nodeDownLabels]struct{}, len(round))
	for _, o := range round {
		addr := o.Node.Addr.String()
		c.probes.WithLabelValues(o.NodeName, addr, string(o.Outcome)).Inc()
		down := 0.0
		if snapshot.Down(o.Node.NodeID, o.Node.Addr) {
			down = 1
		}
		c.nodeDown.WithLabelValues(o.NodeName, addr).Set(down)
		series[nodeDownLabels{cacheNode: o.NodeName, address: addr}] = struct{}{}
	}
	for s := range c.nodeDownSeries {
		if _, ok := series[s]; !ok {
			c.nodeDown.DeleteLabelValues(s.cacheNode, s.address)
		}
	}
	c.nodeDownSeries = series
	for fam, b := range blocked {
		v := 0.0
		if b {
			v = 1
		}
		c.blocked.WithLabelValues(fam).Set(v)
	}

	changed := false
	for _, tr := range transitions {
		var ev *zerolog.Event
		switch tr.Kind {
		case TransitionDown:
			ev = c.logger.Warn()
			changed = true
		case TransitionUp:
			ev = c.logger.Info()
			changed = true
		default:
			ev = c.logger.Warn()
		}
		ev.Str("cache_node", tr.NodeName).Str("address", tr.Node.Addr.String()).
			Str("decision", string(tr.Kind)).Msg("health check decision")
	}

	if changed && c.mode == ModeEnforce {
		select {
		case c.changed <- struct{}{}:
		default:
		}
	}
}
