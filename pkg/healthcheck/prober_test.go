package healthcheck

import (
	"net/netip"
	"testing"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestTargetsFromConfigSkipsMaintenance(t *testing.T) {
	node := func(id byte, name string, addr string, maintenance bool) cdntypes.CacheNode {
		return cdntypes.CacheNode{
			ID:          pgtype.UUID{Bytes: [16]byte{id}, Valid: true},
			Name:        name,
			Addresses:   []netip.Addr{netip.MustParseAddr(addr)},
			Maintenance: maintenance,
		}
	}

	targets := targetsFromConfig(cdntypes.L4LBNodeConfig{CacheNodes: []cdntypes.CacheNode{
		node(1, "cache1", "10.0.0.1", false),
		node(2, "cache2", "10.0.0.2", true),
	}})
	if len(targets) != 1 || targets[0].Node.Addr != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("targets = %+v, want only 10.0.0.1", targets)
	}
}
