package runner

import (
	"testing"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestWithNewMaintenance(t *testing.T) {
	idA := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	idB := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}
	idC := pgtype.UUID{Bytes: [16]byte{3}, Valid: true}

	config := func(maintA, maintB bool) cdntypes.L4LBNodeConfig {
		return cdntypes.L4LBNodeConfig{CacheNodes: []cdntypes.CacheNode{
			{ID: idA, Maintenance: maintA},
			{ID: idB, Maintenance: maintB},
		}}
	}

	// The last config has B in maintenance. The new one, which could not
	// be applied, puts A in maintenance, takes B out of it and adds C.
	last := config(false, true)
	next := config(true, false)
	next.CacheNodes = append(next.CacheNodes, cdntypes.CacheNode{ID: idC, Maintenance: true})

	merged := withNewMaintenance(last, next)

	if !merged.CacheNodes[0].Maintenance {
		t.Error("A not in maintenance, want the new maintenance honoured")
	}
	if !merged.CacheNodes[1].Maintenance {
		t.Error("B taken out of maintenance by a config that was not applied")
	}
	if len(merged.CacheNodes) != 2 {
		t.Errorf("merged has %d cache nodes, want the 2 from the last config", len(merged.CacheNodes))
	}
	if last.CacheNodes[0].Maintenance {
		t.Error("last config was modified")
	}
}
