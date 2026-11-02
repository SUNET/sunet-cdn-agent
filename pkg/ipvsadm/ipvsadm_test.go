package ipvsadm

import (
	"maps"
	"net/netip"
	"slices"
	"testing"
)

func TestOrderRealServerEditsRaisesFirst(t *testing.T) {
	service := netip.MustParseAddr("192.0.2.1")
	nodeA := netip.MustParseAddr("10.0.0.1")
	nodeB := netip.MustParseAddr("10.0.0.2")

	ruleSet := func(weightA, weightB int) RuleSet {
		t.Helper()
		rset := NewRuleset()
		vs, err := NewVirtualService("tcp", service, 443, "mh")
		if err != nil {
			t.Fatal(err)
		}
		if err := rset.AddVS(vs); err != nil {
			t.Fatal(err)
		}
		for _, rs := range []struct {
			addr   netip.Addr
			weight int
		}{{nodeA, weightA}, {nodeB, weightB}} {
			r, err := NewRealServer("tcp", service, 443, rs.addr, 443, rs.weight, "ipip")
			if err != nil {
				t.Fatal(err)
			}
			if err := rset.AddRS(r); err != nil {
				t.Fatal(err)
			}
		}
		return rset
	}

	// A is lowered and B raised in the same update, with A first in config
	// order: B must be raised before A is lowered.
	loaded := ruleSet(1, 0)
	updated := ruleSet(0, 1)
	updates := FindRuleUpdates(loaded, updated)

	got := orderRealServerEdits(loaded, updated, updates.rsToEdit)
	if len(got) != 2 {
		t.Fatalf("got %d edits, want 2", len(got))
	}
	want := []netip.Addr{nodeB, nodeA}
	if gotAddrs := []netip.Addr{got[0].address, got[1].address}; !slices.Equal(gotAddrs, want) {
		t.Errorf("edit order = %v, want %v", gotAddrs, want)
	}
}

func TestZeroWeightServers(t *testing.T) {
	// 10.0.0.1 is at weight 0 on one of its real-servers only, as after a
	// half-applied update, and still counts. 10.0.0.2 is in rotation
	// everywhere.
	rset, err := parseRules(`-A -t 192.0.2.1:80 -s mh -b mh-fallback,mh-port
-a -t 192.0.2.1:80 -r 10.0.0.1:80 -i -w 0 --tun-type ipip
-a -t 192.0.2.1:80 -r 10.0.0.2:80 -i -w 1 --tun-type ipip
-A -t 192.0.2.1:443 -s mh -b mh-fallback,mh-port
-a -t 192.0.2.1:443 -r 10.0.0.1:443 -i -w 1 --tun-type ipip
-a -t 192.0.2.1:443 -r 10.0.0.2:443 -i -w 1 --tun-type ipip
-A -t [2001:db8::1]:443 -s mh -b mh-fallback,mh-port
-a -t [2001:db8::1]:443 -r [2001:db8:1::1]:443 -i -w 0 --tun-type ipip
`)
	if err != nil {
		t.Fatal(err)
	}

	got := rset.ZeroWeightServers()
	want := map[netip.Addr]struct{}{
		netip.MustParseAddr("10.0.0.1"):      {},
		netip.MustParseAddr("2001:db8:1::1"): {},
	}
	if !maps.Equal(got, want) {
		t.Errorf("ZeroWeightServers() = %v, want %v", got, want)
	}
}
