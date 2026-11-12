package runner

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
)

const (
	testOrgID     = "00000000-0000-0000-0000-000000000001"
	testServiceID = "00000000-0000-0000-0000-000000000002"
)

func mustParseUUID(t *testing.T, s string) pgtype.UUID {
	t.Helper()
	var u pgtype.UUID
	err := u.Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func singleServiceContainers(t *testing.T, addrs ...string) []orgIPContainer {
	t.Helper()
	ipAddrs := []netip.Addr{}
	for _, a := range addrs {
		ipAddrs = append(ipAddrs, netip.MustParseAddr(a))
	}
	return []orgIPContainer{
		{
			ID: mustParseUUID(t, testOrgID),
			ServiceIPContainers: []serviceIPContainer{
				{
					ID:          mustParseUUID(t, testServiceID),
					IPAddresses: ipAddrs,
				},
			},
		},
	}
}

func TestBuildAlloyTargetGroups(t *testing.T) {
	tests := []struct {
		name   string
		addrs  []string
		target string // empty means no target groups are expected
		ipv4   string
		ipv6   string
	}{
		{"dual stack", []string{"192.0.2.1", "2001:db8::1"}, "192.0.2.1:9090", "192.0.2.1", "2001:db8::1"},
		{"ipv4 only", []string{"192.0.2.1"}, "192.0.2.1:9090", "192.0.2.1", ""},
		{"ipv6 only", []string{"2001:db8::1"}, "[2001:db8::1]:9090", "", "2001:db8::1"},
		{"ipv4-mapped ipv6", []string{"::ffff:192.0.2.1", "2001:db8::1"}, "192.0.2.1:9090", "192.0.2.1", "2001:db8::1"},
		{"no addresses", nil, "", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildAlloyTargetGroups("node-1", singleServiceContainers(t, tc.addrs...))

			want := []alloyTargetGroup{}
			if tc.target != "" {
				for _, job := range []struct{ name, path string }{
					{"haproxy", "/haproxy/metrics"},
					{"vinyl", "/vinyl/metrics"},
				} {
					want = append(want, alloyTargetGroup{
						Targets: []string{tc.target},
						Labels: alloyTargetLabels{
							Job:         job.name,
							MetricsPath: job.path,
							Instance:    "node-1",
							ListenIPv4:  tc.ipv4,
							ListenIPv6:  tc.ipv6,
							OrgID:       testOrgID,
							ServiceID:   testServiceID,
						},
					})
				}
			}

			if !reflect.DeepEqual(got, want) {
				t.Errorf("unexpected target groups\ngot:  %+v\nwant: %+v", got, want)
			}
		})
	}
}
