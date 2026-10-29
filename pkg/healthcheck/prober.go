package healthcheck

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
)

// maxBodySize is the largest /healthz body accepted.
const maxBodySize = 1 << 20

// Target is one cache node address to probe.
type Target struct {
	Node     NodeKey
	NodeName string
}

// targetsFromConfig returns one target per valid cache node address. Nodes in
// maintenance are left out of health checking, so they are not probed, and
// the tracker forgets them until they leave maintenance.
func targetsFromConfig(lnc cdntypes.L4LBNodeConfig) []Target {
	var targets []Target
	for _, cacheNode := range lnc.CacheNodes {
		if cacheNode.Maintenance {
			continue
		}
		for _, addr := range cacheNode.Addresses {
			addr = addr.Unmap()
			if !addr.IsValid() {
				continue
			}
			targets = append(targets, Target{
				Node:     NodeKey{NodeID: cacheNode.ID.String(), Addr: addr},
				NodeName: cacheNode.Name,
			})
		}
	}
	return targets
}

// prober probes /healthz on cache nodes, dialing from inside the configured
// network namespace with the l4lb source address of the matching family.
type prober struct {
	port       uint16
	ipv4, ipv6 *http.Client
}

func newProber(cfg Config) *prober {
	return &prober{
		port: cfg.Port,
		ipv4: newProbeClient(cfg.NetNS, cfg.SourceIPv4),
		ipv6: newProbeClient(cfg.NetNS, cfg.SourceIPv6),
	}
}

func newProbeClient(netns string, source netip.Addr) *http.Client {
	// http.Transport dials with a context detached from the request, so the
	// dial must be bounded by the dialer, or a blackholed node pins the
	// dialing goroutine (and its namespace OS thread) for minutes.
	dialer := &net.Dialer{Timeout: probeTimeout}
	if source.IsValid() {
		dialer.LocalAddr = &net.TCPAddr{IP: source.AsSlice()}
	}

	return &http.Client{
		// Never follow redirects, a 3xx is just a non-200 answer.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true, // a fresh connection per probe
			DialContext:       dialContextInNetNS(netns, dialer),
		},
	}
}

func (p *prober) probe(ctx context.Context, t Target) Observation {
	return Observation{
		Node:     t.Node,
		NodeName: t.NodeName,
		Outcome:  p.outcome(ctx, t.Node.Addr),
	}
}

func (p *prober) outcome(ctx context.Context, addr netip.Addr) Outcome {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	client := p.ipv4
	if addr.Is6() {
		client = p.ipv6
	}

	u := url.URL{Scheme: "http", Host: netip.AddrPortFrom(addr, p.port).String(), Path: "/healthz"}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return OutcomeError
	}

	resp, err := client.Do(req)
	if err != nil {
		return classifyTransportError(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// LimitReader stops silently at its limit, so read one byte more than
	// allowed: getting more than maxBodySize back means the body was too big.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
	if err != nil {
		return classifyTransportError(err)
	}
	if len(body) > maxBodySize {
		return OutcomeNeutral
	}

	return classifyResponse(resp.StatusCode, body)
}

func classifyTransportError(err error) Outcome {
	var netErr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &netErr) && netErr.Timeout():
		return OutcomeTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return OutcomeRefused
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return OutcomeUnreachable
	default:
		return OutcomeError
	}
}
