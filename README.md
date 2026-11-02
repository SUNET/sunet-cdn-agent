# sunet-cdn-agent

This agent runs on a `l4lb` or `cache` machine and configures it based on the
state in a
[sunet-cdn-manager](https://github.com/SUNET/sunet-cdn-manager) server

## Health checking

On `l4lb` nodes the agent can probe `GET /healthz` on every cache node address
and set the ipvs weight of an address that is clearly not serving to 0. Each
address is its own ipvs real-server and is judged on its own.

Since this is DDoS protection, it is conservative. An address is only taken
out when all of these hold:

- it failed its last 8 probes in a row (about 24s)
- the problem looks local to this node: at most a quarter of the other nodes
  failed their latest probe as well, where a node counts once and as failing
  if any of its addresses of the same family failed
- health checking has not already taken out another node in the same family.
  Addresses of the same node do not count against each other, so a dead node
  can have all its addresses taken out, but never more than one node per
  family is out at a time

An address is put back after 10 consecutive successful probes. Nodes in
maintenance mode are left out of health checking entirely: they are not
probed, and start over when they leave maintenance. The cache nodes probed
and counted are exactly the ones in the l4lb config from the manager, which
only lists the cache nodes in the l4lb node's own node group.

The probes are sent from inside the l4lb network namespace using
`loopback_ipv4`/`loopback_ipv6` as source, so they follow the same path as the
tunneled traffic. Timeouts, refused and unreachable connections and a `fail`
status count as failures. Anything else, including other connection errors
and answers that can't be interpreted, counts neither way.

The health service on the cache nodes is a separate component. It answers in
the [IETF health check
format](https://datatracker.ietf.org/doc/html/draft-inadarei-api-health-check)
(`application/health+json`), for example HTTP 200 with:

```json
{"status": "pass"}
```

`pass` or `warn` with a 2xx/3xx code counts as healthy and `fail` with a
4xx/5xx code (typically 503) as failing. Other values, including the aliases
the draft allows, count neither way. Other fields such as `checks` are ignored.

```toml
[health-check]
mode = "off" # "off", "observe" (decide, log and export metrics only) or "enforce"
port = 8088  # port of the health service on cache nodes

[metrics]
listen_address = "" # e.g. "127.0.0.1:9811", empty disables /metrics
```

When `mode` is not `off`, l4lb nodes also let the probe replies in through
sunet-xdpd and nftables, and cache nodes always allow the health port from the
l4lb nodes.

Before enabling `observe`, check that the `sunet-l4lb-namespace` nftables
ruleset neither filters outgoing TCP to the health port nor `notrack`s it.

With `listen_address` set, `/metrics` shows what the checker sees and decides,
in `observe` mode as well:

- `sunet_cdn_agent_health_probes_total{cache_node, address, result}`: probes
  by result: `pass`, `warn`, `fail`, `timeout`, `refused`, `unreachable`,
  `error` or `neutral`. If every probe times out, the probes or their replies
  are not getting through.
- `sunet_cdn_agent_health_node_down{cache_node, address}`: 1 for a cache node
  address that is out of rotation (in `observe` mode: would be).
- `sunet_cdn_agent_health_removal_blocked{family}`: 1 while a failing node is
  kept in rotation because too many nodes are failing or already out.
