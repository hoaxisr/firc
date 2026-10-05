# tools/bench

Performance measurement for the firc daemon. Any performance claim about
firc needs a figure from a script here.

## Generators and stubs

- `dnsstub` (Go) — fixed-answer upstream DNS over UDP and TCP; `-cname N`
  adds a CNAME chain to every A answer.
- `dnsload` (Go) — load generator: UDP uses a persistent socket per worker,
  TCP one connection per query. JSON results on stdout; `-mode probe`
  prints the time to the first answer.
- `genconfig` (Go) — deterministic bench configs with N rules of a chosen
  type. The group is disabled by default so no netfilter privileges are
  needed; `-group-enable` for router runs, `-list-url` gives the group a list.
- `ctfill` (Go) — opens and holds N forwarded UDP flows, so conntrack holds
  a known number of entries.
- `subscription_fault_stub.py` — a list server that fails on purpose
  (redirect loop, 404, oversized).

## Daemon runs

- `run_c_baseline.sh` — throughput, latency percentiles, CPU and RSS across
  rule counts against `dnsstub`; JSONL results, `summarize.py` turns them
  into markdown tables.
- `run_c_smoke.sh` — one short load run.
- `run_c_soak.sh` — sustained load, watching RSS.
- `run_c_subscription_fault_soak.sh` — sustained load against a failing
  list server.
- `run_sub_cost.sh` — what a group's list sync costs, through
  `/groups/{id}/list/*`. Runs against a router.
- `run_ct_sweep.sh` — what a conntrack flush costs the DNS path. Run it on
  the router.

## Micro-benchmarks

- `run_matcher_bench.sh` (`matcherbench.c`) — building and matching a
  namespace ruleset.
- `run_devsel_bench.sh` (`devselbench.c`) — a device check on the DNS path.
- `run_hello_positions.sh` — where a ClientHello lands in a packet.
- `run_nflog_family.sh` (`nflog_family.c`) — one NFLOG group, both
  families; runs in a user and network namespace.
- `fakeip/quarantine_bench.c` — the pool's quarantine scan; build
  instructions in its header.

## Quick start

```sh
make -C src/backend-c build/host/fircd
sh tools/bench/run_c_baseline.sh /tmp/bench-results
python3 tools/bench/summarize.py /tmp/bench-results/results.jsonl
```

Most scripts need root (raw ports, netfilter); each script's header lists
its requirements and environment variables.
