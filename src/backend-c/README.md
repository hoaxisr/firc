# firc C backend

The `fircd` daemon and its helper tools, in C11.

## Layout

```
include/firc/     module headers
src/
  main/           daemon entry point: wires up everything below
  core/           component lifecycle
  util/           error model, bounded queue, buffers, cancellation, RNG, instance lock
  logging/        levelled logger and the event journal
  platform/       epoll event loop (the only Linux-specific layer)
  config/         config models, YAML load/save
  rules/          rule matching and the rule-set snapshot
  subscriptions/  a group's list: fetch, parse, sync, auto-update
  dns/            DNS wire codec, MITM proxy, response pipeline
  fakeip/         the fake address pool and its persistence
  netfilter/      per-group chains, marks, routes, DNAT, committer, conntrack
  iptables/       iptables save/restore engine
  netlink/        rtnetlink link/address watcher
  interfaces/     Keenetic RCI interface lookup
  tap/            the diagnostic capture
  api/            HTTP/Unix API, auth, handlers
  crypto/         hashes, crypt, HMAC, JWT
  tools/          firc-configtool, firc-dnstool (test drivers)
tests/
  unit/           unit tests (greatest.h)
  differential/   regression suites against golden snapshots
  fuzz/           libFuzzer targets and seeds
  routing/        rootless routing checks against a real kernel
  manual/         checks run by hand against a real kernel
  vendor/         vendored test framework
```

## Commands

Host libraries: libyaml, PCRE2, libmnl, cJSON, libcurl.

```sh
make                          # build/host/fircd, firc-configtool, firc-dnstool
make test                     # unit tests
make sanitize                 # unit tests under ASan + UBSan
make tsan                     # threaded tests under TSan
make static_analysis          # clang-tidy + cppcheck
make fuzz FUZZ_RUNS=200000    # libFuzzer targets
make routing                  # routing checks in a user namespace
sh tests/differential/run_diff.sh   # see BUILDING.md for the user-namespace wrapper
```

Run the daemon:

```sh
build/host/fircd --config /path/to/firc.conf   # groups.yaml is read next to it
```
