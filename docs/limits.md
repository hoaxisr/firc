# Limits

Every hard cap in `fircd`, with its value and what happens when it is reached.

## The pool

At the shipped defaults these bite in table order; a group takes another chunk when its first fills.

| what | where | value | when it is reached |
|---|---|---|---|
| groups with a chunk | `FIRC_MARK_MAX_GROUPS`, `mark.h` | 255 | the mark field is eight bits: enabling another group fails with `FIRC_ERR_LIMIT`, and it stays out of the kernel |
| live names | `maxNames`, config | 65 536 | the name is answered with the blackhole address, never with the real one |
| addresses | pool and chunk size, config | 129 794 (v4 `198.18.0.0/15` in 511 usable `/24` chunks of 254) | the group's chunks are full and no chunk is free: same as above |
| a name's idle life | derived: twice `ttlClamp`, at least 1 h | 1 h | the mapping is reclaimed and its address can be reused |
| TTL handed to clients | `ttlClamp`, config | 5 min | longer TTLs are clamped to it |
| v6 chunks | generated ULA `/48`, `/64` chunks | 65 535 | not reachable before the limits above |

## conntrack

A flush bounds its allocation and its time on the DNS thread.

| what | where | value | when it is reached |
|---|---|---|---|
| entries deleted per family, per flush | `FIRC_CT_MAX_HITS`, `conntrack.c` | 4 096 | the rest wait for the next group flush or full rebuild pass; the startup stale-mark sweep leaves them |
| one dump datagram | `FIRC_CT_RECVBUF`, `conntrack.c` | 32 KiB | the dump is abandoned, drained and reported; nothing is deleted from a partial read |
| one delete request | `FIRC_CT_REQBUF`, `conntrack.c` | 1 KiB | that entry is skipped |
| a flow's original tuple | `FIRC_CT_TUPLE_MAX`, `conntrack.c` | 128 B | counted as an overflow, not as "not ours" |
| a flush's own requests and answers | `FIRC_CT_FLUSH_BUDGET_MS`, `conntrack.c` | 1 s | the flush stops and reports it did not finish; deletions so far stay |
| draining an abandoned dump | `FIRC_CT_DRAIN_BUDGET_MS`, `conntrack.c` | 500 ms | the drain gives up; the next flush may get `EBUSY` until the kernel finishes |
| a flush, wall clock | the two above | 1.5 s | the drain is charged after the budget, not out of it |

## The API

Applies to both the HTTP port and the Unix socket.

| what | where | value | when it is reached |
|---|---|---|---|
| concurrent connections | `FIRC_HTTPD_MAX_CONNS`, `httpd.h` | 64 | a new connection is closed at once |
| request headers | `FIRC_HTTPD_MAX_HEADER_BYTES`, `httpd.h` / `FIRC_HTTPD_MAX_REQ_HEADERS`, `httpd.c` | 8 KiB / 32 | 431 / later headers are ignored |
| request body | `FIRC_HTTPD_MAX_BODY_BYTES`, `httpd.h` | 1 MiB | 413 |
| routes, path segments, query params | `httpd.c` | 64 / 8 / 16 | route registration fails / longer paths do not match / later params are ignored |
| JWT token, subject, issuer | `jwt.h` | 1 KiB / 256 B / 64 B | longer claims are truncated |

## The DNS path

| what | where | value | when it is reached |
|---|---|---|---|
| in-flight queries | `maxConcurrent`, config | 100 | further queries are dropped, with a warning every 10 s; a query holds its slot until answered or timed out, so the ceiling is `maxConcurrent` / `timeout` queries per second while the upstream stalls (100 and 5 s: 20) |
| idle upstream connections | `maxIdleConns`, config | 10 | a new connection is opened instead |
| one message | `FIRC_DNS_MAX_MSG`, `dnswire.h` | 65 535 | the DNS wire limit |
| regex match / recursion | `FIRC_REGEX_MATCH_LIMIT` / `DEPTH_LIMIT`, `match.c` | 10^6 / 10^4 | PCRE2 gives up and the rule does not match |

## Elsewhere

| what | where | value | when it is reached |
|---|---|---|---|
| addresses a device selector considers for one host | `FIRC_DEVSEL_MAX_DEVICE_ADDRS`, `devices.h` | 64 | further addresses are not considered |
| ECMP next hops per route | `FIRC_NL_WATCHER_MAX_NEXTHOPS`, `netlink_watcher.h` | 8 | further next hops are not named |
| interface names pending a debounced refresh | `refresh_ifaces[8]`, `main.c` | 8 | everything is refreshed |
| captured `iptables` stderr | `FIRC_IPT_STDERR_CAP`, `executable_real.c` | 256 KiB | the rest is not kept |
| list body / redirects | `FIRC_SUB_FETCH_MAX_BODY_BYTES` / `FIRC_SUB_FETCH_MAX_REDIRECTS`, `sub_fetch.h` | 8 MiB / 5 | the fetch fails |
| one log line | `FIRC_LOG_LINE_MAX`, `log.c` | 1 KiB | the line is truncated silently |
| mark-field hint table | `hints[FIRC_MARK_MAX_GROUPS]`, `rtnl.c` | 255 | same ceiling as the groups |

## Subnet rules

| what | where | value | when it is reached |
|---|---|---|---|
| subnet rules without a protocol (prefix length 1 or more) | one `hash:net` set per group and family, `setnl.c` | about 30 bytes a prefix in the kernel (0.70 MB at 23 300, 2.92 MB at 100 000); no per-packet cost that grows with the count | a kernel without `ip_set`, `hash:net` or the `set` match refuses the group: it is left out of netfilter and has no chain; its names still get fake addresses and die on the pool's unreachable route, while traffic to its real prefixes is not marked and takes the main route, as for any group the kernel refuses |
| subnet rules with a protocol, and `/0` | two `mangle` rules each (one jump for a group with a selector) | about 0.4 us a rule per packet on MT7621, walked by every forwarded packet | keep them to hundreds |

### Measured on the bench unit

MT7621, 254 MB, kernel `4.9-ndm-5`; 23 300 IPv4 prefixes of eight lengths in a scratch `mangle` chain, jumped
from `PREROUTING` only while `ping -c 20 127.0.0.1` ran; the cost per packet is half the RTT gain. Script:
`tools/bench/run_subnet_sets.sh`. Rules were loaded by `iptables-restore --noflush` and the set by `ipset restore`, not by fircd. "Lines in the chain" is the line count of `iptables -S` on the scratch chain: it includes the `-N` line and leaves out B2's sub-chain, which is why C reads 3.

| shape | lines in the chain | kernel table | load | a foreign `iptables -N` | per packet |
|---|---|---|---|---|---|
| A: MARK and CONNMARK rule per prefix | 46 601 | 17.73 MB | 7.0 s, 39 MB RSS | 1.2-1.5 s | +18.7 ms |
| B: MARK per prefix, one CONNMARK at the end | 23 302 | 9.33 MB | 4.0 s, 22 MB RSS | 0.66 s | +10.9 ms |
| B2: `-d <cidr> -j <sub-chain>` per prefix | 23 301 | 3.54 MB | 2.2 s, 10 MB RSS | 0.36 s | +9.7 ms |
| C: one `hash:net` set and two rules | 3 | set 0.47 MB | 1.4 s set + 0.05 s | 0.02 s | within noise (+0.01 ms) |

At 2 000 prefixes: A +1.65 ms, B +0.86 ms, B2 +0.68 ms, C +0.04 ms. The walk is linear in the rule count. Not
measured in that run: IPv6, aarch64 and big-endian mips.

The daemon itself on the same unit, a group whose list holds the prefixes (lengths /22 to /32), beside four
other groups with sets:

| | no such group | 23 300 prefixes | 100 000 prefixes |
|---|---|---|---|
| lines in `mangle` | 219 | 224 | 224 |
| the set | - | 0.70 MB | 2.92 MB |
| list request to the set in the kernel | - | 1.7 s | 6.0 s |
| `fircd` VmHWM / VmRSS | 12.9 / 12.9 MB | 26.2 / 21.4 MB | 66.4 / 36.8 MB |
| `ping -c 20 127.0.0.1`, avg | 0.50 ms | 0.50 ms | 0.52 ms |

A restart brings every group back, the 23 000-prefix one included, 1.4 s after the start. While the
100 000-line list was applied one API request waited 2.3 s. The daemon keeps about 200 bytes a subnet rule in
its own memory, which is the peak above.

## Not bounded

Bounded only indirectly, by a cap above.

| what | where | value | when it is reached |
|---|---|---|---|
| rules per group | `FIRC_HTTPD_MAX_BODY_BYTES`, `httpd.h` | 1 MiB of JSON per `PUT /groups` | 413 |
| a list rule's length | `firc_rule_is_usable` | none | a long rule is cut off in log lines that quote it |
| a list's rules | `FIRC_SUB_FETCH_MAX_BODY_BYTES`, `sub_fetch.h` | 8 MiB of list text | the fetch fails |
