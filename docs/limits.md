# Limits

Every hard cap in `fircd`, with its value and what happens when it is reached.

## The pool

At the shipped defaults these bite in table order; a group takes another chunk when its first fills.

| what | where | value | when it is reached |
|---|---|---|---|
| groups with a chunk | `FIRC_MARK_MAX_GROUPS`, `mark.h` | 255 | the mark field is eight bits: enabling another group fails with `FIRC_ERR_LIMIT`, and it stays out of the kernel |
| live names | `maxNames`, config | 65 536 | the name is answered with the blackhole address, never with the real one |
| addresses | pool and chunk size, config | 129 794 (v4 `198.18.0.0/15` in 511 usable `/24` chunks of 254) | the group's chunks are full and no chunk is free: same as above |
| a name's idle life | `idleWindow`, config | 24 h | the mapping is reclaimed and its address can be reused |
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
| in-flight queries | `maxConcurrent`, config | 100 | further queries wait |
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

## Not bounded

Bounded only indirectly, by a cap above.

| what | where | value | when it is reached |
|---|---|---|---|
| rules per group | `FIRC_HTTPD_MAX_BODY_BYTES`, `httpd.h` | 1 MiB of JSON per `PUT /groups` | 413 |
| a list rule's length | `firc_rule_is_usable` | none | a long rule is cut off in log lines that quote it |
| a list's rules | `FIRC_SUB_FETCH_MAX_BODY_BYTES`, `sub_fetch.h` | 8 MiB of list text | the fetch fails |
