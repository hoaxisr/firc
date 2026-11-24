package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

var (
	out         = flag.String("out", "-", "output file (- for stdout)")
	nRules      = flag.Int("rules", 1000, "number of rules")
	ruleType    = flag.String("type", "namespace", "rule type: domain|namespace|wildcard|regex|mixed")
	pattern     = flag.String("pattern", "d%06d.bench.example.com", "rule/domain pattern")
	groupEnable = flag.Bool("group-enable", false, "generate the group with enable: true (requires netfilter privileges)")
	upstream    = flag.String("upstream", "127.0.0.1", "upstream DNS address")
	upstreamPt  = flag.Int("upstream-port", 5399, "upstream DNS port")
	hostPort    = flag.Int("port", 3553, "DNS proxy listen port")
	hostAddr    = flag.String("addr", "0.0.0.0", "listen address for DNS proxy and HTTP (use [::] on dual-stack hosts)")
	listURL     = flag.String("list-url", "", "give the group a list fetched from this url (empty: no list)")
	listIval    = flag.Int("list-interval", 86400, "the list's update interval in seconds (0: no timer)")
	nLists      = flag.Int("lists", 1, "lists per group; with more than one, -list-url takes two %d: group and list index")
	nGroups     = flag.Int("groups", 1, "number of groups; only the first carries the rules")
)

func ruleFor(i int, t string) (string, string) {
	base := fmt.Sprintf(*pattern, i)
	switch t {
	case "domain", "namespace":
		return t, base
	case "wildcard":
		return t, "*." + base
	case "regex":
		return t, "^.*\\." + strings.ReplaceAll(base, ".", "\\.") + "$"
	default:
		panic("unknown type " + t)
	}
}

func main() {
	flag.Parse()

	mixed := []string{"domain", "namespace", "wildcard", "regex"}

	var b strings.Builder
	b.WriteString("configVersion: 0.7.0\n")
	b.WriteString("app:\n")
	fmt.Fprintf(&b, "  httpWeb:\n    enabled: true\n    auth:\n      enabled: false\n    host:\n      address: \"%s\"\n      port: 8080\n    skin: default\n", *hostAddr)
	fmt.Fprintf(&b, "  dnsProxy:\n    host:\n      address: \"%s\"\n      port: %d\n    upstream:\n      address: %s\n      port: %d\n", *hostAddr, *hostPort, *upstream, *upstreamPt)
	b.WriteString("    disableRemap53: true\n    disableDropAAAA: false\n    maxIdleConns: 10\n    maxConcurrent: 100\n    timeout: 5s\n")
	b.WriteString("  netfilter:\n    iptables:\n      chainPrefix: FIRC_\n    ipset:\n      tablePrefix: firc_\n      additionalTTL: 1h0m0s\n    disableIPv4: false\n    disableIPv6: false\n    startMarkTableIndex: 1718186595\n")
	b.WriteString("  link: []\n")
	b.WriteString("groups:\n")
	for g := 0; g < *nGroups; g++ {
		fmt.Fprintf(&b, "  - id: %08x\n    name: Bench%d\n    color: '#ffffff'\n    interface: %s\n    enable: %v\n    rules:\n", 0xaa000001+g, g, "blackhole", *groupEnable)
		if g == 0 {
			for i := 0; i < *nRules; i++ {
				t := *ruleType
				if t == "mixed" {
					t = mixed[i%len(mixed)]
				}
				rt, rv := ruleFor(i, t)
				fmt.Fprintf(&b, "      - id: %08x\n        name: r%d\n        type: %s\n        rule: '%s'\n        enable: true\n", 0x10000000+i, i, rt, rv)
			}
		}
		if *listURL != "" {
			b.WriteString("    lists:\n")
			for l := 0; l < *nLists; l++ {
				u := *listURL
				if *nLists > 1 {
					u = fmt.Sprintf(*listURL, g, l)
				}
				fmt.Fprintf(&b, "      - id: %08x\n        url: '%s'\n        interval: %d\n", 0x7a7a7a01+l, u, *listIval)
			}
		}
	}

	if *out == "-" {
		fmt.Print(b.String())
		return
	}
	if err := os.WriteFile(*out, []byte(b.String()), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
