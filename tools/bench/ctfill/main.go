package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type result struct {
	Asked       int    `json:"asked"`
	Opened      int    `json:"destinations"`
	FirstError  string `json:"first_error,omitempty"`
	CountBefore int    `json:"conntrack_count_before,omitempty"`
	CountAfter  int    `json:"conntrack_count_after,omitempty"`
	CountMax    int    `json:"conntrack_max,omitempty"`
	Refreshes   int    `json:"refreshes"`
	HeldFor     string `json:"held_for"`
}

// procInt reads a kernel counter: the true entry count, of which ctfill's own total is a lower bound.
func procInt(paths ...string) int {
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err == nil {
			return n
		}
	}
	return 0
}

func conntrackCount() int {
	return procInt("/proc/sys/net/netfilter/nf_conntrack_count",
		"/proc/sys/net/ipv4/netfilter/ip_conntrack_count")
}

func conntrackMax() int {
	return procInt("/proc/sys/net/netfilter/nf_conntrack_max",
		"/proc/sys/net/ipv4/netfilter/ip_conntrack_max")
}

func targets(cidr string, firstPort, nPorts, n int) ([]*net.UDPAddr, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	base := ipnet.IP.To4()
	if base == nil {
		return nil, fmt.Errorf("%s: not an IPv4 prefix", cidr)
	}
	ones, bits := ipnet.Mask.Size()
	span := 1 << uint(bits-ones)
	if span > 2 {
		span -= 2
	}
	if nPorts < 1 {
		nPorts = 1
	}
	if span*nPorts < n {
		return nil, fmt.Errorf("%s with %d ports gives %d tuples, %d asked for",
			cidr, nPorts, span*nPorts, n)
	}
	v0 := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	out := make([]*net.UDPAddr, 0, n)
	for i := 0; i < n; i++ {
		v := v0 + uint32(i%span) + 1
		out = append(out, &net.UDPAddr{
			IP:   net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)),
			Port: firstPort + (i/span)%nPorts,
		})
	}
	return out, nil
}

func main() {
	n := flag.Int("n", 10000, "distinct flows (tuples) to keep alive")
	dst := flag.String("dst", "198.51.100.0/24", "destination prefix (TEST-NET-2 by default)")
	firstPort := flag.Int("first-port", 20000, "first destination port")
	nPorts := flag.Int("ports", 64, "how many destination ports to use per address")
	refresh := flag.Duration("refresh", 20*time.Second, "how often to re-send, to keep entries from ageing out")
	hold := flag.Duration("hold", 0, "how long to hold; 0 waits for SIGINT")
	flag.Parse()

	dests, err := targets(*dst, *firstPort, *nPorts, *n)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	res := result{Asked: *n, CountBefore: conntrackCount(), CountMax: conntrackMax()}
	if res.CountMax > 0 && res.CountBefore+*n > res.CountMax {
		// Past nf_conntrack_max the kernel evicts, so the table is not the size asked for.
		fmt.Fprintf(os.Stderr,
			"refusing: %d entries plus the %d already there exceeds nf_conntrack_max (%d)\n",
			*n, res.CountBefore, res.CountMax)
		os.Exit(2)
	}

	c, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func() { _ = c.Close() }()

	payload := []byte("firc-bench")
	send := func() int {
		sent := 0
		for _, a := range dests {
			if _, err := c.WriteToUDP(payload, a); err != nil {
				if res.FirstError == "" {
					// ENOBUFS under a burst is ordinary: report the count reached, do not fail.
					res.FirstError = err.Error()
				}
				time.Sleep(time.Millisecond)
				continue
			}
			sent++
		}
		return sent
	}

	res.Opened = send()
	time.Sleep(300 * time.Millisecond)
	res.CountAfter = conntrackCount()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	start := time.Now()
	deadline := time.Time{}
	if *hold > 0 {
		deadline = start.Add(*hold)
	}
	tick := time.NewTicker(*refresh)
	defer tick.Stop()
loop:
	for {
		select {
		case <-sig:
			break loop
		case <-tick.C:
			send()
			res.Refreshes++
			if got := conntrackCount(); got > res.CountAfter {
				res.CountAfter = got
			}
			if !deadline.IsZero() && time.Now().After(deadline) {
				break loop
			}
		}
	}
	res.HeldFor = time.Since(start).Round(time.Millisecond).String()

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
}
