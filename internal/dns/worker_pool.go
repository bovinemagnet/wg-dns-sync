package dns

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bovinemagnet/wg-dns-sync/internal/config"
)

type LookupResult struct {
	Host string
	IPs  []netip.Addr
	Err  error
}

func ResolveHosts(ctx context.Context, resolver IPResolver, hosts []string, cfg config.DNSConfig) ([]LookupResult, error) {
	if resolver == nil {
		resolver = NetResolver{}
	}
	concurrency := cfg.Concurrency
	if concurrency < config.MinDNSConcurrency {
		concurrency = config.MinDNSConcurrency
	}
	if concurrency > config.MaxDNSConcurrency {
		concurrency = config.MaxDNSConcurrency
	}
	timeout, err := time.ParseDuration(cfg.Timeout)
	if err != nil {
		return nil, err
	}
	family4, family6 := includeFamilies(cfg.Families)

	jobs := make(chan string)
	results := make(chan LookupResult, len(hosts))
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for host := range jobs {
			ips, lookupErr := lookupWithRetry(ctx, resolver, host, timeout, cfg.Retries)
			if lookupErr != nil {
				results <- LookupResult{Host: host, Err: lookupErr}
				continue
			}
			filtered := make([]netip.Addr, 0, len(ips))
			for _, ip := range ips {
				if ip.Is4() && family4 {
					filtered = append(filtered, ip)
				}
				if ip.Is6() && family6 {
					filtered = append(filtered, ip)
				}
			}
			if len(filtered) == 0 {
				results <- LookupResult{Host: host, Err: fmt.Errorf("no DNS records found for enabled families")}
				continue
			}
			results <- LookupResult{Host: host, IPs: filtered}
		}
	}

	workers := concurrency
	if len(hosts) < workers {
		workers = len(hosts)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}

	go func() {
		for _, host := range hosts {
			jobs <- host
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	out := make([]LookupResult, 0, len(hosts))
	for r := range results {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out, nil
}

func lookupWithRetry(parent context.Context, resolver IPResolver, host string, timeout time.Duration, retries int) ([]netip.Addr, error) {
	var lastErr error
	attempts := retries + 1
	for i := 0; i < attempts; i++ {
		ctx, cancel := context.WithTimeout(parent, timeout)
		raw, err := resolver.LookupIPAddr(ctx, host)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		ips := make([]netip.Addr, 0, len(raw))
		for _, item := range raw {
			if addr, ok := netip.AddrFromSlice(item.IP); ok {
				ips = append(ips, addr.Unmap())
			}
		}
		if len(ips) == 0 {
			lastErr = fmt.Errorf("no IP addresses resolved")
			continue
		}
		return ips, nil
	}
	return nil, fmt.Errorf("failed to resolve %s: %w", host, lastErr)
}

func includeFamilies(families []string) (bool, bool) {
	if len(families) == 0 {
		return true, false
	}
	var v4, v6 bool
	for _, f := range families {
		switch strings.ToLower(strings.TrimSpace(f)) {
		case "ipv4":
			v4 = true
		case "ipv6":
			v6 = true
		}
	}
	return v4, v6
}
