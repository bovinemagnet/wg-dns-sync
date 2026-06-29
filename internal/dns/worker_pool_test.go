package dns

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/bovinemagnet/wg-dns-sync/internal/config"
)

type fakeResolver struct {
	data map[string][]net.IPAddr
	err  map[string]error
}

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if err, ok := f.err[host]; ok {
		return nil, err
	}
	return f.data[host], nil
}

func TestResolveHostsFiltersIPv4(t *testing.T) {
	resolver := fakeResolver{data: map[string][]net.IPAddr{
		"a.example.com": {
			{IP: net.ParseIP("203.0.113.10")},
			{IP: net.ParseIP("2001:db8::1")},
		},
	}}
	cfg := config.DNSConfig{Concurrency: 2, Timeout: "1s", Retries: 0, Families: []string{"ipv4"}}
	results, err := ResolveHosts(context.Background(), resolver, []string{"a.example.com"}, cfg)
	if err != nil {
		t.Fatalf("ResolveHosts() error = %v", err)
	}
	if len(results) != 1 || len(results[0].IPs) != 1 || !results[0].IPs[0].Is4() {
		t.Fatalf("unexpected results: %+v", results)
	}
}

func TestResolveHostsLookupError(t *testing.T) {
	resolver := fakeResolver{err: map[string]error{"bad.example.com": errors.New("boom")}}
	cfg := config.DNSConfig{Concurrency: 1, Timeout: "1s", Retries: 0, Families: []string{"ipv4"}}
	results, err := ResolveHosts(context.Background(), resolver, []string{"bad.example.com"}, cfg)
	if err != nil {
		t.Fatalf("ResolveHosts() top-level error = %v", err)
	}
	if len(results) != 1 || results[0].Err == nil {
		t.Fatalf("expected per-host lookup error, got %+v", results)
	}
}
