package allowedips

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Build merges static CIDRs and resolved host addresses into a deduplicated
// list of prefixes. Static entries are emitted before resolved entries, each in
// the order supplied. When sortResult is true the combined list is sorted
// deterministically (IPv4 before IPv6, then by address, then prefix length);
// otherwise insertion order is preserved.
func Build(staticCIDRs []string, resolvedIPs []netip.Addr, sortResult bool) ([]netip.Prefix, error) {
	seen := map[netip.Prefix]struct{}{}
	out := make([]netip.Prefix, 0, len(staticCIDRs)+len(resolvedIPs))
	add := func(p netip.Prefix) {
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, cidr := range staticCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("invalid static CIDR %q: %w", cidr, err)
		}
		add(p.Masked())
	}
	for _, ip := range resolvedIPs {
		bits := 128
		if ip.Is4() {
			bits = 32
		}
		add(netip.PrefixFrom(ip, bits).Masked())
	}
	if sortResult {
		slices.SortFunc(out, comparePrefix)
	}
	return out, nil
}

func ToStrings(prefixes []netip.Prefix) []string {
	out := make([]string, len(prefixes))
	for i, p := range prefixes {
		out[i] = p.String()
	}
	return out
}

func Format(prefixes []netip.Prefix, format string) (string, error) {
	values := ToStrings(prefixes)
	switch format {
	case "plain":
		return strings.Join(values, "\n"), nil
	case "wireguard":
		return "AllowedIPs = " + strings.Join(values, ", "), nil
	case "json":
		payload := struct {
			AllowedIPs []string `json:"allowed_ips"`
		}{AllowedIPs: values}
		b, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b), nil
	default:
		return "", fmt.Errorf("unsupported format %q", format)
	}
}

func comparePrefix(a, b netip.Prefix) int {
	a4 := a.Addr().Is4()
	b4 := b.Addr().Is4()
	if a4 != b4 {
		if a4 {
			return -1
		}
		return 1
	}
	if a.Addr().Less(b.Addr()) {
		return -1
	}
	if b.Addr().Less(a.Addr()) {
		return 1
	}
	if a.Bits() < b.Bits() {
		return -1
	}
	if a.Bits() > b.Bits() {
		return 1
	}
	return 0
}
