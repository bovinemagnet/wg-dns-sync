package allowedips

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

func Build(staticCIDRs []string, resolvedIPs []netip.Addr) ([]netip.Prefix, error) {
	set := map[netip.Prefix]struct{}{}
	for _, cidr := range staticCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("invalid static CIDR %q: %w", cidr, err)
		}
		set[p.Masked()] = struct{}{}
	}
	for _, ip := range resolvedIPs {
		bits := 128
		if ip.Is4() {
			bits = 32
		}
		p := netip.PrefixFrom(ip, bits).Masked()
		set[p] = struct{}{}
	}

	out := make([]netip.Prefix, 0, len(set))
	for prefix := range set {
		out = append(out, prefix)
	}
	slices.SortFunc(out, comparePrefix)
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
