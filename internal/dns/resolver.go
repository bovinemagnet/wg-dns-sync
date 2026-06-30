// SPDX-FileCopyrightText: 2026 Paul Snow
// SPDX-License-Identifier: AGPL-3.0-or-later

package dns

import (
	"context"
	"net"
)

type IPResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type NetResolver struct {
	Resolver *net.Resolver
}

func (r NetResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	resolver := r.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return resolver.LookupIPAddr(ctx, host)
}
