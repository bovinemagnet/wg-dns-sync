// SPDX-FileCopyrightText: 2026 Paul Snow
// SPDX-License-Identifier: AGPL-3.0-or-later

package wgsync

import "testing"

func TestInterfaceName(t *testing.T) {
	cases := []struct {
		configPath string
		override   string
		want       string
	}{
		{"/etc/wireguard/wg0.conf", "", "wg0"},
		{"/etc/wireguard/wg0.conf", "wg-home", "wg-home"},
		{"wg1.conf", "", "wg1"},
		{"/etc/wireguard/wg0.conf", "  ", "wg0"},
	}
	for _, c := range cases {
		if got := InterfaceName(c.configPath, c.override); got != c.want {
			t.Errorf("InterfaceName(%q, %q) = %q, want %q", c.configPath, c.override, got, c.want)
		}
	}
}
