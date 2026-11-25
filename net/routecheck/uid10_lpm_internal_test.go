// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"net/netip"
	"testing"

	"tailscale.com/tailcfg"
)

func TestUID10_IncrementalRouteTrieLPMAndCOW(t *testing.T) {
	d := func(id int64) *SegmentDecision {
		n := tailcfg.NodeID(id)
		return &SegmentDecision{WinnerID: n, CarrierID: n}
	}

	var tr *routeTrie
	tr = tr.upsert(netip.MustParsePrefix("10.0.0.0/16"), d(16))
	tr = tr.upsert(netip.MustParsePrefix("10.0.1.0/24"), d(24))
	tr = tr.upsert(netip.MustParsePrefix("0.0.0.0/0"), d(0))
	tr = tr.upsert(netip.MustParsePrefix("2001:db8::/32"), d(32))
	tr = tr.upsert(netip.MustParsePrefix("2001:db8:1::/48"), d(48))

	cases := []struct {
		addr string
		want int64
		ok   bool
	}{
		{"10.0.1.9", 24, true}, // /24 wins over /16
		{"10.0.2.9", 16, true}, // only /16
		{"10.1.2.3", 0, true},  // falls to /0
		{"8.8.8.8", 0, true},   // /0
		{"2001:db8:1::5", 48, true},
		{"2001:db8:2::5", 32, true},
	}
	for _, tc := range cases {
		got, ok := tr.lookup(netip.MustParseAddr(tc.addr))
		if ok != tc.ok {
			t.Fatalf("%s ok=%v want %v", tc.addr, ok, tc.ok)
		}
		if ok && int64(got.CarrierID) != tc.want {
			t.Fatalf("%s carrier=%d want %d", tc.addr, got.CarrierID, tc.want)
		}
	}

	// An older root stays valid after an incremental delete+insert (COW).
	before := tr
	tr2 := tr.deletePrefix(netip.MustParsePrefix("10.0.1.0/24"))
	if got, ok := tr2.lookup(netip.MustParseAddr("10.0.1.9")); !ok || int64(got.CarrierID) != 16 {
		t.Fatalf("after delete lookup carrier=%v ok=%v, want /16", got, ok)
	}
	if got, ok := before.lookup(netip.MustParseAddr("10.0.1.9")); !ok || int64(got.CarrierID) != 24 {
		t.Fatalf("old root mutated: carrier=%v ok=%v, want /24", got, ok)
	}

	// Deleting the /0 removes the default match.
	tr3 := tr2.deletePrefix(netip.MustParsePrefix("0.0.0.0/0"))
	if _, ok := tr3.lookup(netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("default route still present after /0 delete")
	}
}
