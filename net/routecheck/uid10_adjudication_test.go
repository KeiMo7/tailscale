// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck_test

import (
	"bytes"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	gcmp "github.com/google/go-cmp/cmp"
	gcmpopts "github.com/google/go-cmp/cmp/cmpopts"

	"tailscale.com/ipn"
	"tailscale.com/net/routecheck"
	"tailscale.com/net/routecheck/peernode"
	"tailscale.com/tailcfg"
)

var u10CmpNetip = gcmpopts.EquateComparable(netip.Addr{}, netip.Prefix{})

// u10Clock is a deterministic clock.
type u10Clock struct{ t time.Time }

func u10NewClock() *u10Clock            { return &u10Clock{t: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)} }
func (c *u10Clock) now() time.Time      { return c.t }
func (c *u10Clock) add(d time.Duration) { c.t = c.t.Add(d) }

func u10Prefs() routecheck.AdjudicationPrefs {
	return routecheck.AdjudicationPrefs{AcceptSubnetRoutes: true, ProbeAvailable: true}
}

func u10Cand(id tailcfg.NodeID) routecheck.Candidate {
	return routecheck.Candidate{
		ID:       id,
		StableID: tailcfg.StableNodeID(fmt.Sprintf("stable%d", id)),
		Name:     fmt.Sprintf("node%d", id),
	}
}

func u10Adv(id tailcfg.NodeID, pfx string) routecheck.Advertisement {
	return routecheck.Advertisement{Prefix: netip.MustParsePrefix(pfx), Candidate: u10Cand(id)}
}

func u10Reach(id tailcfg.NodeID, s peernode.Reachability, at time.Time) routecheck.ReachConclusion {
	return routecheck.ReachConclusion{Node: id, Reachability: s, At: at}
}

func u10NewEngine(t *testing.T, p routecheck.AdjudicationPrefs) (*routecheck.Adjudicator, *u10Clock) {
	t.Helper()
	clock := u10NewClock()
	a := routecheck.NewAdjudicator(p, routecheck.WithClock(clock.now))
	return a, clock
}

func u10MustDecision(t *testing.T, s *routecheck.Snapshot, pfx string) *routecheck.SegmentDecision {
	t.Helper()
	d := s.Decision(netip.MustParsePrefix(pfx))
	if d == nil {
		var pfxs []string
		for p := range s.Segments {
			pfxs = append(pfxs, p.String())
		}
		t.Fatalf("missing decision for %s; have %v", pfx, pfxs)
	}
	return d
}

// 1. Same segment, multiple nodes: unique winner and ordered backups,
// ordered by reachability then stable node order, independent of insertion.
func TestUID10_AdjudicateSameSegmentMultipleCandidates(t *testing.T) {
	a, clock := u10NewEngine(t, u10Prefs())
	pfx := "10.0.1.0/24"

	// Insert in a deliberately awkward order.
	a.ReplaceAdvertisements([]routecheck.Advertisement{
		u10Adv(33, pfx), u10Adv(11, pfx), u10Adv(22, pfx),
	})
	a.ApplyConclusions(
		u10Reach(33, peernode.Unreachable, clock.now()),
		u10Reach(22, peernode.Reachable, clock.now()),
		u10Reach(11, peernode.Reachable, clock.now()),
	)

	d := u10MustDecision(t, a.Snapshot(), pfx)
	if d.WinnerID != 11 {
		t.Fatalf("winner = %d, want 11 (reachable, lowest stable order)", d.WinnerID)
	}
	wantBackups := []tailcfg.NodeID{22, 33}
	if !slices.Equal(d.BackupIDs, wantBackups) {
		t.Fatalf("backups = %v, want %v", d.BackupIDs, wantBackups)
	}
	if d.Reason != routecheck.ReasonReachableFirst {
		t.Fatalf("reason = %q, want %q", d.Reason, routecheck.ReasonReachableFirst)
	}
	if d.CarrierID != 11 || d.ChosenPrefix.String() != pfx {
		t.Fatalf("carrier=%d chosen=%v, want 11 @ %s", d.CarrierID, d.ChosenPrefix, pfx)
	}

	// Exactly one selected candidate.
	selected := 0
	for _, c := range d.Candidates {
		if c.Selected {
			selected++
		}
	}
	if selected != 1 {
		t.Fatalf("selected candidates = %d, want exactly 1", selected)
	}

	// All-unknown baseline still picks the stable-first node.
	a2, _ := u10NewEngine(t, u10Prefs())
	a2.ReplaceAdvertisements([]routecheck.Advertisement{u10Adv(33, pfx), u10Adv(11, pfx), u10Adv(22, pfx)})
	d2 := u10MustDecision(t, a2.Snapshot(), pfx)
	if d2.WinnerID != 11 || !slices.Equal(d2.BackupIDs, []tailcfg.NodeID{22, 33}) {
		t.Fatalf("baseline order winner=%d backups=%v, want 11 / [22 33]", d2.WinnerID, d2.BackupIDs)
	}
}

// 2. Nested fallback and recovery: narrow /24 holder fails, addresses move
// to the wider /16 node; other addresses in the /16 stay unchanged; recovery
// immediately restores the narrow node.
func TestUID10_AdjudicateNestedFallbackAndRecovery(t *testing.T) {
	a, clock := u10NewEngine(t, u10Prefs())
	wide := "10.0.0.0/16"
	narrow := "10.0.1.0/24"
	a.ReplaceAdvertisements([]routecheck.Advertisement{
		u10Adv(10, wide),
		u10Adv(20, narrow),
	})

	// Baseline: most-specific carrier 20.
	if lk, ok := a.Snapshot().LookupAddr(netip.MustParseAddr("10.0.1.7")); !ok || lk.CarrierID != 20 || lk.FellBack {
		t.Fatalf("baseline lookup 10.0.1.7 = %+v ok=%v, want carrier 20 no fallback", lk, ok)
	}

	// Narrow holder is freshly unreachable.
	a.ApplyConclusion(u10Reach(20, peernode.Unreachable, clock.now()))

	n := u10MustDecision(t, a.Snapshot(), narrow)
	if n.CarrierID != 10 || n.ChosenPrefix.String() != wide || n.Reason != routecheck.ReasonFallback {
		t.Fatalf("narrow decision carrier=%d chosen=%v reason=%q, want 10/%s/fallback",
			n.CarrierID, n.ChosenPrefix, n.Reason, wide)
	}
	if !slices.Equal(n.FallbackPath, []netip.Prefix{
		netip.MustParsePrefix(narrow), netip.MustParsePrefix(wide),
	}) {
		t.Fatalf("fallback path = %v", n.FallbackPath)
	}
	lk, ok := a.Snapshot().LookupAddr(netip.MustParseAddr("10.0.1.7"))
	if !ok || lk.CarrierID != 10 || !lk.FellBack {
		t.Fatalf("lookup after fail = %+v ok=%v, want carrier 10 via fallback", lk, ok)
	}

	// Address elsewhere in the wide segment is unchanged.
	lk2, ok := a.Snapshot().LookupAddr(netip.MustParseAddr("10.0.9.9"))
	if !ok || lk2.CarrierID != 10 || lk2.FellBack {
		t.Fatalf("wide address lookup = %+v ok=%v, want carrier 10 direct", lk2, ok)
	}
	w := u10MustDecision(t, a.Snapshot(), wide)
	if w.CarrierID != 10 || w.Reason != routecheck.ReasonSoleCandidate {
		t.Fatalf("wide decision changed unexpectedly: %+v", w)
	}

	// Recovery: fresh reachable conclusion immediately restores narrow node.
	clock.add(time.Second)
	a.ApplyConclusion(u10Reach(20, peernode.Reachable, clock.now()))
	lk3, ok := a.Snapshot().LookupAddr(netip.MustParseAddr("10.0.1.7"))
	if !ok || lk3.CarrierID != 20 || lk3.FellBack {
		t.Fatalf("lookup after recovery = %+v ok=%v, want carrier 20 restored", lk3, ok)
	}
	n2 := u10MustDecision(t, a.Snapshot(), narrow)
	if n2.Reason != routecheck.ReasonSoleCandidate {
		t.Fatalf("recovered reason = %q, want sole-candidate", n2.Reason)
	}
}

// Multi-level nesting: /24 -> /16 -> /8.
func TestUID10_AdjudicateMultiLevelFallback(t *testing.T) {
	a, clock := u10NewEngine(t, u10Prefs())
	p8, p16, p24 := "10.0.0.0/8", "10.0.0.0/16", "10.0.1.0/24"
	a.ReplaceAdvertisements([]routecheck.Advertisement{
		u10Adv(8, p8), u10Adv(16, p16), u10Adv(24, p24),
	})

	a.ApplyConclusion(u10Reach(24, peernode.Unreachable, clock.now()))
	if d := u10MustDecision(t, a.Snapshot(), p24); d.CarrierID != 16 || d.ChosenPrefix.String() != p16 {
		t.Fatalf("first tier fallback carrier=%d chosen=%v, want 16 @ /16", d.CarrierID, d.ChosenPrefix)
	}

	a.ApplyConclusion(u10Reach(16, peernode.Unreachable, clock.now()))
	if d := u10MustDecision(t, a.Snapshot(), p24); d.CarrierID != 8 || d.ChosenPrefix.String() != p8 || d.Reason != routecheck.ReasonFallback {
		t.Fatalf("second tier fallback carrier=%d chosen=%v reason=%s, want 8 @ /8 fallback", d.CarrierID, d.ChosenPrefix, d.Reason)
	}
}

// 4. Unknown is not unavailable: new/unknown candidates never depose a
// winner; expiry and suspicious sources become unknown (stale) and hold;
// disabled probing returns the baseline result.
func TestUID10_AdjudicateUnknownAndProbeDisabled(t *testing.T) {
	p := u10Prefs()
	p.ConclusionTTL = time.Minute
	a, clock := u10NewEngine(t, p)
	pfx := "10.0.2.0/24"
	a.ReplaceAdvertisements([]routecheck.Advertisement{u10Adv(11, pfx), u10Adv(22, pfx)})
	a.ApplyConclusions(
		u10Reach(11, peernode.Reachable, clock.now()),
		u10Reach(22, peernode.Reachable, clock.now()),
	)
	if d := u10MustDecision(t, a.Snapshot(), pfx); d.WinnerID != 11 {
		t.Fatalf("initial winner = %d, want 11", d.WinnerID)
	}

	// A brand new candidate with no conclusion is unknown and must not win.
	a.UpsertAdvertisement(u10Adv(10, pfx))
	if d := u10MustDecision(t, a.Snapshot(), pfx); d.WinnerID != 11 {
		t.Fatalf("unknown new candidate changed winner to %d", d.WinnerID)
	}
	// Remove it again so the hold assertion uses the original stable order.
	a.RemoveAdvertisement(netip.MustParsePrefix(pfx), 10)

	// Expire both conclusions: unknown + stale, incumbent held.
	clock.add(2 * time.Minute)
	a.Reevaluate()
	d := u10MustDecision(t, a.Snapshot(), pfx)
	if d.WinnerID != 11 || d.Reason != routecheck.ReasonHold {
		t.Fatalf("after expiry winner=%d reason=%q, want 11/hold", d.WinnerID, d.Reason)
	}
	w := d.Winner()
	if w == nil || !w.Stale || w.Reachability != peernode.Unknown || !w.Available {
		t.Fatalf("winner assessment after expiry = %+v, want stale unknown available", w)
	}

	// Once every conclusion is expired/unknown, ordering matches today's
	// baseline stable order even when a lower-ID node was newly added.
	a.UpsertAdvertisement(u10Adv(10, pfx))
	a.Reevaluate()
	if d := u10MustDecision(t, a.Snapshot(), pfx); d.WinnerID != 10 {
		t.Fatalf("fully unknown result winner=%d, want baseline stable-first 10", d.WinnerID)
	}

	// A suspicious conclusion is likewise unknown and flagged.
	a2, clock2 := u10NewEngine(t, u10Prefs())
	a2.ReplaceAdvertisements([]routecheck.Advertisement{u10Adv(11, pfx), u10Adv(22, pfx)})
	rc := u10Reach(11, peernode.Reachable, clock2.now())
	rc.Suspicious = true
	a2.ApplyConclusion(rc)
	d2 := u10MustDecision(t, a2.Snapshot(), pfx)
	w2 := d2.Winner()
	if w2 == nil || !w2.Suspicious || !w2.Stale || w2.Reachability != peernode.Unknown {
		t.Fatalf("suspicious assessment = %+v, want suspicious stale unknown", w2)
	}

	// Probe source unavailable: reachability ignored, baseline stable order.
	p3 := u10Prefs()
	p3.ProbeAvailable = false
	a3 := routecheck.NewAdjudicator(p3, routecheck.WithClock(u10NewClock().now))
	a3.ReplaceAdvertisements([]routecheck.Advertisement{u10Adv(22, pfx), u10Adv(11, pfx)})
	// Even an (untrusted) unreachable conclusion must not cause fallback.
	a3.ApplyConclusion(routecheck.ReachConclusion{Node: 11, Reachability: peernode.Unreachable})
	d3 := u10MustDecision(t, a3.Snapshot(), pfx)
	if d3.WinnerID != 11 || d3.Reason != routecheck.ReasonProbeUnavailable {
		t.Fatalf("probe-disabled winner=%d reason=%q, want 11/probe-unavailable", d3.WinnerID, d3.Reason)
	}
}

// 5. Incremental recomputation and idempotency.
func TestUID10_AdjudicateIncrementalAndIdempotent(t *testing.T) {
	a, _ := u10NewEngine(t, u10Prefs())
	p1, p2 := "10.1.0.0/24", "10.2.0.0/24"
	a.ReplaceAdvertisements([]routecheck.Advertisement{
		u10Adv(11, p1), u10Adv(12, p1),
		u10Adv(21, p2), u10Adv(22, p2),
	})
	snap1 := a.Snapshot()
	d2Before := snap1.Segments[netip.MustParsePrefix(p2)]
	recBefore := a.Stats().Recomputations

	rcDown := u10Reach(11, peernode.Unreachable, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC))
	out := a.ApplyConclusion(rcDown)
	if len(out.Recomputed) != 1 || out.Recomputed[0].String() != p1 {
		t.Fatalf("recomputed = %v, want exactly [%s]", out.Recomputed, p1)
	}
	if got := a.Stats().Recomputations - recBefore; got != 1 {
		t.Fatalf("recompute delta = %d, want 1", got)
	}
	snap2 := a.Snapshot()
	if snap2.Segments[netip.MustParsePrefix(p2)] != d2Before {
		t.Fatal("unaffected segment decision was rebuilt/replaced")
	}
	if snap2.Generation == snap1.Generation {
		t.Fatal("expected a new published generation")
	}

	// Exact same conclusion redelivered is a no-op.
	if dup := a.ApplyConclusion(rcDown); !dup.Duplicate {
		t.Fatalf("identical redelivery not marked duplicate: %+v", dup)
	}
	if a.Snapshot().Generation != snap2.Generation {
		t.Fatal("duplicate conclusion changed generation")
	}
	if a.Stats().DuplicateUpdates == 0 {
		t.Fatal("duplicate counter did not increase")
	}

	// A different node's identical payload delivered twice is also a no-op.
	rc := u10Reach(12, peernode.Reachable, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	a.ApplyConclusion(rc)
	gBeforeDup := a.Snapshot().Generation
	dup := a.ApplyConclusion(rc)
	if !dup.Duplicate || a.Snapshot().Generation != gBeforeDup {
		t.Fatalf("second-node redelivery not idempotent: %+v", dup)
	}

	// The same reachability state with a fresh timestamp re-evaluates but
	// changes no segment conclusion: no update/selection event, no publish.
	beforeGen := a.Snapshot().Generation
	refreshed := u10Reach(11, peernode.Unreachable, time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC))
	outRefresh := a.ApplyConclusion(refreshed)
	if outRefresh.Published || len(outRefresh.Updated) != 0 || len(outRefresh.SelectionChanged) != 0 {
		t.Fatalf("state-refresh produced change events: %+v", outRefresh)
	}
	if a.Snapshot().Generation != beforeGen {
		t.Fatal("state-refresh published a new generation")
	}
}

// Recompute cone: changing a wide segment re-adjudicates nested dependents;
// changing a narrow segment does not recompute the wide one.
func TestUID10_AdjudicateRecomputeCone(t *testing.T) {
	a, clock := u10NewEngine(t, u10Prefs())
	wide, narrow := "10.0.0.0/16", "10.0.1.0/24"
	a.ReplaceAdvertisements([]routecheck.Advertisement{u10Adv(10, wide), u10Adv(20, narrow)})

	out := a.ApplyConclusion(u10Reach(10, peernode.Reachable, clock.now()))
	if len(out.Recomputed) != 2 {
		t.Fatalf("wide-node recompute = %v, want wide+narrow cone", out.Recomputed)
	}

	out = a.ApplyConclusion(u10Reach(20, peernode.Reachable, clock.now()))
	if len(out.Recomputed) != 1 || out.Recomputed[0].String() != narrow {
		t.Fatalf("narrow-node recompute = %v, want only [%s]", out.Recomputed, narrow)
	}
}

// 3 (stability). Flap damping prevents rapid flip-flopping, then time-based
// reevaluation restores the preferred node after cooldown.
func TestUID10_AdjudicateFlapDamping(t *testing.T) {
	a, clock := u10NewEngine(t, u10Prefs())
	pfx := "10.0.3.0/24"
	a.ReplaceAdvertisements([]routecheck.Advertisement{u10Adv(11, pfx), u10Adv(22, pfx)})

	a.ApplyConclusions(
		u10Reach(11, peernode.Reachable, clock.now()),
		u10Reach(22, peernode.Reachable, clock.now()),
	)
	if d := u10MustDecision(t, a.Snapshot(), pfx); d.WinnerID != 11 {
		t.Fatalf("initial winner = %d, want 11", d.WinnerID)
	}

	flip := func(s peernode.Reachability) {
		clock.add(time.Second)
		a.ApplyConclusion(u10Reach(11, s, clock.now()))
	}
	flip(peernode.Unreachable) // #1 -> 22
	if d := u10MustDecision(t, a.Snapshot(), pfx); d.WinnerID != 22 {
		t.Fatalf("after down winner=%d, want 22", d.WinnerID)
	}
	flip(peernode.Reachable) // #2 -> immediate recovery to 11
	if d := u10MustDecision(t, a.Snapshot(), pfx); d.WinnerID != 11 {
		t.Fatalf("single-cycle recovery winner=%d, want immediate 11", d.WinnerID)
	}
	flip(peernode.Unreachable) // #3 arms damping, winner 22
	flip(peernode.Reachable)   // #4 dampened recovery must be ignored

	d := u10MustDecision(t, a.Snapshot(), pfx)
	if d.WinnerID != 22 || d.Reason != routecheck.ReasonFlapIgnored {
		t.Fatalf("dampened winner=%d reason=%q, want 22/flap-ignored", d.WinnerID, d.Reason)
	}
	if a.Stats().FlapIgnored == 0 {
		t.Fatal("flap-ignored counter is zero")
	}
	var damp bool
	for _, c := range d.Candidates {
		if c.ID == 11 {
			damp = c.Dampened
		}
	}
	if !damp {
		t.Fatal("node 11 not marked dampened")
	}

	// Past cooldown, reevaluation lets 11 preempt again.
	clock.add(31 * time.Second)
	a.Reevaluate()
	if d := u10MustDecision(t, a.Snapshot(), pfx); d.WinnerID != 11 {
		t.Fatalf("post-cooldown winner=%d, want 11", d.WinnerID)
	}
}

// 7. All tiers unavailable still yields a conclusion: baseline carrier stays
// in the tunnel, with an observable alert and count.
func TestUID10_AdjudicateAllUnavailableAlert(t *testing.T) {
	a, clock := u10NewEngine(t, u10Prefs())
	wide, narrow := "10.0.0.0/16", "10.0.1.0/24"
	a.ReplaceAdvertisements([]routecheck.Advertisement{u10Adv(10, wide), u10Adv(20, narrow)})
	a.ApplyConclusions(
		u10Reach(20, peernode.Unreachable, clock.now()),
		u10Reach(10, peernode.Unreachable, clock.now()),
	)

	s := a.Snapshot()
	d := u10MustDecision(t, s, narrow)
	if !d.AllUnavailable || d.Reason != routecheck.ReasonAllUnavailable {
		t.Fatalf("decision allUnavailable=%v reason=%q, want true/all-unavailable", d.AllUnavailable, d.Reason)
	}
	// Packets still go into the tunnel via today's baseline carrier.
	if d.CarrierID != 20 {
		t.Fatalf("baseline carrier = %d, want 20", d.CarrierID)
	}
	lk, ok := s.LookupAddr(netip.MustParseAddr("10.0.1.9"))
	if !ok || lk.CarrierID != 20 || !lk.AllUnavailable {
		t.Fatalf("lookup = %+v ok=%v, want tunnel baseline 20 all-unavailable", lk, ok)
	}
	if len(s.Alerts) == 0 {
		t.Fatal("expected an observable alert")
	}
	if a.Stats().AllUnavailable == 0 {
		t.Fatal("all-unavailable counter is zero")
	}
}

// 6. Exceptions: exit routes only via selected exit node; self/service/source
// validation prefixes excluded; disabling accept-subnet-routes adopts nothing.
func TestUID10_AdjudicateExceptions(t *testing.T) {
	// Exit route handling.
	a, _ := u10NewEngine(t, u10Prefs())
	p := u10Prefs()
	p.ExitNode = "stable12"
	a.SetPreferences(p)
	a.ReplaceAdvertisements([]routecheck.Advertisement{
		u10Adv(11, "0.0.0.0/0"), u10Adv(12, "0.0.0.0/0"),
	})
	d := u10MustDecision(t, a.Snapshot(), "0.0.0.0/0")
	if d.WinnerID != 12 || d.CarrierID != 12 || d.Reason != routecheck.ReasonExitNode {
		t.Fatalf("exit decision winner=%d carrier=%d reason=%q, want 12", d.WinnerID, d.CarrierID, d.Reason)
	}
	for _, c := range d.Candidates {
		if c.ID == 11 && c.Eligible {
			t.Fatal("non-selected exit advertiser marked eligible")
		}
	}
	if lk, ok := a.Snapshot().LookupAddr(netip.MustParseAddr("8.8.8.8")); !ok || lk.CarrierID != 12 {
		t.Fatalf("exit lookup = %+v ok=%v, want 12", lk, ok)
	}

	// A default route is never a fallback tier for a subnet.
	a2, clock := u10NewEngine(t, u10Prefs())
	a2.ReplaceAdvertisements([]routecheck.Advertisement{u10Adv(11, "10.5.0.0/24"), u10Adv(99, "0.0.0.0/0")})
	a2.ApplyConclusion(u10Reach(11, peernode.Unreachable, clock.now()))
	d2 := u10MustDecision(t, a2.Snapshot(), "10.5.0.0/24")
	if d2.ChosenPrefix.String() != "10.5.0.0/24" || !d2.AllUnavailable {
		t.Fatalf("subnet fallback leaked to default route: chosen=%v all=%v", d2.ChosenPrefix, d2.AllUnavailable)
	}

	// Excluded prefix kinds never produce segments.
	a3 := routecheck.NewAdjudicator(u10Prefs())
	self := u10Adv(11, "100.64.0.11/32")
	self.Purpose = routecheck.PurposeSelfAddress
	svc := u10Adv(11, "100.100.100.100/32")
	svc.Purpose = routecheck.PurposeServiceAddress
	srcv := u10Adv(12, "192.168.9.0/24")
	srcv.Purpose = routecheck.PurposeSourceValidation
	a3.ReplaceAdvertisements([]routecheck.Advertisement{self, svc, srcv, u10Adv(11, "10.6.0.0/24")})
	s3 := a3.Snapshot()
	if len(s3.Segments) != 1 {
		t.Fatalf("segments = %d, want exactly 1 subnet: %v", len(s3.Segments), s3.Segments)
	}
	if len(s3.Ignored) != 3 {
		t.Fatalf("ignored = %d entries, want 3: %+v", len(s3.Ignored), s3.Ignored)
	}

	// Accept subnet routes off: no subnet adopted, no fallback alerts.
	off := u10Prefs()
	off.AcceptSubnetRoutes = false
	a4 := routecheck.NewAdjudicator(off)
	a4.ReplaceAdvertisements([]routecheck.Advertisement{u10Adv(11, "10.7.0.0/24"), u10Adv(22, "10.7.0.0/24")})
	s4 := a4.Snapshot()
	if len(s4.Segments) != 0 || len(s4.Alerts) != 0 {
		t.Fatalf("accept-off segments=%d alerts=%d, want none", len(s4.Segments), len(s4.Alerts))
	}
	if len(s4.Ignored) == 0 {
		t.Fatal("expected ignored audit entries while accept is off")
	}
	// Turning it back on adjudicates again.
	on := off
	on.AcceptSubnetRoutes = true
	a4.SetPreferences(on)
	if len(a4.Snapshot().Segments) != 1 {
		t.Fatalf("re-enable segments = %d, want 1", len(a4.Snapshot().Segments))
	}
}

// Removal/revocation never leaves a half-open published result, and an old
// snapshot taken before removal stays valid.
func TestUID10_AdjudicatorRemovalAtomicAndOldSnapshotUsable(t *testing.T) {
	a, clock := u10NewEngine(t, u10Prefs())
	wide, narrow := "10.0.0.0/16", "10.0.1.0/24"
	a.ReplaceAdvertisements([]routecheck.Advertisement{u10Adv(10, wide), u10Adv(20, narrow)})
	a.ApplyConclusion(u10Reach(20, peernode.Unreachable, clock.now()))
	before := a.Snapshot()
	lk, _ := before.LookupAddr(netip.MustParseAddr("10.0.1.1"))
	if lk.CarrierID != 10 {
		t.Fatalf("pre-removal carrier = %d, want 10", lk.CarrierID)
	}

	a.RemoveNode(20)
	after := a.Snapshot()
	for pfx, d := range after.Segments {
		if d.WinnerID == 20 || d.CarrierID == 20 {
			t.Fatalf("segment %s still references removed node 20", pfx)
		}
		for _, c := range d.Candidates {
			if c.ID == 20 {
				t.Fatalf("segment %s still lists removed candidate 20", pfx)
			}
		}
	}
	// The narrow decision is gone; LPM falls through to the wide segment.
	if d := after.Decision(netip.MustParsePrefix(narrow)); d != nil {
		t.Fatal("revoked node left a stale narrow decision")
	}
	lk2, ok := after.LookupAddr(netip.MustParseAddr("10.0.1.1"))
	if !ok || lk2.CarrierID != 10 {
		t.Fatalf("post-removal lookup = %+v ok=%v, want wide carrier 10", lk2, ok)
	}

	// Old snapshot remains self-consistent and usable.
	oldLK, ok := before.LookupAddr(netip.MustParseAddr("10.0.1.1"))
	if !ok || oldLK.CarrierID != 10 {
		t.Fatalf("old snapshot lookup changed/unusable: %+v ok=%v", oldLK, ok)
	}

	// RevokePrefix path.
	a.RevokePrefix(netip.MustParsePrefix(wide))
	if len(a.Snapshot().Segments) != 0 {
		t.Fatalf("after revoke segments = %v, want empty", a.Snapshot().Segments)
	}
}

// Concurrent conclusions are race-free and every published snapshot is
// internally consistent: one conclusion per segment, no dangling carriers.
func TestUID10_AdjudicatorConcurrentConclusions(t *testing.T) {
	a, _ := u10NewEngine(t, u10Prefs())
	pfx := "10.8.0.0/24"
	a.ReplaceAdvertisements([]routecheck.Advertisement{u10Adv(11, pfx), u10Adv(22, pfx), u10Adv(33, pfx)})

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				id := tailcfg.NodeID([]int{11, 22, 33}[(i+g)%3])
				st := []peernode.Reachability{peernode.Reachable, peernode.Unreachable, peernode.Unknown}[i%3]
				a.ApplyConclusion(u10Reach(id, st, time.Now()))
				s := a.Snapshot()
				for _, d := range s.Segments {
					ids := map[tailcfg.NodeID]bool{}
					for _, c := range d.Candidates {
						if ids[c.ID] {
							t.Errorf("duplicate candidate %d in %s", c.ID, d.Prefix)
						}
						ids[c.ID] = true
					}
					if d.WinnerID != 0 && !ids[d.WinnerID] {
						t.Errorf("winner %d missing from candidates of %s", d.WinnerID, d.Prefix)
					}
					if d.CarrierID != 0 && !ids[d.CarrierID] && d.ChosenPrefix == d.Prefix {
						t.Errorf("carrier %d dangling in %s", d.CarrierID, d.Prefix)
					}
				}
			}
		}(g)
	}
	wg.Wait()
}

// Two ordered conclusions: later covers earlier; ledger shows the covered
// submission; final state is the later one.
func TestUID10_AdjudicatorLedgerSupersession(t *testing.T) {
	a, clock := u10NewEngine(t, u10Prefs())
	pfx := "10.9.0.0/24"
	a.ReplaceAdvertisements([]routecheck.Advertisement{u10Adv(11, pfx)})

	o1 := a.ApplyConclusion(u10Reach(11, peernode.Reachable, clock.now()))
	clock.add(time.Second)
	o2 := a.ApplyConclusion(u10Reach(11, peernode.Unreachable, clock.now()))
	if o2.SupersededSeq != o1.Seq {
		t.Fatalf("superseded seq = %d, want %d", o2.SupersededSeq, o1.Seq)
	}
	var found bool
	for _, e := range a.Ledger() {
		if e.Seq == o1.Seq && e.SupersededBy == o2.Seq {
			found = true
		}
	}
	if !found {
		t.Fatalf("ledger does not show seq %d covered by %d: %+v", o1.Seq, o2.Seq, a.Ledger())
	}
	if d := u10MustDecision(t, a.Snapshot(), pfx); d.WinnerID != 11 || d.Reason != routecheck.ReasonAllUnavailable {
		t.Fatalf("final decision winner=%d reason=%q, want later unreachable state", d.WinnerID, d.Reason)
	}
}

// Determinism: different insertion and conclusion arrival orders converge to
// the same decisions except timestamps/generation.
func TestUID10_AdjudicatorDeterminism(t *testing.T) {
	wide, narrow, other := "10.0.0.0/16", "10.0.1.0/24", "10.2.0.0/24"
	ads := []routecheck.Advertisement{
		u10Adv(10, wide), u10Adv(20, narrow), u10Adv(21, narrow), u10Adv(30, other),
	}
	concs := []routecheck.ReachConclusion{
		u10Reach(20, peernode.Unreachable, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)),
		u10Reach(21, peernode.Reachable, time.Date(2026, 6, 1, 0, 1, 0, 0, time.UTC)),
		u10Reach(10, peernode.Reachable, time.Date(2026, 6, 1, 0, 2, 0, 0, time.UTC)),
		u10Reach(30, peernode.Reachable, time.Date(2026, 6, 1, 0, 3, 0, 0, time.UTC)),
	}

	type result struct {
		lookups  map[string]u10CarrierView
		segments map[string]*routecheck.SegmentDecision
	}
	run := func(adOrder []int, cOrder []int) result {
		clock := u10NewClock()
		a := routecheck.NewAdjudicator(u10Prefs(), routecheck.WithClock(clock.now))
		orderedAds := make([]routecheck.Advertisement, 0, len(ads))
		for _, i := range adOrder {
			orderedAds = append(orderedAds, ads[i])
		}
		a.ReplaceAdvertisements(orderedAds)
		for _, i := range cOrder {
			a.ApplyConclusion(concs[i])
		}
		res := result{
			lookups:  map[string]u10CarrierView{},
			segments: map[string]*routecheck.SegmentDecision{},
		}
		for _, addr := range []string{"10.0.1.5", "10.0.2.7", "10.9.0.1"} {
			lk, ok := a.Snapshot().LookupAddr(netip.MustParseAddr(addr))
			if ok {
				res.lookups[addr] = u10CarrierView{lk.CarrierID, lk.ChosenPrefix.String(), lk.FellBack, lk.AllUnavailable}
			}
		}
		for p, d := range a.Snapshot().Segments {
			cp := *d
			cp.DecidedAt = time.Time{}
			cp.Generation = 0
			res.segments[p.String()] = &cp
		}
		return res
	}

	r1 := run([]int{0, 1, 2, 3}, []int{0, 1, 2, 3})
	r2 := run([]int{3, 1, 0, 2}, []int{3, 0, 2, 1})
	if diff := gcmp.Diff(r1.lookups, r2.lookups); diff != "" {
		t.Fatalf("lookup results differ with arrival order (-run1 +run2):\n%s", diff)
	}
	if diff := gcmp.Diff(r1.segments, r2.segments, u10CmpNetip); diff != "" {
		t.Fatalf("segment decisions differ with ordering (-run1 +run2):\n%s", diff)
	}

	r3 := run([]int{2, 3, 0, 1}, []int{1, 2, 3, 0})
	r4 := run([]int{1, 0, 3, 2}, []int{2, 1, 0, 3})
	if diff := gcmp.Diff(r3.segments, r4.segments, u10CmpNetip); diff != "" {
		t.Fatalf("segment decisions differ on second permutation:\n%s", diff)
	}
	if diff := gcmp.Diff(r1.segments, r3.segments, u10CmpNetip); diff != "" {
		t.Fatalf("segment decisions differ across all permutations:\n%s", diff)
	}
}

type u10CarrierView struct {
	Carrier        tailcfg.NodeID
	Chosen         string
	FellBack       bool
	AllUnavailable bool
}

// Adapter from tailcfg NodeViews and a routecheck Report.
func TestUID10_AdvertisementsFromPeersAndReport(t *testing.T) {
	peers := []tailcfg.NodeView{
		makeNode(21, withName("subnet21"), withRoutes(netip.MustParsePrefix("192.168.1.0/24"))),
		makeNode(22, withName("subnet22"), withRoutes(netip.MustParsePrefix("192.168.1.0/24"))),
		makeNode(23, withName("plain23")), // only self addresses
	}
	got := routecheck.AdvertisementsFromPeers(peers)
	if len(got) != 2 {
		t.Fatalf("advertisements = %d, want 2 (self addresses omitted): %+v", len(got), got)
	}

	// GroupRoutersByPrefix agrees on the advertised segment.
	grouped := routecheck.GroupRoutersByPrefix(peers)
	if len(grouped[netip.MustParsePrefix("192.168.1.0/24")]) != 2 {
		t.Fatalf("grouped candidates = %d, want 2", len(grouped))
	}

	a, clock := u10NewEngine(t, u10Prefs())
	a.ReplacePeers(peers)
	r := &routecheck.Report{
		Done: clock.now(),
		Reachable: routecheck.NodeSet{
			22: {ID: 22, Name: "subnet22"},
		},
	}
	a.ApplyReport(r)
	d := u10MustDecision(t, a.Snapshot(), "192.168.1.0/24")
	if d.WinnerID != 22 {
		t.Fatalf("report-driven winner = %d, want reachable 22", d.WinnerID)
	}
}

// Baseline compatibility: with a single advertiser per segment and no
// overlap, adjudication picks exactly today's node and the advertised prefix
// set matches GroupRoutersByPrefix. Accept-subnet-routes off adopts nothing.
func TestUID10_AdjudicateBaselineCompatibility(t *testing.T) {
	peers := []tailcfg.NodeView{
		makeNode(31, withName("r31"), withRoutes(netip.MustParsePrefix("172.16.0.0/16"))),
		makeNode(32, withName("r32"), withRoutes(netip.MustParsePrefix("172.17.0.0/16"))),
	}
	grouped := routecheck.GroupRoutersByPrefix(peers)

	a, _ := u10NewEngine(t, u10Prefs())
	a.ReplacePeers(peers)
	s := a.Snapshot()
	if len(s.Segments) != len(grouped) {
		t.Fatalf("segment count = %d, GroupRoutersByPrefix = %d", len(s.Segments), len(grouped))
	}
	for pfx, nodes := range grouped {
		d := s.Decision(pfx)
		if d == nil {
			t.Fatalf("missing decision for %s", pfx)
		}
		if len(nodes) != 1 {
			continue
		}
		if d.WinnerID != nodes[0].ID() || d.CarrierID != nodes[0].ID() {
			t.Fatalf("%s winner=%d carrier=%d, want baseline node %d",
				pfx, d.WinnerID, d.CarrierID, nodes[0].ID())
		}
		if d.Reason != routecheck.ReasonSoleCandidate {
			t.Fatalf("%s reason=%q, want sole-candidate", pfx, d.Reason)
		}
	}

	// Accept subnet routes off: no adopted segment and no alerts.
	off := u10Prefs()
	off.AcceptSubnetRoutes = false
	a2 := routecheck.NewAdjudicator(off)
	a2.ReplacePeers(peers)
	if len(a2.Snapshot().Segments) != 0 || len(a2.Snapshot().Alerts) != 0 {
		t.Fatalf("accept-off segments=%d alerts=%d, want 0/0",
			len(a2.Snapshot().Segments), len(a2.Snapshot().Alerts))
	}
}

func TestUID10_PreferencesFromIPN(t *testing.T) {
	p := &ipn.Prefs{RouteAll: false, ExitNodeID: tailcfg.StableNodeID("stable7")}
	got := routecheck.PreferencesFromIPN(p, true, 0)
	if got.AcceptSubnetRoutes || got.ExitNode != "stable7" || !got.ProbeAvailable {
		t.Fatalf("prefs mapping = %+v", got)
	}
	if got.ConclusionTTL != routecheck.DefaultConclusionTTL {
		t.Fatalf("default TTL = %s, want %s", got.ConclusionTTL, routecheck.DefaultConclusionTTL)
	}
}

// Audit output contains candidates, winner, reason and timestamp sections.
func TestUID10_SnapshotWriteAudit(t *testing.T) {
	a, clock := u10NewEngine(t, u10Prefs())
	a.ReplaceAdvertisements([]routecheck.Advertisement{u10Adv(11, "10.10.0.0/24"), u10Adv(22, "10.10.0.0/24")})
	a.ApplyConclusions(
		u10Reach(11, peernode.Unreachable, clock.now()),
		u10Reach(22, peernode.Unreachable, clock.now()),
	)

	var buf bytes.Buffer
	if err := a.Snapshot().WriteAudit(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"adjudication generation", "10.10.0.0/24", "WINNER", "backups", "all-routes-unavailable"} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Fatalf("audit output missing %q:\n%s", want, out)
		}
	}
}
