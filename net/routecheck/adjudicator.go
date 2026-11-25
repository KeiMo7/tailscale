// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/net/routecheck/peernode"
	"tailscale.com/tailcfg"
	"tailscale.com/util/clientmetric"
)

// Adjudicator counters. They supplement the in-process [Stats], which tests
// can read without cross-test counter interference.
var (
	metricAdjudicateRecompute       = clientmetric.NewCounter("routecheck_adjudicate_recompute")
	metricAdjudicatePublication     = clientmetric.NewCounter("routecheck_adjudicate_publication")
	metricAdjudicateSelectionChange = clientmetric.NewCounter("routecheck_adjudicate_selection_change")
	metricAdjudicateFallback        = clientmetric.NewCounter("routecheck_adjudicate_fallback")
	metricAdjudicateAllUnavailable  = clientmetric.NewCounter("routecheck_adjudicate_all_unavailable")
	metricAdjudicateFlapIgnored     = clientmetric.NewCounter("routecheck_adjudicate_flap_ignored")
	metricAdjudicateDuplicate       = clientmetric.NewCounter("routecheck_adjudicate_duplicate")
	metricAdjudicateSuperseded      = clientmetric.NewCounter("routecheck_adjudicate_superseded")
)

// Stats is a point-in-time copy of adjudicator counters.
type Stats struct {
	// Recomputations counts segment re-adjudications. Incremental updates
	// only pay for affected segments plus their nested dependents.
	Recomputations uint64

	// Publications counts fresh atomic snapshots stored.
	Publications uint64

	// UpdatedSegments counts segment conclusions whose content changed.
	UpdatedSegments uint64

	// SelectionChanges counts winner/carrier changes.
	SelectionChanges uint64

	// Fallbacks counts fallback resolutions performed during adjudication.
	Fallbacks uint64

	// AllUnavailable counts all-unavailable resolutions performed.
	AllUnavailable uint64

	// FlapIgnored counts preemptions blocked by flap damping.
	FlapIgnored uint64

	// DuplicateUpdates counts identical conclusions delivered again.
	DuplicateUpdates uint64

	// SupersededUpdates counts earlier conclusions covered by later ones.
	SupersededUpdates uint64
}

// Ledger status values.
const (
	LedgerApplied   = "applied"
	LedgerDuplicate = "duplicate"
)

// LedgerEntry is one audited input submission. When a later conclusion for
// the same node covers an earlier one, the earlier entry keeps its sequence
// number and is marked SupersededBy the newer sequence.
type LedgerEntry struct {
	Seq          uint64    `json:"seq"`
	At           time.Time `json:"at"`
	Kind         string    `json:"kind"`
	Key          string    `json:"key"`
	Summary      string    `json:"summary,omitempty"`
	Status       string    `json:"status"`
	SupersededBy uint64    `json:"supersededBy,omitempty"`
}

// UpdateOutcome reports what one submission did.
type UpdateOutcome struct {
	// Seq is the ledger sequence assigned to the submission.
	Seq uint64

	// Generation is the published snapshot generation after the update.
	Generation uint64

	// Duplicate reports that the exact same conclusion was already present
	// and the update was a no-op: no recomputation and no publication.
	Duplicate bool

	// Published reports that a fresh snapshot was stored.
	Published bool

	// Recomputed lists the prefixes that were re-adjudicated because they
	// were affected by the update.
	Recomputed []netip.Prefix

	// Updated lists prefixes whose decision content changed.
	Updated []netip.Prefix

	// SelectionChanged lists prefixes whose winner or carrier changed.
	SelectionChanged []netip.Prefix

	// SupersededSeq is the sequence of the earlier conclusion covered by
	// this submission, when one existed.
	SupersededSeq uint64
}

type advKey struct {
	pfx netip.Prefix
	id  int64 // tailcfg.NodeID, kept comparable
}

type advRecord struct {
	adv     Advertisement
	purpose RoutePurpose
}

type storedReach struct {
	rc         ReachConclusion
	receivedAt time.Time
}

type flapState struct {
	lastDecisive peernode.Reachability // last Reachable/Unreachable raw state
	seenDecisive bool
	transitions  []time.Time
}

// Adjudicator incrementally combines preferences, advertisements and
// reachability conclusions into atomically published [Snapshot] results.
//
// All mutation is serialized by mu. The published snapshot is read with a
// single atomic pointer load and needs no lock on the packet path.
type Adjudicator struct {
	mu     sync.Mutex
	pub    atomic.Pointer[Snapshot]
	clock  func() time.Time
	logger func(format string, a ...any)

	prefs AdjudicationPrefs
	flap  FlapPolicy

	selfPrefixes map[netip.Prefix]struct{}
	svcPrefixes  map[netip.Prefix]struct{}
	srcPrefixes  map[netip.Prefix]struct{}

	advs  map[advKey]advRecord
	reach map[tailcfg.NodeID]storedReach
	flaps map[tailcfg.NodeID]*flapState

	gen    uint64
	seq    uint64
	stats  Stats
	ledger []LedgerEntry
}

// Option configures a new [Adjudicator].
type Option func(*Adjudicator)

// WithClock uses now as the current time source (deterministic tests).
func WithClock(now func() time.Time) Option {
	return func(a *Adjudicator) { a.clock = now }
}

// WithLogger sends diagnostic logs through logf.
func WithLogger(logf func(format string, a ...any)) Option {
	return func(a *Adjudicator) { a.logger = logf }
}

// WithFlapPolicy sets the flap damping policy.
func WithFlapPolicy(p FlapPolicy) Option {
	return func(a *Adjudicator) { a.flap = p.withDefaults() }
}

// WithSelfPrefixes marks prefixes as local self addresses that never
// participate in outbound fallback.
func WithSelfPrefixes(p ...netip.Prefix) Option {
	return func(a *Adjudicator) {
		for _, x := range p {
			a.selfPrefixes[x] = struct{}{}
		}
	}
}

// WithServicePrefixes marks prefixes as Tailscale Services/VIP addresses.
func WithServicePrefixes(p ...netip.Prefix) Option {
	return func(a *Adjudicator) {
		for _, x := range p {
			a.svcPrefixes[x] = struct{}{}
		}
	}
}

// WithSourceValidationPrefixes marks prefixes as in-tunnel source-validation
// extras that must never influence outbound selection.
func WithSourceValidationPrefixes(p ...netip.Prefix) Option {
	return func(a *Adjudicator) {
		for _, x := range p {
			a.srcPrefixes[x] = struct{}{}
		}
	}
}

// maxLedgerEntries bounds the audit ledger memory.
const maxLedgerEntries = 256

// NewAdjudicator returns an adjudicator using prefs.
// The initial published snapshot is empty but valid.
func NewAdjudicator(prefs AdjudicationPrefs, opts ...Option) *Adjudicator {
	a := &Adjudicator{
		clock:        time.Now,
		prefs:        prefs,
		flap:         FlapPolicy{}.withDefaults(),
		selfPrefixes: map[netip.Prefix]struct{}{},
		svcPrefixes:  map[netip.Prefix]struct{}{},
		srcPrefixes:  map[netip.Prefix]struct{}{},
		advs:         map[advKey]advRecord{},
		reach:        map[tailcfg.NodeID]storedReach{},
		flaps:        map[tailcfg.NodeID]*flapState{},
	}
	for _, o := range opts {
		o(a)
	}
	s := a.emptySnapshotLocked()
	a.pub.Store(s)
	return a
}

func (a *Adjudicator) emptySnapshotLocked() *Snapshot {
	return &Snapshot{
		Generation: a.gen,
		DecidedAt:  a.now(),
		Prefs:      a.prefs,
		Segments:   map[netip.Prefix]*SegmentDecision{},
		table:      &routeTrie{},
	}
}

func (a *Adjudicator) now() time.Time {
	if a.clock != nil {
		return a.clock()
	}
	return time.Now()
}

// logf emits a diagnostic line when a logger was configured.
func (a *Adjudicator) logf(format string, args ...any) {
	if a.logger != nil {
		a.logger(format, args...)
	}
}

func advKeyOf(p netip.Prefix, id tailcfg.NodeID) advKey {
	return advKey{pfx: p, id: int64(id)}
}

// Snapshot returns the latest atomically published result.
// It never returns nil after [NewAdjudicator].
func (a *Adjudicator) Snapshot() *Snapshot {
	return a.pub.Load()
}

// Stats returns a copy of the cumulative counters.
func (a *Adjudicator) Stats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stats
}

// Ledger returns a copy of the audit ledger in submission order.
func (a *Adjudicator) Ledger() []LedgerEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.ledger)
}

// SetPreferences replaces the route acceptance preferences and re-adjudicates
// every segment whose effective result can depend on them.
func (a *Adjudicator) SetPreferences(p AdjudicationPrefs) UpdateOutcome {
	a.mu.Lock()
	defer a.mu.Unlock()

	changed := p != a.prefs
	a.prefs = p
	dirty := map[netip.Prefix]struct{}{}
	if changed {
		// Global gate/probe/TTL/exit changes can affect every segment.
		for k := range a.advs {
			dirty[k.pfx] = struct{}{}
		}
	}
	out := a.recomputeLocked(dirty, nil)
	a.appendLedgerLocked("preferences", "prefs",
		fmt.Sprintf("accept=%v exit=%q probe=%v ttl=%s",
			p.AcceptSubnetRoutes, p.ExitNode, p.ProbeAvailable, p.ConclusionTTL),
		LedgerApplied)
	return out
}

// ReplaceAdvertisements replaces the whole advertised-segment set and
// re-adjudicates only the union of old and new affected prefixes.
func (a *Adjudicator) ReplaceAdvertisements(advs []Advertisement) UpdateOutcome {
	a.mu.Lock()
	defer a.mu.Unlock()

	dirty := map[netip.Prefix]struct{}{}
	for k := range a.advs {
		dirty[k.pfx] = struct{}{}
	}
	clear(a.advs)
	for _, adv := range advs {
		a.insertAdvertisementLocked(adv, dirty)
	}
	return a.recomputeLocked(dirty, nil)
}

// UpsertAdvertisement inserts or replaces one node's advertisement.
func (a *Adjudicator) UpsertAdvertisement(adv Advertisement) UpdateOutcome {
	a.mu.Lock()
	defer a.mu.Unlock()

	dirty := map[netip.Prefix]struct{}{}
	a.insertAdvertisementLocked(adv, dirty)
	return a.recomputeLocked(dirty, nil)
}

func (a *Adjudicator) insertAdvertisementLocked(adv Advertisement, dirty map[netip.Prefix]struct{}) {
	if !adv.Prefix.IsValid() || adv.Candidate.ID == 0 {
		return
	}
	adv.Prefix = adv.Prefix.Masked()
	purpose, _ := a.classifyLocked(adv)
	k := advKeyOf(adv.Prefix, adv.Candidate.ID)
	a.advs[k] = advRecord{adv: adv, purpose: purpose}
	dirty[adv.Prefix] = struct{}{}
}

// RemoveAdvertisement removes one node's advertisement of prefix.
func (a *Adjudicator) RemoveAdvertisement(prefix netip.Prefix, id tailcfg.NodeID) UpdateOutcome {
	a.mu.Lock()
	defer a.mu.Unlock()

	prefix = prefix.Masked()
	delete(a.advs, advKeyOf(prefix, id))
	dirty := map[netip.Prefix]struct{}{prefix: {}}
	return a.recomputeLocked(dirty, nil)
}

// RemoveNode removes every advertisement of id plus its reachability/flap
// state. The published result never references a removed node.
func (a *Adjudicator) RemoveNode(id tailcfg.NodeID) UpdateOutcome {
	a.mu.Lock()
	defer a.mu.Unlock()

	dirty := map[netip.Prefix]struct{}{}
	for k := range a.advs {
		if tailcfg.NodeID(k.id) == id {
			delete(a.advs, k)
			dirty[k.pfx] = struct{}{}
		}
	}
	delete(a.reach, id)
	delete(a.flaps, id)
	return a.recomputeLocked(dirty, nil)
}

// RevokePrefix removes every advertisement of prefix (the segment is revoked
// by all nodes).
func (a *Adjudicator) RevokePrefix(prefix netip.Prefix) UpdateOutcome {
	a.mu.Lock()
	defer a.mu.Unlock()

	prefix = prefix.Masked()
	for k := range a.advs {
		if k.pfx == prefix {
			delete(a.advs, k)
		}
	}
	dirty := map[netip.Prefix]struct{}{prefix: {}}
	return a.recomputeLocked(dirty, nil)
}

// ApplyConclusion delivers one reachability conclusion.
// Identical redelivery is a no-op; a later conclusion for the same node
// covers the previous one and the ledger records the supersession.
func (a *Adjudicator) ApplyConclusion(rc ReachConclusion) UpdateOutcome {
	return a.ApplyConclusions(rc)
}

// ApplyConclusions delivers a batch of conclusions in order.
func (a *Adjudicator) ApplyConclusions(rcs ...ReachConclusion) UpdateOutcome {
	a.mu.Lock()
	defer a.mu.Unlock()

	var last UpdateOutcome
	for _, rc := range rcs {
		last = a.applyConclusionLocked(rc)
	}
	return last
}

func (a *Adjudicator) applyConclusionLocked(rc ReachConclusion) UpdateOutcome {
	key := fmt.Sprintf("reach:%d", rc.Node)

	// Exact redelivery is a no-op. Compare the semantic input fields and
	// do not stamp rc.At first, so zero-time heartbeats stay idempotent.
	if old, ok := a.reach[rc.Node]; ok && old.rc.Reachability == rc.Reachability &&
		old.rc.At.Equal(rc.At) && old.rc.Suspicious == rc.Suspicious {
		a.stats.DuplicateUpdates++
		metricAdjudicateDuplicate.Add(1)
		seq := a.appendLedgerLocked("reachability", key,
			rc.Reachability.String()+" (duplicate ignored)", LedgerDuplicate)
		return UpdateOutcome{Seq: seq, Generation: a.gen, Duplicate: true}
	}

	superseded := uint64(0)
	now := a.now()
	a.updateFlapLocked(rc.Node, rc.Reachability, conclusionTime(rc, now))
	a.reach[rc.Node] = storedReach{rc: rc, receivedAt: now}

	seq := a.appendLedgerLocked("reachability", key,
		fmt.Sprintf("%s at=%s suspicious=%v", rc.Reachability, conclusionTime(rc, now).Format(time.RFC3339Nano), rc.Suspicious),
		LedgerApplied)
	if oldSeq := a.markSupersededLocked(key, seq); oldSeq != 0 {
		superseded = oldSeq
		a.stats.SupersededUpdates++
		metricAdjudicateSuperseded.Add(1)
	}

	dirty := map[netip.Prefix]struct{}{}
	for k := range a.advs {
		if tailcfg.NodeID(k.id) == rc.Node {
			dirty[k.pfx] = struct{}{}
		}
	}
	out := a.recomputeLocked(dirty, &reasonHint{unknown: rc.Reachability == peernode.Unknown || rc.Suspicious})
	out.Seq = seq
	out.SupersededSeq = superseded
	return out
}

func conclusionTime(rc ReachConclusion, now time.Time) time.Time {
	if !rc.At.IsZero() {
		return rc.At
	}
	return now
}

// ApplyReport merges the reachable nodes of a routecheck [Report].
//
// A [Report] currently positively tracks reachable nodes only; nodes absent
// from it are left untouched (and therefore Unknown if never concluded),
// never marked unreachable.
func (a *Adjudicator) ApplyReport(r *Report) UpdateOutcome {
	if r == nil {
		return UpdateOutcome{}
	}
	rcs := make([]ReachConclusion, 0, len(r.Reachable))
	for _, n := range r.Reachable {
		rcs = append(rcs, ReachConclusion{
			Node:         n.ID,
			Reachability: peernode.Reachable,
			At:           r.Done,
			Source:       "routecheck.Report",
		})
	}
	slices.SortFunc(rcs, func(x, y ReachConclusion) int { return cmp.Compare(x.Node, y.Node) })
	return a.ApplyConclusions(rcs...)
}

// Reevaluate recomputes segments whose TTL expiry or flap cooldown status may
// have changed with the clock. It is safe to call periodically.
func (a *Adjudicator) Reevaluate() UpdateOutcome {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.now()
	dirty := map[netip.Prefix]struct{}{}
	for id := range a.reach {
		if a.conclusionExpiringLocked(id, now) || a.flapCooldownElapsedLocked(id, now) {
			for k := range a.advs {
				if tailcfg.NodeID(k.id) == id {
					dirty[k.pfx] = struct{}{}
				}
			}
		}
	}
	return a.recomputeLocked(dirty, &reasonHint{timeBased: true})
}

func (a *Adjudicator) conclusionExpiringLocked(id tailcfg.NodeID, now time.Time) bool {
	if a.prefs.ConclusionTTL <= 0 || !a.prefs.ProbeAvailable {
		return false
	}
	sr, ok := a.reach[id]
	if !ok || sr.rc.At.IsZero() {
		return false
	}
	// Once the conclusion is at/over its TTL, normalization changes to
	// Unknown. Repeated reevaluation is an idempotent semantic no-op.
	return now.Sub(sr.rc.At) >= a.prefs.ConclusionTTL
}

func (a *Adjudicator) flapCooldownElapsedLocked(id tailcfg.NodeID, now time.Time) bool {
	fs := a.flaps[id]
	if fs == nil || len(fs.transitions) == 0 {
		return false
	}
	last := fs.transitions[len(fs.transitions)-1]
	// Cooldown boundary: while still dampened nothing time-based changed;
	// at/after expiry the node may be allowed to preempt again.
	return len(fs.transitions) >= a.flap.Threshold &&
		now.Sub(last) >= a.flap.Cooldown
}

func (a *Adjudicator) updateFlapLocked(id tailcfg.NodeID, state peernode.Reachability, at time.Time) {
	if state != peernode.Reachable && state != peernode.Unreachable {
		return
	}
	fs := a.flaps[id]
	if fs == nil {
		fs = &flapState{}
		a.flaps[id] = fs
	}
	if fs.seenDecisive && fs.lastDecisive != state {
		fs.transitions = append(fs.transitions, at)
	}
	fs.lastDecisive = state
	fs.seenDecisive = true
}

// dampenedLocked reports whether preemption by id is currently blocked.
func (a *Adjudicator) dampenedLocked(id tailcfg.NodeID, now time.Time) bool {
	fs := a.flaps[id]
	if fs == nil {
		return false
	}
	cutoff := now.Add(-a.flap.Window)
	fs.transitions = slices.DeleteFunc(fs.transitions, func(t time.Time) bool { return t.Before(cutoff) })
	if len(fs.transitions) < a.flap.Threshold {
		return false
	}
	last := fs.transitions[len(fs.transitions)-1]
	return now.Sub(last) < a.flap.Cooldown
}

func (a *Adjudicator) normalizeReachLocked(id tailcfg.NodeID, now time.Time) (peernode.Reachability, bool, bool) {
	if !a.prefs.ProbeAvailable {
		return peernode.Unknown, false, false
	}
	sr, ok := a.reach[id]
	if !ok {
		return peernode.Unknown, false, false
	}
	if sr.rc.Suspicious {
		return peernode.Unknown, true, true
	}
	if a.prefs.ConclusionTTL > 0 && !sr.rc.At.IsZero() && now.Sub(sr.rc.At) > a.prefs.ConclusionTTL {
		return peernode.Unknown, true, false
	}
	return sr.rc.Reachability, false, false
}

func (a *Adjudicator) classifyLocked(adv Advertisement) (RoutePurpose, string) {
	pfx := adv.Prefix
	if adv.Purpose != PurposeAuto {
		return adv.Purpose, "explicit purpose"
	}
	if _, ok := a.selfPrefixes[pfx]; ok {
		return PurposeSelfAddress, "local node address"
	}
	if _, ok := a.svcPrefixes[pfx]; ok {
		return PurposeServiceAddress, "tailscale service/VIP address"
	}
	if _, ok := a.srcPrefixes[pfx]; ok {
		return PurposeSourceValidation, "in-tunnel source validation prefix"
	}
	if isWellKnownServicePrefix(pfx) {
		return PurposeServiceAddress, "well-known tailscale service address"
	}
	if isExitPrefix(pfx) {
		return PurposeExit, "default route carried by selected exit node only"
	}
	return PurposeSubnet, ""
}

func isExitPrefix(p netip.Prefix) bool {
	return p.Bits() == 0
}

func isWellKnownServicePrefix(p netip.Prefix) bool {
	if !p.IsValid() || p.Bits() != p.Addr().BitLen() {
		return false // only exact /32 or /128 service IPs
	}
	addr := p.Addr().Unmap()
	return addr == netip.MustParseAddr("100.100.100.100") ||
		addr == netip.MustParseAddr("fd7a:115c:a1e0::53")
}

type reasonHint struct {
	unknown   bool
	timeBased bool
}

// recomputeLocked re-adjudicates every prefix in seed plus nested prefixes
// that could fall back through them, publishes an atomic snapshot and
// returns the precise outcome.
func (a *Adjudicator) recomputeLocked(seed map[netip.Prefix]struct{}, hint *reasonHint) UpdateOutcome {
	now := a.now()
	old := a.pub.Load()
	out := UpdateOutcome{Generation: a.gen}

	if len(seed) == 0 {
		return out
	}

	// All currently known prefixes, for nested-dependant expansion.
	known := map[netip.Prefix]struct{}{}
	for k := range a.advs {
		known[k.pfx] = struct{}{}
	}

	dirty := map[netip.Prefix]struct{}{}
	for s := range seed {
		// A seeded prefix itself is dirty even if its last advertisement
		// was just removed, so its stale decision gets deleted.
		dirty[s] = struct{}{}
		for p := range known {
			if prefixCovers(s, p) {
				dirty[p] = struct{}{}
			}
		}
	}

	// Recompute widest tier first so that nested decisions resolve fallback
	// against freshly rebuilt ancestor decisions.
	ordered := slices.SortedFunc(maps.Keys(dirty), prefixSpecificityAsc)
	out.Recomputed = slices.Clone(ordered)

	final := map[netip.Prefix]*SegmentDecision{}
	if old != nil {
		final = maps.Clone(old.Segments)
	}

	var updated, selectionChanged []netip.Prefix
	for _, pfx := range ordered {
		a.stats.Recomputations++
		metricAdjudicateRecompute.Add(1)

		var oldD *SegmentDecision
		if old != nil {
			oldD = old.Segments[pfx]
		}
		d := a.buildSegmentLocked(pfx, now, oldD, hint)
		if d == nil {
			if _, existed := final[pfx]; existed {
				delete(final, pfx)
				updated = append(updated, pfx)
			}
			continue
		}
		a.resolveCarrierLocked(d, final, now)
		d.Generation = a.gen + 1 // prospective generation; ignored by semanticEqual

		if oldD != nil && semanticEqual(oldD, d) {
			// Nothing semantic changed: keep the prior pointer and its
			// original conclusion timestamp.
			final[pfx] = oldD
			continue
		}

		final[pfx] = d
		updated = append(updated, pfx)
		a.stats.UpdatedSegments++
		if oldD == nil || oldD.WinnerID != d.WinnerID || oldD.CarrierID != d.CarrierID ||
			oldD.ChosenPrefix != d.ChosenPrefix || oldD.AllUnavailable != d.AllUnavailable {
			selectionChanged = append(selectionChanged, pfx)
			a.stats.SelectionChanges++
			metricAdjudicateSelectionChange.Add(1)
		}
	}

	// Refresh alerts: retain alerts for untouched prefixes, rebuild dirty ones
	// while preserving the original onset time of a continuing alert.
	var alerts []Alert
	oldAlertSince := map[netip.Prefix]time.Time{}
	if old != nil {
		for _, al := range old.Alerts {
			if _, isDirty := dirty[al.Prefix]; !isDirty {
				alerts = append(alerts, al)
			} else {
				oldAlertSince[al.Prefix] = al.Since
			}
		}
	}
	for _, pfx := range ordered {
		d := final[pfx]
		if d != nil && d.AllUnavailable {
			since := now
			if t, ok := oldAlertSince[pfx]; ok && !t.IsZero() {
				since = t
			}
			alerts = append(alerts, Alert{
				Kind:    AlertAllRoutesUnavailable,
				Prefix:  pfx,
				Since:   since,
				NodeIDs: unavailableIDs(d),
				Message: fmt.Sprintf("all carriers of %s are unreachable; continuing via tunnel baseline", pfx),
			})
		}
	}
	slices.SortFunc(alerts, func(x, y Alert) int { return netip.Prefix.Compare(x.Prefix, y.Prefix) })

	ignored := a.buildIgnoredLocked()

	prefsChanged := old == nil || old.Prefs != a.prefs
	if len(updated) == 0 && !prefsChanged && old != nil &&
		slices.EqualFunc(old.Ignored, ignored, ignoredEqual) &&
		len(old.Alerts) == len(alerts) {
		// No externally visible change: do not publish.
		return out
	}

	a.gen++
	// Incrementally update the LPM index only for actually changed segments;
	// untouched prefixes keep using the prior immutable trie nodes.
	table := &routeTrie{}
	if old != nil && old.table != nil {
		table = old.table
	}
	for _, pfx := range updated {
		if d := final[pfx]; d != nil {
			d.Generation = a.gen
			table = table.upsert(pfx, d)
		} else {
			table = table.deletePrefix(pfx)
		}
	}

	snap := &Snapshot{
		Generation: a.gen,
		DecidedAt:  now,
		Prefs:      a.prefs,
		Segments:   final,
		Ignored:    ignored,
		Alerts:     alerts,
		table:      table,
	}
	a.pub.Store(snap)
	a.stats.Publications++
	metricAdjudicatePublication.Add(1)

	out.Published = true
	out.Generation = a.gen
	out.Updated = updated
	out.SelectionChanged = selectionChanged
	return out
}

func ignoredEqual(a, b IgnoredAdvertisement) bool {
	return a == b
}

func unavailableIDs(d *SegmentDecision) []tailcfg.NodeID {
	var ids []tailcfg.NodeID
	for _, c := range d.Candidates {
		if !c.Available {
			ids = append(ids, c.ID)
		}
	}
	return ids
}

// recordsForPrefixLocked returns the prefix's advertisement records in a
// stable (node ID) order independent of map iteration.
func (a *Adjudicator) recordsForPrefixLocked(pfx netip.Prefix) []advRecord {
	var recs []advRecord
	for k, r := range a.advs {
		if k.pfx == pfx {
			recs = append(recs, r)
		}
	}
	slices.SortFunc(recs, func(x, y advRecord) int {
		return compareCandidateKey(x.adv.Candidate, y.adv.Candidate)
	})
	return recs
}

func compareCandidateKey(x, y Candidate) int {
	if c := cmp.Compare(x.ID, y.ID); c != 0 {
		return c
	}
	if c := cmp.Compare(x.StableID, y.StableID); c != 0 {
		return c
	}
	return cmp.Compare(x.Name, y.Name)
}

func (a *Adjudicator) buildIgnoredLocked() []IgnoredAdvertisement {
	var out []IgnoredAdvertisement
	for _, r := range a.advs {
		if r.purpose.Participates() {
			continue
		}
		reason := "excluded from outbound fallback"
		if _, why := a.classifyLocked(r.adv); why != "" {
			reason = why
		}
		if r.purpose == PurposeSubnet && !a.prefs.AcceptSubnetRoutes {
			reason = "accept subnet routes is disabled"
		}
		out = append(out, IgnoredAdvertisement{
			Prefix:  r.adv.Prefix,
			NodeID:  r.adv.Candidate.ID,
			Purpose: r.purpose,
			Reason:  reason,
		})
	}
	if !a.prefs.AcceptSubnetRoutes {
		// Subnet records participate by classification but are not adopted.
		for _, r := range a.advs {
			if r.purpose == PurposeSubnet {
				out = append(out, IgnoredAdvertisement{
					Prefix:  r.adv.Prefix,
					NodeID:  r.adv.Candidate.ID,
					Purpose: PurposeSubnet,
					Reason:  "accept subnet routes is disabled",
				})
			}
		}
	}
	slices.SortFunc(out, func(x, y IgnoredAdvertisement) int {
		if c := netip.Prefix.Compare(x.Prefix, y.Prefix); c != 0 {
			return c
		}
		return cmp.Compare(x.NodeID, y.NodeID)
	})
	return slices.CompactFunc(out, func(x, y IgnoredAdvertisement) bool {
		return x.Prefix == y.Prefix && x.NodeID == y.NodeID && x.Purpose == y.Purpose
	})
}

func (a *Adjudicator) buildSegmentLocked(pfx netip.Prefix, now time.Time, old *SegmentDecision, hint *reasonHint) *SegmentDecision {
	recs := a.recordsForPrefixLocked(pfx)
	if len(recs) == 0 {
		return nil
	}
	purpose := recs[0].purpose
	if !purpose.Participates() {
		return nil
	}
	if purpose == PurposeSubnet && !a.prefs.AcceptSubnetRoutes {
		return nil
	}

	if purpose == PurposeExit {
		return a.buildExitLocked(pfx, now, recs)
	}

	cas := make([]CandidateAssessment, 0, len(recs))
	for _, r := range recs {
		state, stale, suspicious := a.normalizeReachLocked(r.adv.Candidate.ID, now)
		damp := a.dampenedLocked(r.adv.Candidate.ID, now)
		cas = append(cas, CandidateAssessment{
			Candidate:    r.adv.Candidate,
			Reachability: state,
			Stale:        stale,
			Suspicious:   suspicious,
			Dampened:     damp,
			Available:    state != peernode.Unreachable,
			Eligible:     true,
		})
	}
	slices.SortFunc(cas, compareAssessment)
	for i := range cas {
		cas[i].Order = i
	}

	winnerIdx := 0
	blockedFlap := false
	if old != nil && old.WinnerID != 0 && cas[0].ID != old.WinnerID && cas[0].Dampened {
		if idx := indexOfCandidate(cas, old.WinnerID); idx >= 0 && cas[idx].Available {
			winnerIdx = idx
			blockedFlap = true
			a.stats.FlapIgnored++
			metricAdjudicateFlapIgnored.Add(1)
			a.logf("routecheck: flap-dampened node %d recovery ignored for %s, keeping %d",
				cas[0].ID, pfx, old.WinnerID)
		}
	}
	cas[winnerIdx].Selected = true
	winner := cas[winnerIdx]

	backups := make([]tailcfg.NodeID, 0, len(cas)-1)
	for i := range cas {
		if i == winnerIdx {
			continue
		}
		backups = append(backups, cas[i].ID)
	}

	reason := a.reasonForLocked(winner, cas, old, blockedFlap, hint)

	return &SegmentDecision{
		Prefix:     pfx,
		Purpose:    PurposeSubnet,
		Candidates: cas,
		WinnerID:   winner.ID,
		BackupIDs:  backups,
		Reason:     reason,
		DecidedAt:  now,
	}
}

func (a *Adjudicator) reasonForLocked(winner CandidateAssessment, cas []CandidateAssessment, old *SegmentDecision, blockedFlap bool, hint *reasonHint) Reason {
	switch {
	case blockedFlap:
		return ReasonFlapIgnored
	case !winner.Available:
		return ReasonAllUnavailable
	case len(cas) == 1:
		return ReasonSoleCandidate
	case old != nil && old.WinnerID == winner.ID && winner.Reachability == peernode.Unknown &&
		(hint != nil && (hint.unknown || hint.timeBased)):
		return ReasonHold
	case a.prefs.ProbeAvailable && winner.Reachability == peernode.Reachable &&
		slices.ContainsFunc(cas, func(c CandidateAssessment) bool { return stateRank(c.Reachability) > stateRank(peernode.Reachable) }):
		return ReasonReachableFirst
	case !a.prefs.ProbeAvailable:
		return ReasonProbeUnavailable
	default:
		return ReasonStableOrder
	}
}

func (a *Adjudicator) buildExitLocked(pfx netip.Prefix, now time.Time, recs []advRecord) *SegmentDecision {
	cas := make([]CandidateAssessment, 0, len(recs))
	var selected tailcfg.NodeID
	for _, r := range recs {
		id := r.adv.Candidate.ID
		state, stale, suspicious := a.normalizeReachLocked(id, now)
		eligible := a.prefs.ExitNode != "" && r.adv.Candidate.StableID == a.prefs.ExitNode
		c := CandidateAssessment{
			Candidate:    r.adv.Candidate,
			Reachability: state,
			Stale:        stale,
			Suspicious:   suspicious,
			Dampened:     a.dampenedLocked(id, now),
			Available:    state != peernode.Unreachable,
			Eligible:     eligible,
		}
		if eligible {
			c.Selected = true
			selected = id
		}
		cas = append(cas, c)
	}
	slices.SortFunc(cas, func(x, y CandidateAssessment) int {
		if x.Eligible != y.Eligible {
			if x.Eligible {
				return -1
			}
			return 1
		}
		return compareAssessment(x, y)
	})
	for i := range cas {
		cas[i].Order = i
	}
	d := &SegmentDecision{
		Prefix:     pfx,
		Purpose:    PurposeExit,
		Candidates: cas,
		Reason:     ReasonExitNode,
		DecidedAt:  now,
	}
	if selected != 0 {
		d.WinnerID = selected
		d.CarrierID = selected
		d.ChosenPrefix = pfx
	}
	return d
}

// resolveCarrierLocked applies nested fallback: when every candidate of this
// tier is freshly unreachable, walk wider covering subnet segments until one
// has an available winner. Exit segments are never fallback targets.
func (a *Adjudicator) resolveCarrierLocked(d *SegmentDecision, all map[netip.Prefix]*SegmentDecision, now time.Time) {
	if d.Purpose == PurposeExit {
		return // carrier already set to the selected exit node, if any
	}
	winner := d.Winner()
	if winner != nil && winner.Available {
		d.CarrierID = d.WinnerID
		d.ChosenPrefix = d.Prefix
		return
	}

	// Every candidate at this tier is unreachable (or there is no winner).
	d.FallbackPath = []netip.Prefix{d.Prefix}

	var supers []netip.Prefix
	for p := range all {
		if p == d.Prefix || p.Bits() == 0 {
			continue
		}
		// A prefix p covers the whole segment d when p is at most as
		// specific and contains d's (masked) network address.
		if prefixCovers(p, d.Prefix) {
			supers = append(supers, p)
		}
	}
	slices.SortFunc(supers, prefixSpecificityDesc)

	for _, sp := range supers {
		sd := all[sp]
		if sd == nil || sd.Purpose != PurposeSubnet || sd.WinnerID == 0 {
			d.FallbackPath = append(d.FallbackPath, sp)
			continue
		}
		w := sd.Winner()
		d.FallbackPath = append(d.FallbackPath, sp)
		if w != nil && w.Available {
			d.CarrierID = sd.WinnerID
			d.ChosenPrefix = sp
			d.Reason = ReasonFallback
			a.stats.Fallbacks++
			metricAdjudicateFallback.Add(1)
			a.logf("routecheck: %s carriers unavailable, falling back to %s via node %d",
				d.Prefix, sp, sd.WinnerID)
			return
		}
	}

	// No usable tier anywhere. Preserve today's tunnel behavior via the
	// stable baseline winner and raise an observable alert/count.
	d.CarrierID = d.WinnerID
	d.ChosenPrefix = d.Prefix
	d.AllUnavailable = true
	d.Reason = ReasonAllUnavailable
	a.stats.AllUnavailable++
	metricAdjudicateAllUnavailable.Add(1)
	a.logf("routecheck: all covering tiers for %s unavailable; keeping tunnel baseline node %d",
		d.Prefix, d.WinnerID)
}

func indexOfCandidate(cas []CandidateAssessment, id tailcfg.NodeID) int {
	for i := range cas {
		if cas[i].ID == id {
			return i
		}
	}
	return -1
}

func (a *Adjudicator) appendLedgerLocked(kind, key, summary, status string) uint64 {
	a.seq++
	e := LedgerEntry{
		Seq:     a.seq,
		At:      a.now(),
		Kind:    kind,
		Key:     key,
		Summary: summary,
		Status:  status,
	}
	a.ledger = append(a.ledger, e)
	if len(a.ledger) > maxLedgerEntries {
		a.ledger = slices.Delete(a.ledger, 0, len(a.ledger)-maxLedgerEntries)
	}
	return a.seq
}

// supersedeLastAppliedLocked marks the most recent applied ledger entry for
// key as covered by a new submission and returns its sequence number.
// markSupersededLocked marks the most recent earlier applied ledger entry
// for key as covered by newSeq and returns its sequence number.
func (a *Adjudicator) markSupersededLocked(key string, newSeq uint64) uint64 {
	for i := len(a.ledger) - 1; i >= 0; i-- {
		e := &a.ledger[i]
		if e.Seq == newSeq {
			continue
		}
		if e.Key == key && e.SupersededBy == 0 && e.Status != LedgerDuplicate {
			e.SupersededBy = newSeq
			return e.Seq
		}
	}
	return 0
}
