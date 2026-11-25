// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"cmp"
	"iter"
	"net/netip"
	"slices"
	"time"

	"tailscale.com/net/routecheck/peernode"
	"tailscale.com/tailcfg"
)

// This file implements the local route adjudication layer.
//
// It combines three inputs that already exist elsewhere in the client:
//
//   - the local route acceptance preferences (see [AdjudicationPrefs],
//     typically derived from ipn.Prefs),
//   - the subnets that each node advertises (see [Advertisement],
//     typically derived from tailcfg.NodeView.AllowedIPs/PrimaryRoutes),
//   - the reachability conclusions produced by routecheck probing
//     (see [ReachConclusion] and [Report]).
//
// The output is an immutable, atomically published [Snapshot] that gives,
// for every accepted segment, the ordered candidates, the unique winner,
// the ordered backups, the reason for the decision and its timestamp.
// Nested segments resolve to a wider covering segment when every carrier
// of the more specific segment is freshly known to be unreachable.
//
// The packet path never adjudicates and never takes the adjudication lock:
// it loads one published [Snapshot] and calls [Snapshot.LookupAddr].
// A snapshot is immutable and stays valid for as long as the caller holds it,
// so a reader that loaded the previous snapshot mid-update is unaffected.

// Reason explains why a [SegmentDecision] selected its carrier.
type Reason string

const (
	// ReasonSoleCandidate is used when exactly one node advertises a segment.
	ReasonSoleCandidate Reason = "sole-candidate" // 唯一候选

	// ReasonReachableFirst is used when positive reachability conclusions
	// decide the ordering between multiple candidates.
	ReasonReachableFirst Reason = "reachable-first" // 可达优先

	// ReasonFallback is used when every carrier of the most specific segment
	// is unreachable and traffic moves up to a wider covering segment.
	ReasonFallback Reason = "fallback" // 回退

	// ReasonHold is used when an incumbent winner is retained through
	// unknown/stale reachability data: unknown is never treated as unavailable.
	ReasonHold Reason = "hold" // 保持

	// ReasonFlapIgnored is used when a dampened node's rapid recovery is
	// not allowed to preempt the incumbent, to avoid repeated flip-flopping.
	ReasonFlapIgnored Reason = "flap-ignored" // 抖动忽略

	// ReasonStableOrder is used when reachability does not distinguish the
	// candidates and the deterministic stable node order decides.
	ReasonStableOrder Reason = "stable-order"

	// ReasonAllUnavailable is used when every tier that could carry a segment
	// is freshly known to be unreachable. Packets still enter the tunnel via
	// the baseline ("today's") carrier; an [Alert] and counters are emitted.
	ReasonAllUnavailable Reason = "all-unavailable"

	// ReasonProbeUnavailable is used when the reachability probe source is
	// switched off, unsupported or errored: reachability conclusions are
	// ignored and the decision matches today's control-plane/baseline choice.
	ReasonProbeUnavailable Reason = "probe-unavailable"

	// ReasonExitNode is used for default routes (/0), which are carried only
	// by the explicitly selected exit node, never by fallback adjudication.
	ReasonExitNode Reason = "exit-node"
)

// RoutePurpose classifies an advertised prefix so that prefixes which must
// not participate in subnet fallback can be excluded or handled specially.
type RoutePurpose string

const (
	// PurposeAuto asks the adjudicator to classify the prefix using the
	// configured self/service/source-validation prefix sets and well-known
	// addresses.
	PurposeAuto RoutePurpose = ""

	// PurposeSubnet is an ordinary accepted subnet route.
	PurposeSubnet RoutePurpose = "subnet"

	// PurposeExit is a default route (0.0.0.0/0 or ::/0).
	// It is only carried by the selected exit node.
	PurposeExit RoutePurpose = "exit"

	// PurposeSelfAddress is one of the local node's own addresses.
	// It never participates in fallback.
	PurposeSelfAddress RoutePurpose = "self-address"

	// PurposeServiceAddress is a Tailscale Services/VIP address.
	// It never participates in fallback.
	PurposeServiceAddress RoutePurpose = "service-address"

	// PurposeSourceValidation is an extra prefix that is only installed so
	// that inbound packets can pass in-tunnel source validation.
	// It must never influence outbound selection or fallback.
	PurposeSourceValidation RoutePurpose = "source-validation"
)

// Participates reports whether p is a segment that the adjudicator rules on
// for outbound selection. Self, service and source-validation prefixes are
// only recorded as [Snapshot.Ignored] audit entries.
func (p RoutePurpose) Participates() bool {
	return p == PurposeSubnet || p == PurposeExit
}

// Candidate identifies a node that advertises a prefix.
type Candidate struct {
	// ID is the numeric node ID. It is the final stable ordering key,
	// matching [Node.Compare].
	ID tailcfg.NodeID `json:"id"`

	// StableID is the control-plane stable node ID, used to match prefs
	// such as the selected exit node.
	StableID tailcfg.StableNodeID `json:"stableID,omitempty"`

	// Name is the node's FQDN, for audit output.
	Name string `json:"name,omitempty"`

	// Primary reports whether the control plane currently designates this
	// node as the primary router for the prefix ([tailcfg.NodeView.PrimaryRoutes]).
	// It represents "today's choice" and is used as the first stable
	// tie-break when reachability does not distinguish candidates.
	Primary bool `json:"primary,omitempty"`
}

// Advertisement is one node advertising one prefix.
type Advertisement struct {
	// Prefix is the advertised network segment.
	Prefix netip.Prefix `json:"prefix"`

	// Candidate is the advertising node.
	Candidate Candidate `json:"candidate"`

	// Purpose optionally overrides automatic classification.
	Purpose RoutePurpose `json:"purpose,omitempty"`
}

// ReachConclusion is one reachability conclusion for a node.
//
// A zero At means "at processing time". Conclusions are keyed by Node;
// delivering another conclusion for the same node covers the previous one.
type ReachConclusion struct {
	// Node is the node the conclusion is about.
	Node tailcfg.NodeID `json:"node"`

	// Reachability is the concluded state.
	Reachability peernode.Reachability `json:"reachability"`

	// At is when the conclusion was produced. It participates in TTL
	// expiry and flap tracking. Zero means the adjudicator's current time.
	At time.Time `json:"at,omitempty"`

	// Source optionally identifies the probe/report source, for audit.
	Source string `json:"source,omitempty"`

	// Suspicious marks a conclusion whose provenance or freshness is not
	// trusted. It is handled exactly like an expired conclusion: unknown,
	// with the timeliness flag set.
	Suspicious bool `json:"suspicious,omitempty"`
}

// AdjudicationPrefs are the local preferences that bound adjudication.
// They are typically derived from [tailscale.com/ipn.Prefs].
type AdjudicationPrefs struct {
	// AcceptSubnetRoutes mirrors ipn.Prefs.RouteAll: whether subnets
	// advertised by other nodes are accepted at all. When false, no subnet
	// segment is adjudicated and no fallback or related alert is produced.
	// Default routes are not governed by this flag; see ExitNode.
	AcceptSubnetRoutes bool `json:"acceptSubnetRoutes"`

	// ExitNode is ipn.Prefs.ExitNodeID: the only node allowed to carry
	// default routes.
	ExitNode tailcfg.StableNodeID `json:"exitNode,omitempty"`

	// ProbeAvailable reports whether reachability probing is currently
	// available (enabled, supported by the platform and not in an error
	// state). When false, all reachability data is ignored and decisions
	// match today's baseline result. Missing data while probing is available
	// stays Unknown and never by itself triggers fallback.
	ProbeAvailable bool `json:"probeAvailable"`

	// ConclusionTTL is how long a reachability conclusion stays fresh.
	// Zero means conclusions never expire.
	ConclusionTTL time.Duration `json:"conclusionTTL,omitempty"`
}

// FlapPolicy configures reachability flap damping.
//
// Once a node has made Threshold Reachable<->Unreachable transitions within
// Window, it is considered dampened for Cooldown after its last transition.
// A dampened node's recovery is not allowed to preempt a healthy incumbent,
// which prevents rapid flip-flopping. Zero fields are replaced by defaults.
type FlapPolicy struct {
	// Threshold is the number of transitions that arms damping.
	// Defaults to 3.
	Threshold int `json:"threshold,omitempty"`

	// Window is the history window for counting transitions.
	// Defaults to 2 minutes.
	Window time.Duration `json:"window,omitempty"`

	// Cooldown is how long preemption stays blocked after the last
	// transition. Defaults to 30 seconds.
	Cooldown time.Duration `json:"cooldown,omitempty"`
}

func (p FlapPolicy) withDefaults() FlapPolicy {
	if p.Threshold <= 0 {
		p.Threshold = 3
	}
	if p.Window <= 0 {
		p.Window = 2 * time.Minute
	}
	if p.Cooldown <= 0 {
		p.Cooldown = 30 * time.Second
	}
	return p
}

// CandidateAssessment is one candidate as seen by a segment decision.
type CandidateAssessment struct {
	Candidate

	// Reachability is the normalized state (expired/suspicious conclusions
	// become [peernode.Unknown]).
	Reachability peernode.Reachability `json:"reachability"`

	// Stale reports that the conclusion was expired or otherwise not fresh.
	Stale bool `json:"stale,omitempty"`

	// Suspicious reports an untrusted conclusion source.
	Suspicious bool `json:"suspicious,omitempty"`

	// Dampened reports that flap damping is currently active for this node.
	Dampened bool `json:"dampened,omitempty"`

	// Available reports whether the node may carry traffic: it is true for
	// Reachable and Unknown, false only for a fresh Unreachable conclusion.
	Available bool `json:"available"`

	// Eligible reports whether the candidate is allowed to win. It is false
	// for non-selected advertisers of default routes.
	Eligible bool `json:"eligible"`

	// Order is the 0-based canonical position of the candidate.
	Order int `json:"order"`

	// Selected marks the unique tier winner.
	Selected bool `json:"selected,omitempty"`
}

// SegmentDecision is the auditable adjudication of one advertised segment.
type SegmentDecision struct {
	// Prefix is the advertised segment this decision rules on.
	Prefix netip.Prefix `json:"prefix"`

	// Purpose is the classified route purpose.
	Purpose RoutePurpose `json:"purpose"`

	// Candidates are in canonical, deterministic order:
	// reachable first, then unknown, then unreachable, then stable node order.
	// The winner is the selected entry; BackupIDs holds the ordered backups.
	Candidates []CandidateAssessment `json:"candidates"`

	// WinnerID is the unique elected candidate for this specific tier.
	// It is zero only when the segment has no eligible exit node.
	WinnerID tailcfg.NodeID `json:"winnerID,omitempty"`

	// BackupIDs are the ordered backups within this tier.
	BackupIDs []tailcfg.NodeID `json:"backupIDs,omitempty"`

	// Reason is the tier-level decision reason. When fallback actually moves
	// traffic to a wider tier, Reason becomes [ReasonFallback].
	Reason Reason `json:"reason"`

	// CarrierID is the node that should receive outbound packets for
	// addresses inside Prefix. It equals WinnerID unless nested fallback
	// selected a wider tier's winner. When every tier is unavailable it is
	// still set to the baseline winner so packets enter the tunnel as today.
	CarrierID tailcfg.NodeID `json:"carrierID,omitempty"`

	// ChosenPrefix is the tier whose winner is the CarrierID.
	// It equals Prefix without fallback.
	ChosenPrefix netip.Prefix `json:"chosenPrefix"`

	// FallbackPath lists the tiers examined, most specific first, ending at
	// ChosenPrefix when fallback succeeded.
	FallbackPath []netip.Prefix `json:"fallbackPath,omitempty"`

	// AllUnavailable reports that no covering tier has an available carrier.
	AllUnavailable bool `json:"allUnavailable,omitempty"`

	// DecidedAt is the conclusion timestamp.
	DecidedAt time.Time `json:"decidedAt"`

	// Generation is the snapshot generation this decision was published in.
	Generation uint64 `json:"generation,omitempty"`
}

// Winner returns the selected candidate assessment, or nil if there is none.
func (d *SegmentDecision) Winner() *CandidateAssessment {
	if d == nil {
		return nil
	}
	for i := range d.Candidates {
		if d.Candidates[i].ID == d.WinnerID && d.Candidates[i].Selected {
			return &d.Candidates[i]
		}
	}
	for i := range d.Candidates {
		if d.Candidates[i].ID == d.WinnerID {
			return &d.Candidates[i]
		}
	}
	return nil
}

// Carrier returns the assessment of the outbound carrier, or nil.
func (d *SegmentDecision) Carrier() *CandidateAssessment {
	if d == nil || d.CarrierID == 0 {
		return nil
	}
	for i := range d.Candidates {
		if d.Candidates[i].ID == d.CarrierID {
			return &d.Candidates[i]
		}
	}
	return nil
}

// IgnoredAdvertisement records a prefix that was intentionally excluded
// from outbound adjudication.
type IgnoredAdvertisement struct {
	Prefix  netip.Prefix   `json:"prefix"`
	NodeID  tailcfg.NodeID `json:"nodeID"`
	Purpose RoutePurpose   `json:"purpose"`
	Reason  string         `json:"reason"`
}

// AlertKind identifies an observable adjudication alert.
type AlertKind string

const (
	// AlertAllRoutesUnavailable is raised when every covering tier's
	// carriers are unreachable and traffic continues through the baseline.
	AlertAllRoutesUnavailable AlertKind = "all-routes-unavailable"
)

// Alert is an observable warning produced by adjudication.
type Alert struct {
	Kind    AlertKind        `json:"kind"`
	Prefix  netip.Prefix     `json:"prefix"`
	Message string           `json:"message"`
	Since   time.Time        `json:"since"`
	NodeIDs []tailcfg.NodeID `json:"nodeIDs,omitempty"`
}

// Snapshot is the immutable, atomically published adjudication result.
//
// A Snapshot must be treated as read-only. The [Adjudicator] publishes a
// fresh pointer on every semantic change; a caller that loaded an older
// pointer keeps a valid, self-consistent result for as long as it holds it.
type Snapshot struct {
	// Generation is the monotonically increasing publication number.
	Generation uint64 `json:"generation"`

	// DecidedAt is the publication timestamp.
	DecidedAt time.Time `json:"decidedAt"`

	// Prefs is the preference set this snapshot was produced with.
	Prefs AdjudicationPrefs `json:"prefs"`

	// Segments maps every accepted, adjudicated prefix to its decision.
	// Treat the map and its decisions as immutable.
	Segments map[netip.Prefix]*SegmentDecision `json:"segments"`

	// Ignored records self/service/source-validation prefixes and other
	// advertisements that do not participate.
	Ignored []IgnoredAdvertisement `json:"ignored,omitempty"`

	// Alerts are the currently active alerts (e.g. all tiers unavailable).
	Alerts []Alert `json:"alerts,omitempty"`

	// table is the copy-on-write longest-prefix index used by the lock-free
	// packet path. It is immutable for this snapshot generation.
	table *routeTrie
}

// Decision returns the exact-prefix decision, or nil.
func (s *Snapshot) Decision(p netip.Prefix) *SegmentDecision {
	if s == nil {
		return nil
	}
	return s.Segments[p]
}

// Lookup is the result of a packet-path longest-prefix lookup.
type Lookup struct {
	// Addr is the looked-up destination address.
	Addr netip.Addr

	// Segment is the longest accepted segment covering Addr.
	Segment *SegmentDecision

	// CarrierID is the node that should receive the packet.
	CarrierID tailcfg.NodeID

	// ChosenPrefix is the tier whose winner carries it.
	ChosenPrefix netip.Prefix

	// FellBack reports that ChosenPrefix is wider than Segment.Prefix.
	FellBack bool

	// AllUnavailable reports that every tier was unavailable and the
	// baseline tunnel carrier is being used.
	AllUnavailable bool
}

// LookupAddr performs a lock-free longest-prefix lookup for addr against the
// published snapshot and returns the outbound carrier conclusion.
// It never adjudicates.
func (s *Snapshot) LookupAddr(addr netip.Addr) (Lookup, bool) {
	if s == nil || s.table == nil {
		return Lookup{}, false
	}
	addr = addr.Unmap()
	d, ok := s.table.lookup(addr)
	if !ok || d == nil || d.CarrierID == 0 {
		return Lookup{}, false
	}
	return Lookup{
		Addr:           addr,
		Segment:        d,
		CarrierID:      d.CarrierID,
		ChosenPrefix:   d.ChosenPrefix,
		FellBack:       d.ChosenPrefix.IsValid() && d.ChosenPrefix != d.Prefix,
		AllUnavailable: d.AllUnavailable,
	}, true
}

// SortedSegments iterates decisions in deterministic prefix order
// ([netip.Prefix.Compare]).
func (s *Snapshot) SortedSegments() iter.Seq2[netip.Prefix, *SegmentDecision] {
	return func(yield func(netip.Prefix, *SegmentDecision) bool) {
		if s == nil {
			return
		}
		pfxs := mapsKeys(s.Segments)
		slices.SortFunc(pfxs, netip.Prefix.Compare)
		for _, p := range pfxs {
			if !yield(p, s.Segments[p]) {
				return
			}
		}
	}
}

func mapsKeys[V any](m map[netip.Prefix]V) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// prefixSpecificityLess orders prefixes from more specific to less specific:
// longer mask first, then [netip.Prefix.Compare] for determinism.
func prefixSpecificityDesc(a, b netip.Prefix) int {
	if c := cmp.Compare(b.Bits(), a.Bits()); c != 0 {
		return c
	}
	return netip.Prefix.Compare(a, b)
}

// prefixSpecificityAsc orders prefixes from less specific (wider) to more
// specific. It is the recomputation order so ancestor tiers are fresh first.
func prefixSpecificityAsc(a, b netip.Prefix) int {
	if c := cmp.Compare(a.Bits(), b.Bits()); c != 0 {
		return c
	}
	return netip.Prefix.Compare(a, b)
}

// prefixCovers reports whether outer contains the whole inner prefix.
// Both prefixes are expected to be masked (canonical); advertisements are
// masked on insertion.
func prefixCovers(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// stateRank orders reachability: reachable, unknown, unreachable.
func stateRank(r peernode.Reachability) int {
	switch r {
	case peernode.Reachable:
		return 0
	case peernode.Unknown:
		return 1
	case peernode.Unreachable:
		return 2
	default:
		return 1
	}
}

// compareAssessment is the canonical stable ordering of candidates:
// reachability first, then stable node order ([Node.Compare]: node ID,
// then stable ID/name as final tie-breaks). The control-plane primary
// designation is exposed as metadata but never perturbs this order.
func compareAssessment(a, b CandidateAssessment) int {
	if c := cmp.Compare(stateRank(a.Reachability), stateRank(b.Reachability)); c != 0 {
		return c
	}
	if c := cmp.Compare(a.ID, b.ID); c != 0 {
		return c
	}
	if c := cmp.Compare(a.StableID, b.StableID); c != 0 {
		return c
	}
	return cmp.Compare(a.Name, b.Name)
}

// semanticEqual reports whether two decisions carry the same adjudication
// outcome, ignoring the conclusion timestamp and publication generation.
func semanticEqual(a, b *SegmentDecision) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Prefix != b.Prefix || a.Purpose != b.Purpose || a.Reason != b.Reason ||
		a.WinnerID != b.WinnerID || a.CarrierID != b.CarrierID ||
		a.ChosenPrefix != b.ChosenPrefix || a.AllUnavailable != b.AllUnavailable {
		return false
	}
	if !slices.Equal(a.BackupIDs, b.BackupIDs) || !slices.Equal(a.FallbackPath, b.FallbackPath) {
		return false
	}
	if len(a.Candidates) != len(b.Candidates) {
		return false
	}
	for i := range a.Candidates {
		x, y := a.Candidates[i], b.Candidates[i]
		if x.ID != y.ID || x.Reachability != y.Reachability ||
			x.Stale != y.Stale || x.Suspicious != y.Suspicious ||
			x.Dampened != y.Dampened || x.Available != y.Available ||
			x.Eligible != y.Eligible ||
			x.Order != y.Order || x.Selected != y.Selected || x.Primary != y.Primary {
			return false
		}
	}
	return true
}
