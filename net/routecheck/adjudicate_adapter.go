// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"net/netip"
	"slices"

	"tailscale.com/tailcfg"
)

// PeerAdOption configures [AdvertisementsFromPeers].
type PeerAdOption func(*peerAdConfig)

type peerAdConfig struct {
	sourceValidation []netip.Prefix
	service          []netip.Prefix
}

// WithPeerSourceValidationPrefixes tags extra prefixes that are only used for
// in-tunnel source validation and must not participate in fallback.
func WithPeerSourceValidationPrefixes(p ...netip.Prefix) PeerAdOption {
	return func(c *peerAdConfig) { c.sourceValidation = append(c.sourceValidation, p...) }
}

// WithPeerServicePrefixes tags Tailscale Services/VIP prefixes.
func WithPeerServicePrefixes(p ...netip.Prefix) PeerAdOption {
	return func(c *peerAdConfig) { c.service = append(c.service, p...) }
}

// AdvertisementsFromPeers converts netmap peers into [Advertisement] values.
//
// It applies exactly the existing routecheck rule from [GroupRoutersByPrefix]:
// a prefix that is one of the node's own Addresses is omitted, because
// routers never forward their own local addresses. Classification of service
// and source-validation prefixes is left to the [Adjudicator] unless explicit
// prefix sets are supplied here.
func AdvertisementsFromPeers(peers []tailcfg.NodeView, opts ...PeerAdOption) []Advertisement {
	var cfg peerAdConfig
	for _, o := range opts {
		o(&cfg)
	}

	var out []Advertisement
	for _, n := range peers {
		cand := Candidate{
			ID:       n.ID(),
			StableID: n.StableID(),
			Name:     n.Name(),
		}
		primary := n.PrimaryRoutes()
		for _, pfx := range routes(n) {
			purpose := PurposeAuto
			switch {
			case slices.Contains(cfg.sourceValidation, pfx):
				purpose = PurposeSourceValidation
			case slices.Contains(cfg.service, pfx):
				purpose = PurposeServiceAddress
			}
			out = append(out, Advertisement{
				Prefix:    pfx,
				Purpose:   purpose,
				Candidate: withPrimary(cand, primary, pfx),
			})
		}
	}
	return out
}

func withPrimary(c Candidate, primary interface {
	Len() int
	At(int) netip.Prefix
}, pfx netip.Prefix) Candidate {
	for i := 0; i < primary.Len(); i++ {
		if primary.At(i) == pfx {
			c.Primary = true
			break
		}
	}
	return c
}

// ReplacePeers replaces the advertised-segment set from netmap peers.
// Reachability state is preserved.
func (a *Adjudicator) ReplacePeers(peers []tailcfg.NodeView) UpdateOutcome {
	ads := AdvertisementsFromPeers(peers)
	return a.ReplaceAdvertisements(ads)
}

// SyncFromClient performs one incremental sync from an existing routecheck
// [Client]: current peers supply advertisements and the cached [Report], if
// any, supplies reachable conclusions.
//
// It is a convenience bridge; long-running callers can instead subscribe to
// netmap/report changes and call [Adjudicator.ReplacePeers] and
// [Adjudicator.ApplyReport] incrementally.
func (a *Adjudicator) SyncFromClient(c *Client) UpdateOutcome {
	if c == nil || c.nb == nil {
		return UpdateOutcome{}
	}
	ads := AdvertisementsFromPeers(c.nb.NodeBackend().Peers())
	routeOut := a.ReplaceAdvertisements(ads)
	if r := c.Report(); r != nil {
		reachOut := a.ApplyReport(r)
		routeOut.Recomputed = append(routeOut.Recomputed, reachOut.Recomputed...)
		routeOut.Updated = append(routeOut.Updated, reachOut.Updated...)
		routeOut.SelectionChanged = append(routeOut.SelectionChanged, reachOut.SelectionChanged...)
		if reachOut.Published {
			routeOut.Published = true
			routeOut.Generation = reachOut.Generation
		}
	}
	return routeOut
}

// AdjudicateOnce builds a one-off adjudication from the client's current
// netmap peers and cached reachability report using prefs.
//
// It does not change the client or any routing state. Callers that need
// incremental updates should retain an [Adjudicator] instead.
func (c *Client) AdjudicateOnce(prefs AdjudicationPrefs) *Snapshot {
	a := NewAdjudicator(prefs)
	a.SyncFromClient(c)
	return a.Snapshot()
}
