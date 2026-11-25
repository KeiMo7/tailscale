// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"time"

	"tailscale.com/ipn"
)

// DefaultConclusionTTL is the suggested freshness window for reachability
// conclusions used in adjudication. Callers may choose their own.
const DefaultConclusionTTL = 5 * time.Minute

// PreferencesFromIPN maps the existing route acceptance preferences in
// ipn.Prefs to [AdjudicationPrefs].
//
// probeAvailable reports whether routecheck probing is currently enabled and
// healthy; callers typically derive it from [IsEnabled] plus probe health.
// A zero ttl means [DefaultConclusionTTL].
func PreferencesFromIPN(p *ipn.Prefs, probeAvailable bool, ttl time.Duration) AdjudicationPrefs {
	ap := AdjudicationPrefs{
		AcceptSubnetRoutes: p != nil && p.RouteAll,
		ProbeAvailable:     probeAvailable,
		ConclusionTTL:      ttl,
	}
	if ttl == 0 {
		ap.ConclusionTTL = DefaultConclusionTTL
	}
	if p != nil {
		ap.ExitNode = p.ExitNodeID
	}
	return ap
}
