// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"text/tabwriter"

	"tailscale.com/tailcfg"
)

// WriteAudit writes a deterministic, human-readable per-segment adjudication
// report: candidates in order, the unique winner, backups, reason, fallback
// tier, carrier and conclusion timestamp.
//
// Output ordering is deterministic; only timestamps vary between identical
// runs.
func (s *Snapshot) WriteAudit(w io.Writer) error {
	if s == nil {
		_, err := io.WriteString(w, "(no adjudication snapshot)\n")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "# adjudication generation=%d at=%s acceptSubnetRoutes=%v probeAvailable=%v\n",
		s.Generation, s.DecidedAt.Format("2006-01-02T15:04:05.000Z07:00"),
		s.Prefs.AcceptSubnetRoutes, s.Prefs.ProbeAvailable)

	for pfx, d := range s.SortedSegments() {
		fmt.Fprintf(tw, "\nsegment %s (%s) reason=%s decidedAt=%s\n",
			pfx, d.Purpose, d.Reason, d.DecidedAt.Format("2006-01-02T15:04:05.000Z07:00"))
		if d.ChosenPrefix.IsValid() && d.ChosenPrefix != pfx {
			fmt.Fprintf(tw, "  fallback: path=%v chosen=%s carrier=%d allUnavailable=%v\n",
				prefixStrings(d.FallbackPath), d.ChosenPrefix, d.CarrierID, d.AllUnavailable)
		} else if d.AllUnavailable {
			fmt.Fprintf(tw, "  all tiers unavailable: baseline carrier=%d stays in tunnel\n", d.CarrierID)
		} else if d.CarrierID != 0 && d.CarrierID != d.WinnerID {
			fmt.Fprintf(tw, "  carrier=%d via %s\n", d.CarrierID, d.ChosenPrefix)
		}
		for _, c := range d.Candidates {
			marks := make([]string, 0, 4)
			if c.Selected {
				marks = append(marks, "WINNER")
			}
			if !c.Eligible {
				marks = append(marks, "ineligible")
			}
			if c.Primary {
				marks = append(marks, "control-primary")
			}
			if c.Dampened {
				marks = append(marks, "flap-dampened")
			}
			if c.Stale {
				marks = append(marks, "stale")
			}
			if c.Suspicious {
				marks = append(marks, "suspicious")
			}
			if !c.Available {
				marks = append(marks, "UNAVAILABLE")
			}
			label := strings.Join(marks, ",")
			if label != "" {
				label = " [" + label + "]"
			}
			fmt.Fprintf(tw, "  #%d node=%d stable=%q name=%q reach=%s%s\n",
				c.Order, c.ID, c.StableID, c.Name, c.Reachability, label)
		}
		if len(d.BackupIDs) > 0 {
			fmt.Fprintf(tw, "  backups: %s\n", formatNodeIDs(d.BackupIDs))
		}
	}

	if len(s.Alerts) > 0 {
		fmt.Fprintln(tw, "\nalerts:")
		for _, a := range s.Alerts {
			fmt.Fprintf(tw, "  - %s %s: %s nodes=%s\n", a.Kind, a.Prefix, a.Message, formatNodeIDs(a.NodeIDs))
		}
	}
	if len(s.Ignored) > 0 {
		fmt.Fprintln(tw, "\nignored (no outbound fallback):")
		for _, ig := range s.Ignored {
			fmt.Fprintf(tw, "  - %s node=%d purpose=%s: %s\n", ig.Prefix, ig.NodeID, ig.Purpose, ig.Reason)
		}
	}
	return tw.Flush()
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

func formatNodeIDs(ids []tailcfg.NodeID) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.FormatInt(int64(id), 10)
	}
	return "[" + strings.Join(parts, " ") + "]"
}
