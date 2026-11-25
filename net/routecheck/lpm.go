// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import "net/netip"

// routeTrie is an immutable longest-prefix-match index of published
// [SegmentDecision] values.
//
// Updates are copy-on-write along at most the prefix length's number of nodes,
// so the work is proportional to the changed prefixes rather than to the whole
// routing table. Once published, a routeTrie is never mutated: packet-path
// readers may hold and query any older root without locks while the
// [Adjudicator] publishes a new one.
type routeTrie struct {
	root *trieNode
}

type trieNode struct {
	kid [2]*trieNode
	val *SegmentDecision // decision installed at this prefix depth, or nil
}

func (n *trieNode) clone() *trieNode {
	if n == nil {
		return &trieNode{}
	}
	c := *n
	return &c
}

// upsert returns a new trie with p bound to v. The receiver is not modified.
func (t *routeTrie) upsert(p netip.Prefix, v *SegmentDecision) *routeTrie {
	p = p.Masked()
	var oldRoot *trieNode
	if t != nil {
		oldRoot = t.root
	}
	root := oldRoot.clone()
	cur := root
	b := p.Addr().AsSlice()
	for i := 0; i < p.Bits(); i++ {
		bit := prefixBit(b, i)
		child := cur.kid[bit].clone()
		cur.kid[bit] = child
		cur = child
	}
	cur.val = v
	return &routeTrie{root: root}
}

// deletePrefix returns a new trie with p removed. The receiver is not modified.
func (t *routeTrie) deletePrefix(p netip.Prefix) *routeTrie {
	if t == nil || t.root == nil {
		return t
	}
	p = p.Masked()
	root := t.root.clone()
	cur := root
	b := p.Addr().AsSlice()
	for i := 0; i < p.Bits(); i++ {
		bit := prefixBit(b, i)
		if cur.kid[bit] == nil {
			return t // absent: nothing to remove
		}
		child := cur.kid[bit].clone()
		cur.kid[bit] = child
		cur = child
	}
	cur.val = nil
	return &routeTrie{root: root}
}

// lookup returns the decision installed at the longest prefix covering addr.
func (t *routeTrie) lookup(addr netip.Addr) (*SegmentDecision, bool) {
	if t == nil || t.root == nil {
		return nil, false
	}
	addr = addr.Unmap()
	b := addr.AsSlice()
	bits := addr.BitLen()

	cur := t.root
	var best *SegmentDecision
	if cur.val != nil {
		best = cur.val // /0 default route
	}
	for i := 0; i < bits && cur != nil; i++ {
		bit := prefixBit(b, i)
		next := cur.kid[bit]
		if next == nil {
			break
		}
		cur = next
		if cur.val != nil {
			best = cur.val
		}
	}
	if best == nil {
		return nil, false
	}
	return best, true
}

func prefixBit(bytes []byte, i int) byte {
	return (bytes[i/8] >> (7 - uint(i%8))) & 1
}
