/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"strings"
	"testing"
)

// TestDatapathKeepsNoTrafficAccounting pins the shape the traffic rework
// depends on: tproxy.c must not carry per-packet byte carriers or a flow index
// for pass-through accounting. Observation lives in separate eBPF hooks
// (direct_stats.c), which are allowed only if they stay read-only over the
// flow state they observe.
func TestDatapathKeepsNoTrafficAccounting(t *testing.T) {
	raw, err := os.ReadFile("kern/tproxy.c")
	if err != nil {
		t.Fatalf("read kernel source: %v", err)
	}
	source := string(raw)
	for _, banned := range []string{
		"direct_traffic_map",
		"direct_reverse_map",
		"account_direct_traffic",
		"remember_direct_flow",
		"is_known_direct_flow",
		"counted_as_download",
	} {
		if strings.Contains(source, banned) {
			t.Fatalf("datapath still carries %q; pass-through accounting must stay out of tproxy.c", banned)
		}
	}
}

// TestDirectStatsObserverIsReadOnly pins the observer contract: it may read
// conn_state_map but must never write or delete it, so counting cannot change
// datapath verdicts or flow lifetimes.
func TestDirectStatsObserverIsReadOnly(t *testing.T) {
	raw, err := os.ReadFile("kern/direct_stats.c")
	if err != nil {
		t.Fatalf("read observer source: %v", err)
	}
	source := string(raw)
	for _, forbidden := range []string{
		"bpf_map_update_elem(&conn_state_map",
		"bpf_map_delete_elem(&conn_state_map",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("observer writes flow state via %q; it must stay read-only", forbidden)
		}
	}
	if !strings.Contains(source, "bpf_map_lookup_elem(&conn_state_map") {
		t.Fatal("observer must read conn_state_map to decide direct passthrough")
	}
}

// TestPerPacketCountersArePercpu pins the cacheline argument: the counters that
// fire per packet must not be a shared ARRAY, or every CPU contends for one
// line on the stateless-passthrough path.
func TestPerPacketCountersArePercpu(t *testing.T) {
	raw, err := os.ReadFile("kern/tproxy.c")
	if err != nil {
		t.Fatalf("read kernel source: %v", err)
	}
	source := string(raw)
	start := strings.Index(source, "bpf_stats_map SEC(\".maps\")")
	if start < 0 {
		t.Fatal("bpf_stats_map not found")
	}
	declaration := source[:start]
	blockStart := strings.LastIndex(declaration, "struct {")
	if blockStart < 0 {
		t.Fatal("bpf_stats_map declaration not found")
	}
	if !strings.Contains(declaration[blockStart:], "BPF_MAP_TYPE_PERCPU_ARRAY") {
		t.Fatal("bpf_stats_map must be a PERCPU array: per-packet increments cannot share one cacheline")
	}
}
