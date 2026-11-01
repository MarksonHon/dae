package control

import (
	"fmt"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/vishvananda/netlink"
)

// directStatsEnabled is the process-wide switch for direct-traffic observation.
// It is read whenever LAN hooks are staged, so it survives datapath reloads.
var directStatsEnabled atomic.Bool

// directStatsPriority must be lower than the tproxy LAN hook priority so the
// observer runs before tproxy can return TC_ACT_OK for direct passthrough.
const directStatsPriority = uint16(1)

const (
	directStatsKeyUpBytes uint32 = iota
	directStatsKeyUpPackets
	directStatsKeyDownBytes
	directStatsKeyDownPackets
)

type DirectStatsCounters struct {
	UpBytes     uint64
	UpPackets   uint64
	DownBytes   uint64
	DownPackets uint64
}

type directStatsLan struct {
	link   netlink.Link
	layer2 bool
}

// SetDirectStatsEnabled toggles direct-traffic observation at runtime.
func (c *ControlPlane) SetDirectStatsEnabled(enabled bool) error {
	directStatsEnabled.Store(enabled)
	if c == nil || c.core == nil {
		return nil
	}
	return c.core.applyDirectStatsSwitch(enabled)
}

// DirectStatsSnapshot returns counters summed across CPUs. It returns zeros
// when observation has never been loaded.
func (c *ControlPlane) DirectStatsSnapshot() (DirectStatsCounters, error) {
	if c == nil || c.core == nil {
		return DirectStatsCounters{}, nil
	}
	return c.core.readDirectStats()
}

func (c *controlPlaneCore) rememberDirectStatsLan(link netlink.Link, layer2 bool) {
	c.directStatsMu.Lock()
	defer c.directStatsMu.Unlock()
	if c.directStatsLans == nil {
		c.directStatsLans = make(map[string]directStatsLan)
	}
	c.directStatsLans[link.Attrs().Name] = directStatsLan{link: link, layer2: layer2}
}

// stageDirectStatsLan stages the observer hooks for a LAN link when the switch is on.
func (c *controlPlaneCore) stageDirectStatsLan(link netlink.Link, layer2 bool) error {
	c.rememberDirectStatsLan(link, layer2)
	if !directStatsEnabled.Load() {
		return nil
	}
	specs, err := c.directStatsHookSpecs(link, layer2)
	if err != nil {
		return err
	}
	for _, spec := range specs {
		if err := c.stageTCHook(spec); err != nil {
			return fmt.Errorf("install direct stats hook: %w", err)
		}
	}
	return nil
}

func (c *controlPlaneCore) applyDirectStatsSwitch(enabled bool) error {
	c.directStatsMu.Lock()
	lans := make([]directStatsLan, 0, len(c.directStatsLans))
	for _, lan := range c.directStatsLans {
		lans = append(lans, lan)
	}
	c.directStatsMu.Unlock()

	for _, lan := range lans {
		if enabled {
			specs, err := c.directStatsHookSpecs(lan.link, lan.layer2)
			if err != nil {
				return err
			}
			for _, spec := range specs {
				if err := c.stageTCHook(spec); err != nil {
					return fmt.Errorf("install direct stats hook: %w", err)
				}
			}
			continue
		}
		for _, direction := range []tcHookDirection{tcHookIngress, tcHookEgress} {
			key := tcHookKey{
				group: tcHookGroupKey{
					scope:     tcHookScopeHost,
					ifindex:   lan.link.Attrs().Index,
					direction: direction,
				},
				priority: directStatsPriority,
			}
			if err := c.removeTCHookKey(key); err != nil {
				return fmt.Errorf("remove direct stats hook: %w", err)
			}
		}
	}
	return nil
}

func (c *controlPlaneCore) directStatsHookSpecs(link netlink.Link, layer2 bool) ([]tcHookSpec, error) {
	coll, err := c.ensureDirectStatsCollection()
	if err != nil {
		return nil, err
	}
	ingressName := "direct_stats_lan_ingress_l3"
	egressName := "direct_stats_lan_egress_l3"
	if layer2 {
		ingressName = "direct_stats_lan_ingress_l2"
		egressName = "direct_stats_lan_egress_l2"
	}
	ingress := coll.Programs[ingressName]
	egress := coll.Programs[egressName]
	if ingress == nil || egress == nil {
		return nil, fmt.Errorf("direct stats programs missing from collection")
	}
	return []tcHookSpec{
		makeTCHookSpec(tcHookScopeHost, link, tcHookIngress, directStatsPriority, 0x2023, ingress, consts.AppName+"_"+ingressName, nil),
		makeTCHookSpec(tcHookScopeHost, link, tcHookEgress, directStatsPriority, 0x2023, egress, consts.AppName+"_"+egressName, nil),
	}, nil
}

// ensureDirectStatsCollection loads the observer object once per core. It
// reuses the live conn_state_map so the observer reads tproxy's flow state.
func (c *controlPlaneCore) ensureDirectStatsCollection() (*ebpf.Collection, error) {
	c.directStatsMu.Lock()
	defer c.directStatsMu.Unlock()
	if c.directStats != nil {
		return c.directStats, nil
	}
	bpf := c.bpf.Load()
	if bpf == nil || bpf.ConnStateMap == nil {
		return nil, fmt.Errorf("conn_state_map is unavailable")
	}
	info, err := bpf.ConnStateMap.Info()
	if err != nil {
		return nil, fmt.Errorf("query conn_state_map: %w", err)
	}
	spec, err := loadDirectstats()
	if err != nil {
		return nil, fmt.Errorf("load direct stats spec: %w", err)
	}
	connStateSpec := spec.Maps["conn_state_map"]
	if connStateSpec == nil {
		return nil, fmt.Errorf("direct stats spec has no conn_state_map")
	}
	connStateSpec.MaxEntries = info.MaxEntries
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{"conn_state_map": bpf.ConnStateMap},
	})
	if err != nil {
		return nil, fmt.Errorf("create direct stats collection: %w", err)
	}
	c.directStats = coll
	c.addDeferFunc(func() error {
		coll.Close()
		return nil
	})
	return coll, nil
}

func (c *controlPlaneCore) readDirectStats() (DirectStatsCounters, error) {
	c.directStatsMu.Lock()
	coll := c.directStats
	c.directStatsMu.Unlock()
	if coll == nil {
		return DirectStatsCounters{}, nil
	}
	m := coll.Maps["direct_stats_map"]
	if m == nil {
		return DirectStatsCounters{}, fmt.Errorf("direct_stats_map is missing")
	}
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		return DirectStatsCounters{}, err
	}
	sum := func(key uint32) (uint64, error) {
		values := make([]uint64, ncpu)
		if err := m.Lookup(key, &values); err != nil {
			return 0, err
		}
		var total uint64
		for _, v := range values {
			total += v
		}
		return total, nil
	}
	var out DirectStatsCounters
	dst := []struct {
		key uint32
		p   *uint64
	}{
		{directStatsKeyUpBytes, &out.UpBytes},
		{directStatsKeyUpPackets, &out.UpPackets},
		{directStatsKeyDownBytes, &out.DownBytes},
		{directStatsKeyDownPackets, &out.DownPackets},
	}
	for _, d := range dst {
		v, err := sum(d.key)
		if err != nil {
			return DirectStatsCounters{}, fmt.Errorf("read direct stats key %d: %w", d.key, err)
		}
		*d.p = v
	}
	return out, nil
}
