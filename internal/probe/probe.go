package probe

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/markpash/flowlat/internal/clsact"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang probe ../../bpf/probe.c -- -O2 -g -Wall -Werror -Wno-address-of-packed-member

type probe struct {
	iface      netlink.Link
	handle     *netlink.Handle
	qdisc      *clsact.ClsAct
	filters    []*netlink.BpfFilter
	bpfObjects *probeObjects
}

// Run runs the probe on the given interface.
func Run(ctx context.Context, iface netlink.Link, smac net.HardwareAddr) error {
	probe, err := newProbe(iface)
	if err != nil {
		return err
	}
	defer probe.Close()

	smacMap := probe.bpfObjects.Smac
	for i := 0; i < 6; i++ {
		err = smacMap.Put(uint32(i), smac[i])
		if err != nil {
			return err
		}
	}

	pipe := probe.bpfObjects.Pipe
	rd, err := perf.NewReader(pipe, 10)
	if err != nil {
		return err
	}
	defer rd.Close()

	c := make(chan []byte)
	go func() {
		for {
			event, err := rd.Read()
			if err != nil {
				fmt.Println(err)
				continue
			}
			c <- event.RawSample
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return probe.Close()
		case event := <-c:
			fmt.Printf("%v\n", event)
		}
	}
}

func (p *probe) Close() error {
	if err := p.handle.QdiscDel(p.qdisc); err != nil {
		return err
	}

	if err := p.bpfObjects.Close(); err != nil {
		return err
	}

	p.handle.Delete()
	return nil
}

func newProbe(iface netlink.Link) (*probe, error) {
	if err := setRlimit(); err != nil {
		return nil, err
	}

	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}

	probe := probe{
		iface:  iface,
		handle: handle,
	}

	if err := probe.loadObjects(); err != nil {
		return nil, err
	}

	if err := probe.createQdisc(); err != nil {
		return nil, err
	}

	if err := probe.createFilters(); err != nil {
		return nil, err
	}

	return &probe, nil
}

func (p *probe) createQdisc() error {
	p.qdisc = clsact.NewClsAct(&netlink.QdiscAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	})

	if err := p.handle.QdiscAdd(p.qdisc); err != nil {
		return err
	}
	return nil
}

func (p *probe) createFilters() error {
	addFilter := func(attrs netlink.FilterAttrs) {
		p.filters = append(p.filters, &netlink.BpfFilter{
			FilterAttrs:  attrs,
			DirectAction: true,
			Fd:           p.bpfObjects.Probe.FD(),
		})
	}

	// Ingress
	addFilter(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Protocol:  unix.ETH_P_ALL,
	})

	// Egress
	addFilter(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Protocol:  unix.ETH_P_ALL,
	})

	for _, filter := range p.filters {
		if err := p.handle.FilterReplace(filter); err != nil {
			return err
		}
	}

	return nil
}

func (p *probe) loadObjects() error {
	objs := probeObjects{}
	if err := loadProbeObjects(
		&objs,
		&ebpf.CollectionOptions{
			Maps:     ebpf.MapOptions{},
			Programs: ebpf.ProgramOptions{LogLevel: (ebpf.LogLevelInstruction | ebpf.LogLevelBranch | ebpf.LogLevelStats)},
		},
	); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// Using %+v will print the whole verifier error, not just the last
			// few lines.
			fmt.Printf("Verifier error: %+v\n", ve)
		}
		return err
	}
	p.bpfObjects = &objs

	return nil
}

func setRlimit() error {
	n := uint64(1024 * 1024 * 10)
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: n, Max: n})
}
