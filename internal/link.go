package internal

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

func attachXDP(prog *ebpf.Program, ifC InterfaceConfig) error {
	nl, err := netlink.LinkByIndex(ifC.Interface.Index)
	if err != nil {
		return err
	}

	if err := netlink.LinkSetXdpFdWithFlags(nl, prog.FD(), int(ifC.XDPAttachMode)); err != nil {
		return fmt.Errorf("attach XDP: failed to attach program to interface %s in mode %d: %w", ifC.Interface.Name, ifC.XDPAttachMode, err)
	}

	log.Printf("XDP program attached to %s\n", ifC.Interface.Name)
	return nil
}

func detachXDP(ifC InterfaceConfig) error {
	nl, err := netlink.LinkByIndex(ifC.Interface.Index)
	if err != nil {
		return err
	}

	if err := netlink.LinkSetXdpFdWithFlags(nl, -1, int(ifC.XDPAttachMode)); err != nil {
		return fmt.Errorf("detach XDP: failed to detach program from interface %s in mode %d: %w", ifC.Interface.Name, ifC.XDPAttachMode, err)
	}

	log.Printf("XDP program detached from %s\n", ifC.Interface.Name)
	return nil
}
