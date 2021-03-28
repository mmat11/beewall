package internal

import (
	"fmt"
	"net"
	"strconv"

	"inet.af/netaddr"
)

type Config struct {
	InterfacesConfig []InterfaceConfig
	Rules            struct {
		Ingress []Rule
		Egress  []Rule
	}
}

type InterfaceConfig struct {
	Interface     net.Interface
	XDPAttachMode XDPAttachMode
}

type Rule struct {
	IPs      []netaddr.IP
	Protocol Protocol
	Ports    []Port
}

type Port uint16

type Protocol uint8

const (
	ProtocolICMP Protocol = iota
	ProtocolTCP
	ProtocolUDP
)

/* https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_link.h#L1165 */
type XDPAttachMode uint8

const (
	XDPAttachModeGeneric XDPAttachMode = 0
	XDPAttachModeSkb     XDPAttachMode = 1 << 1
	XDPAttachModeDrv     XDPAttachMode = 1 << 2
	XDPAttachModeHW      XDPAttachMode = 1 << 3
)

type rawConfig struct {
	InterfacesConfig []struct {
		Interface     string `yaml:"interface"`
		XDPAttachMode string `yaml:"xdp_attach_mode"`
	} `yaml:"interfaces_config"`
	Rules struct {
		Ingress []rawRule `yaml:"ingress"`
		Egress  []rawRule `yaml:"egress"`
	} `yaml:"rules"`
}

type rawRule struct {
	IPs      []string `yaml:"ips"` // TODO: cidr
	Protocol string   `yaml:"protocol"`
	Ports    []string `yaml:"ports"` // TODO: port ranges
}

func (cfg *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var raw rawConfig
	if err := unmarshal(&raw); err != nil {
		return err
	}

	for _, ifc := range raw.InterfacesConfig {
		var ifCfg InterfaceConfig

		netIf, err := net.InterfaceByName(ifc.Interface)
		if err != nil {
			return fmt.Errorf("load config interface: %w", err)
		}
		ifCfg.Interface = *netIf

		switch ifc.XDPAttachMode {
		case "", "generic":
			ifCfg.XDPAttachMode = XDPAttachModeGeneric
		case "skb":
			ifCfg.XDPAttachMode = XDPAttachModeSkb
		case "drv":
			ifCfg.XDPAttachMode = XDPAttachModeDrv
		case "hw":
			ifCfg.XDPAttachMode = XDPAttachModeHW
		default:
			return fmt.Errorf("XDP attach mode for interface %s invalid or not supported", netIf.Name)
		}

		cfg.InterfacesConfig = append(cfg.InterfacesConfig, ifCfg)
	}
	for _, in := range raw.Rules.Ingress {
		r, err := ruleFromRaw(&in)
		if err != nil {
			return err
		}
		cfg.Rules.Ingress = append(cfg.Rules.Ingress, *r)
	}
	for _, in := range raw.Rules.Egress {
		r, err := ruleFromRaw(&in)
		if err != nil {
			return err
		}
		cfg.Rules.Egress = append(cfg.Rules.Egress, *r)
	}

	return nil
}

func ruleFromRaw(rr *rawRule) (*Rule, error) {
	var r Rule

	for _, i := range rr.IPs {
		ip, err := netaddr.ParseIP(i)
		if err != nil {
			return nil, fmt.Errorf("load config ip: %w", err)
		}
		r.IPs = append(r.IPs, ip)
	}

	switch rr.Protocol {
	case "icmp":
		r.Protocol = ProtocolICMP
	case "tcp":
		r.Protocol = ProtocolTCP
	case "udp":
		r.Protocol = ProtocolUDP
	default:
		return nil, fmt.Errorf("invalid protocol: %v", rr.Protocol)
	}

	for _, p := range rr.Ports {
		u64p, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %v", p)
		}
		r.Ports = append(r.Ports, Port(uint16(u64p)))
	}

	return &r, nil
}

type BpfRule struct {
	L3proto uint32
	L4proto uint32
	Saddr   [4]byte
	Saddr6  [16]byte
	Dport   uint16
}

func (cfg *Config) ToBpf() ([]BpfRule, []BpfRule) {
	toBpf := func(rules []Rule) []BpfRule {
		var bpfRules = make([]BpfRule, 0)

		for _, r := range rules {
			for _, ip := range r.IPs {
				if r.Protocol == ProtocolICMP {
					// set the ports to [0] in order to add only one rule
					r.Ports = []Port{Port(0)}
				}

				for _, port := range r.Ports {
					var rule BpfRule

					if ip.Is4() {
						rule.L3proto = 0
						rule.Saddr = ip.As4()
					} else {
						rule.L3proto = 1
						rule.Saddr6 = ip.As16()
					}
					rule.L4proto = uint32(r.Protocol)
					rule.Dport = uint16(port)

					bpfRules = append(bpfRules, rule)
				}
			}
		}
		return bpfRules
	}

	return toBpf(cfg.Rules.Ingress), toBpf(cfg.Rules.Egress)
}
