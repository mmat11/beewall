package internal

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strconv"

	"gopkg.in/yaml.v3"
	"inet.af/netaddr"
)

type Config struct {
	Interfaces []InterfaceConfig
	Rules      struct {
		Ingress []Rule
		Egress  []Rule
	}
}

type InterfaceConfig struct {
	Interface     net.Interface
	XDPAttachMode XDPAttachMode
}

type Rule struct {
	IPPrefixes []netaddr.IPPrefix
	Protocol   Protocol
	Ports      []Port
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
	_ XDPAttachMode = 1 << iota
	XDPAttachModeSkb
	XDPAttachModeDrv
	XDPAttachModeHW
)

type rawConfig struct {
	Interfaces []struct {
		Interface     string `yaml:"interface"`
		XDPAttachMode string `yaml:"xdp_attach_mode"`
	} `yaml:"interfaces"`
	Rules struct {
		Ingress []rawRule `yaml:"ingress"`
		Egress  []rawRule `yaml:"egress"`
	} `yaml:"rules"`
}

type rawRule struct {
	IPs      []string `yaml:"ips"`
	Protocol string   `yaml:"protocol"`
	Ports    []string `yaml:"ports"` // TODO: port ranges
}

func ConfigFromFile(file string) Config {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatalf("open config file: %v", err)
	}

	var cfg Config
	if err := yaml.Unmarshal([]byte(data), &cfg); err != nil {
		log.Fatalf("unmarshal config file: %v", err)
	}
	return cfg
}

func (cfg *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var raw rawConfig
	if err := unmarshal(&raw); err != nil {
		return err
	}

	for _, ifc := range raw.Interfaces {
		var ifCfg InterfaceConfig

		netIf, err := net.InterfaceByName(ifc.Interface)
		if err != nil {
			return fmt.Errorf("load config interface: %w", err)
		}
		ifCfg.Interface = *netIf

		switch ifc.XDPAttachMode {
		case "", "skb", "generic":
			ifCfg.XDPAttachMode = XDPAttachModeSkb
		case "drv":
			ifCfg.XDPAttachMode = XDPAttachModeDrv
		case "hw":
			ifCfg.XDPAttachMode = XDPAttachModeHW
		default:
			return fmt.Errorf("XDP attach mode for interface %s invalid or not supported", netIf.Name)
		}

		cfg.Interfaces = append(cfg.Interfaces, ifCfg)
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
		ipPrefix, err := netaddr.ParseIPPrefix(i)
		if err != nil {
			return nil, fmt.Errorf("load config ip: %w", err)
		}
		r.IPPrefixes = append(r.IPPrefixes, ipPrefix)
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

type (
	BpfRules map[OuterKey]LpmMap
	OuterKey struct {
		L3proto uint32
		L4proto uint32
		Dport   uint16
	}
	LpmMap map[LpmKey]uint8 // val:unused
	LpmKey struct {
		Prefixlen uint32
		Saddr     [16]byte
	}
)

func (cfg *Config) ToBpf() (BpfRules, BpfRules) {
	toBpf := func(rules []Rule) BpfRules {
		bpfRules := make(BpfRules)

		for _, r := range rules {
			for _, ipPrefix := range r.IPPrefixes {
				if r.Protocol == ProtocolICMP {
					// set the ports to [0] in order to add only one rule
					r.Ports = []Port{Port(0)}
				}

				var (
					l3proto uint8  = 0
					lpmKey  LpmKey = LpmKey{Prefixlen: uint32(ipPrefix.Bits)}
				)
				if ipPrefix.IP.Is6() {
					l3proto = 1
				}

				for _, port := range r.Ports {
					outerKey := OuterKey{L3proto: uint32(l3proto), L4proto: uint32(r.Protocol), Dport: uint16(port)}

					if ipPrefix.IP.Is4() {
						lpmKey.Saddr = ip4As16(ipPrefix.IP)
					} else {
						lpmKey.Saddr = ipPrefix.IP.As16()
					}

					if _, ok := bpfRules[outerKey]; !ok {
						bpfRules[outerKey] = make(LpmMap)
					}

					bpfRules[outerKey][lpmKey] = uint8(1)
				}
			}
		}

		return bpfRules
	}

	return toBpf(cfg.Rules.Ingress), toBpf(cfg.Rules.Egress)
}

// ip4As16 creates a byte array to be used as lpm map key.
// ip.As16() is not ok in this case because the ipv4 part is put at the end.
func ip4As16(ip netaddr.IP) [16]byte {
	var ret [16]byte
	for i, b := range ip.As4() {
		ret[i] = b
	}
	return ret
}
