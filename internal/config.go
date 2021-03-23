package internal

import (
	"fmt"
	"strconv"

	"inet.af/netaddr"
)

type Config struct {
	Ingress []Rule
	Egress  []Rule
}

type rawConfig struct {
	Ingress []rawRule `yaml:"ingress"`
	Egress  []rawRule `yaml:"egress"`
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

	for _, in := range raw.Ingress {
		r, err := ruleFromRaw(&in)
		if err != nil {
			return err
		}
		cfg.Ingress = append(cfg.Ingress, *r)
	}
	for _, in := range raw.Egress {
		r, err := ruleFromRaw(&in)
		if err != nil {
			return err
		}
		cfg.Egress = append(cfg.Egress, *r)
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
