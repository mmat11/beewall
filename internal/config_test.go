package internal_test

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
	"inet.af/netaddr"

	"github.com/mmat11/beewall/internal"
)

func TestParseConfig(t *testing.T) {
	var tests = []struct {
		name           string
		bytes          []byte
		expectedConfig internal.Config
	}{
		{
			"empty file",
			[]byte{},
			internal.Config{},
		},
		{
			"full",
			[]byte(`
rules:
  ingress:
    - ips:
      - 8.8.8.0/24
      - 2001:4860:4860::8888/128
      protocol: icmp
    - ips:
      - 10.0.0.1/32
      - 10.0.0.2/32
      protocol: tcp
      ports:
      - 80
      - 443
  egress:
    - ips:
      - 1.2.3.4/32
      - 5.6.7.8/32
      protocol: icmp
    - ips:
      - 10.0.0.1/32
      protocol: tcp
      ports:
      - 80
      - 443`),
			internal.Config{
				Rules: struct {
					Ingress []internal.Rule
					Egress  []internal.Rule
				}{
					Ingress: []internal.Rule{
						{IPPrefixes: []netaddr.IPPrefix{netaddr.MustParseIPPrefix("8.8.8.0/24"), netaddr.MustParseIPPrefix("2001:4860:4860::8888/128")}, Protocol: internal.ProtocolICMP},
						{
							IPPrefixes: []netaddr.IPPrefix{netaddr.MustParseIPPrefix("10.0.0.1/32"), netaddr.MustParseIPPrefix("10.0.0.2/32")},
							Protocol:   internal.ProtocolTCP,
							Ports:      []internal.Port{80, 443},
						},
					},
					Egress: []internal.Rule{
						{IPPrefixes: []netaddr.IPPrefix{netaddr.MustParseIPPrefix("1.2.3.4/32"), netaddr.MustParseIPPrefix("5.6.7.8/32")}, Protocol: internal.ProtocolICMP},
						{
							IPPrefixes: []netaddr.IPPrefix{netaddr.MustParseIPPrefix("10.0.0.1/32")},
							Protocol:   internal.ProtocolTCP,
							Ports:      []internal.Port{80, 443},
						},
					},
				},
			},
		},
	}

	var cfg internal.Config
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := yaml.Unmarshal(tt.bytes, &cfg); err != nil {
				t.Fatalf("unmarshal config file: %v", err)
			}
			if !reflect.DeepEqual(cfg, tt.expectedConfig) {
				t.Fatalf("parsed config is incorrect:\nwant:\n%v\ngot:\n%v\n", tt.expectedConfig, cfg)
			}
		})
	}
}

func TestParseConfigInvalid(t *testing.T) {
	var tests = []struct {
		name  string
		bytes []byte
	}{
		{
			"unknown interface",
			[]byte(`
interfaces:
  - interface: idontexist
    xdp_attach_mode: drv`),
		},
	}

	var cfg internal.Config
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := yaml.Unmarshal(tt.bytes, &cfg); err == nil {
				t.Fatal("unmarshal config file: expected error")
			}
		})
	}
}
