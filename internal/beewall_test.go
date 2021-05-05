package internal_test

import (
	"log"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"

	"github.com/mmat11/beewall/internal"
)

type XDPAction uint8

const (
	Aborted XDPAction = iota
	Drop
	Pass
	Tx
	Redirect
)

func (a XDPAction) String() string {
	switch a {
	case Aborted:
		return "ABORTED"
	case Drop:
		return "DROP"
	case Pass:
		return "PASS"
	case Tx:
		return "TX"
	case Redirect:
		return "REDIRECT"
	default:
		return "UNKNOWN"
	}
}

func TestBeewall(t *testing.T) {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}

	tests := []struct {
		name   string
		config internal.Config
		packet []byte
		exp    XDPAction
	}{
		{
			name:   "invalid packet",
			config: internal.Config{},
			packet: make([]byte, 14),
			exp:    Pass,
		},
		{
			name: "tcp match",
			config: internal.Config{
				Rules: struct {
					Ingress []internal.Rule
					Egress  []internal.Rule
				}{
					Ingress: []internal.Rule{
						{
							Protocol:   internal.ProtocolTCP,
							IPPrefixes: []netaddr.IPPrefix{netaddr.MustParseIPPrefix("8.8.8.0/24")},
							Ports:      []internal.Port{internal.Port(443)},
						},
					},
				},
			},
			packet: mustMakeIPv4TCPPacket(net.IP{8, 8, 8, 8}, 443),
			exp:    Pass,
		},
		{
			name: "tcp no match dport",
			config: internal.Config{
				Rules: struct {
					Ingress []internal.Rule
					Egress  []internal.Rule
				}{
					Ingress: []internal.Rule{
						{
							Protocol:   internal.ProtocolTCP,
							IPPrefixes: []netaddr.IPPrefix{netaddr.MustParseIPPrefix("8.8.8.0/24")},
							Ports:      []internal.Port{internal.Port(443)},
						},
					},
				},
			},
			packet: mustMakeIPv4TCPPacket(net.IP{8, 8, 8, 8}, 80),
			exp:    Drop,
		},
	}

	in := internal.IngressObjects{}
	if err := internal.LoadIngressObjects(&in, nil); err != nil {
		t.Fatalf("load objects: %v", err)
	}
	defer in.Close()

	specs, err := internal.LoadIngress()
	if err != nil {
		t.Fatalf("load specs: %v", err)
	}
	lpmSpec := specs.Maps["lpm"].Copy()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingress, _ := tt.config.ToBpf()
			internal.FillMap(in.IngressRules, lpmSpec, ingress)

			ret, _, err := in.Ingress.Test(tt.packet)
			if err != nil {
				t.Fatalf("program test: %v", err)
			}
			act := XDPAction(ret)
			if tt.exp != act {
				t.Fatalf("program test: expected xdp action %s, got %s", tt.exp, act)
			}
		})
	}
}

func mustMakeIPv4TCPPacket(srcIP net.IP, dstPort uint16) []byte {
	var (
		buffer  = gopacket.NewSerializeBuffer()
		options = gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		eth = layers.Ethernet{
			EthernetType: layers.EthernetTypeIPv4,
			SrcMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xee, 0xee, 0xff},
			DstMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xee, 0xee, 0xff},
		}
		ip = layers.IPv4{
			Protocol: layers.IPProtocolTCP,
			SrcIP:    srcIP,
			DstIP:    net.IP{1, 2, 3, 4},
		}
		tcp = layers.TCP{
			SrcPort: layers.TCPPort(1234),
			DstPort: layers.TCPPort(dstPort),
		}
	)

	if err := tcp.SetNetworkLayerForChecksum(&ip); err != nil {
		panic(err)
	}

	if err := gopacket.SerializeLayers(buffer, options,
		&eth,
		&ip,
		&tcp,
		gopacket.Payload([]byte{0x00}),
	); err != nil {
		panic(err)
	}

	return buffer.Bytes()
}
