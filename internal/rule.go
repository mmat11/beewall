package internal

import "inet.af/netaddr"

type Rule struct {
	IPs      []netaddr.IP
	Protocol Protocol
	Ports    []Port
}

type Protocol uint8

var (
	// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/in.h#L28
	ProtocolICMP Protocol = 1
	ProtocolTCP  Protocol = 6
	ProtocolUDP  Protocol = 17
)

type Port uint16
