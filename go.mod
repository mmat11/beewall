module github.com/mmat11/beewall

go 1.16

require (
	github.com/cilium/ebpf v0.4.0
	golang.org/x/sys v0.0.0-20210124154548-22da62e12c0c
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
	inet.af/netaddr v0.0.0-20210317195617-2d42ec05f8a1
)

replace github.com/cilium/ebpf => /home/matt/cebpf
