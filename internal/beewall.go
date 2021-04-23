package internal

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "$BPF_CFLAGS" -cc clang-11 Ingress ../bpf/ingress.c

func Run(ctx context.Context, file string) error {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	cfg := ConfigFromFile(file)

	in := IngressObjects{}
	if err := LoadIngressObjects(&in, nil); err != nil {
		return err
	}
	defer in.Close()

	specs, err := LoadIngress()
	if err != nil {
		return err
	}
	lpmSpec := specs.Maps["lpm"].Copy()

	ingressRules, _ := cfg.ToBpf()

	FillMap(in.IngressRules, lpmSpec, ingressRules)

	log.Printf("registered %d ingress rules\n", len(ingressRules))

	// TODO: egress

	for _, ifC := range cfg.Interfaces {
		if err := attachXDP(in.Ingress, ifC); err != nil {
			return err
		}

		defer func(ifC InterfaceConfig) {
			if err := detachXDP(ifC); err != nil {
				log.Println(err)
			}
		}(ifC)
	}

	<-stopper
	return nil
}

func FillMap(m *ebpf.Map, spec *ebpf.MapSpec, rules BpfRules) {
	fill := func(k OuterKey, lpm LpmMap) {
		var contents = make([]ebpf.MapKV, 0)
		for k, v := range lpm {
			contents = append(contents, ebpf.MapKV{Key: k, Value: v})
		}
		spec.Contents = contents

		innerMap, err := ebpf.NewMap(spec)
		if err != nil {
			log.Fatalf("create inner map: %v", err)
		}

		if err := m.Put(k, innerMap); err != nil {
			log.Fatalf("map put: %v", err)
		}
	}

	for outerKey, lpmMap := range rules {
		fill(outerKey, lpmMap)
	}
}
