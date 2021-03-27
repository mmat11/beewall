package internal

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "$BPF_CFLAGS" -cc clang-11 BeewallIngress ../bpf/ingress.c

func Run(ctx context.Context, cfg Config) error {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	in := BeewallIngressObjects{}
	if err := LoadBeewallIngressObjects(&in, nil); err != nil {
		return err
	}
	defer in.Close()

	ingressRules, _ := cfg.ToBpf()
	for i, rule := range ingressRules {
		if err := in.BeewallIngressMaps.IngressRules.Put(rule, uint8(1)); err != nil {
			log.Fatalf("map put %v(%v): %v", i, rule, err)
		}
	}
	log.Printf("registered %d ingress rules\n", len(ingressRules))

	// TODO: egress

	for _, ifC := range cfg.InterfacesConfig {
		if err := attachXDP(in.BeewallIngress, ifC); err != nil {
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
