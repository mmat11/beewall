package internal

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-11 Beewall ../bpf/beewall.c

func Run(ctx context.Context, cfg Config) error {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	objs := BeewallObjects{}
	if err := LoadBeewallObjects(&objs, nil); err != nil {
		return err
	}
	defer objs.Close()

	// TODO: attach to interface

	<-stopper
	return nil
}
