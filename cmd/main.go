package main

import (
	"context"
	"flag"
	"log"

	"golang.org/x/sys/unix"

	"github.com/mmat11/beewall/internal"
)

const defaultConfigFile = "config.yml"

func main() {
	var (
		ctx        = context.Background()
		configFile = flag.String("c", defaultConfigFile, "config file path")
	)
	flag.Parse()

	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}

	if err := internal.Run(ctx, *configFile); err != nil {
		log.Fatalf("error while attaching and running programs: %v", err)
	}
}
