package main

import (
	"context"
	"flag"
	"log"
	"os"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"

	"github.com/mmat11/beewall/internal"
)

const defaultConfigFile = "config.yml"

func main() {
	var (
		ctx        = context.Background()
		configFile = flag.String("c", defaultConfigFile, "config file path")
	)
	flag.Parse()

	cfg := loadConfig(*configFile)

	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}

	if err := internal.Run(ctx, cfg); err != nil {
		log.Fatalf("error while attaching and running programs: %v", err)
	}
}

func loadConfig(configFile string) internal.Config {
	var cfg internal.Config

	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("open config file: %v", err)
	}

	if err := yaml.Unmarshal([]byte(data), &cfg); err != nil {
		log.Fatalf("unmarshal config file: %v", err)
	}
	return cfg
}
