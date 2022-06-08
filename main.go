package main

import (
	"flag"
	"fmt"

	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/config"
)

func main() {
	// process command line arguments
	configDir := flag.String("configDir", "configs", "configuration directory")
	configMode := flag.String("config", "development", "configuration mode")
	flag.Parse()
	config.Init(*configDir, *configMode)
	cfg := config.Get()
	fmt.Println(cfg.Name)
}
