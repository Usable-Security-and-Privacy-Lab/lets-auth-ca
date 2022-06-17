package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/certs"
	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/config"
	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/errorHandler"
)

var cfg *config.Config

func main() {
	// process command line arguments
	signRoot := flag.Bool("root", false, "Resigns the root certificate. Mutually exclusive with other operating flags.")
	configDir := flag.String("configDir", "configs", "configuration directory")
	configMode := flag.String("config", "development", "configuration mode")
	flag.Parse()

	config.Init(*configDir, *configMode)
	cfg = config.Get()
	fmt.Println(cfg.Name)

	if *signRoot {
		resignRootCert()
		os.Exit(0)
	}
	// else continue with normal ca operations
}

func resignRootCert() {
	root, err := certs.SignRoot(cfg.PublicKey, cfg.PrivateKey)
	if err != nil {
		errorHandler.Fatal(err)
	}

	rootData := certs.PackCertificateToPemBytes(root)
	err = os.WriteFile(cfg.RootCertificateFile, rootData, 0644)
	if err != nil {
		errorHandler.Fatal(err)
	}

	fmt.Println("Successfully resigned the root certificate")
}
