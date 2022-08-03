// util loads a Configuration from a configuration file called 'config.yml'
// in a specified directory. The intended usage is for the user to setup a
// 'development' directory and a 'production' directory containing necessary
// configuration info.
//
// The configuration uses the YAML format.
//
// This code follows the singleton pattern, so that there is one Config
// variable that is used globally. The sync.Once library ensures that the
// variable is configured only once. We follow the pattern shown here:
// https://golangbyexample.com/singleton-design-pattern-go/
package util

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/errorHandler"

	"gopkg.in/yaml.v2"
)

var once sync.Once
var cfg *Config

// A Config is a singleton which reads in and stores the configuration file(s)
// needed to run the CA
type Config struct {
	Name     string `yaml:"name"` // name of the configuration, such as 'development' or 'production'
	Base     string `yaml:"-"`
	DbConfig string `yaml:"database config"`

	RPDisplayName string `yaml:"RP display name"`
	RPID          string `yaml:"RP ID"`
	RPOrigin      string `yaml:"RP origin"`

	PublicKeyFile       string `yaml:"public key"`       // public key file path
	PrivateKeyFile      string `yaml:"private key"`      // private key file path
	RootCertificateFile string `yaml:"root certificate"` // location of the root certificate

	PublicKey       *rsa.PublicKey    `yaml:"-"` // public key
	PrivateKey      *rsa.PrivateKey   `yaml:"-"` // private key
	RootCertificate *x509.Certificate `yaml:"-"` // root certificate
}

// ConfigInit is called early into the runtime of a program. This function
// initializes the config singleton and reads in all of the referenced files.
// After this function returns, Get() may be called to retrieve a copy of a
// pointer to the singleton.
func ConfigInit(configDir string) {
	base := configDir + "/"
	fileName := base + "config.yml"
	once.Do(
		func() {
			f, err := os.Open(fileName)
			if err != nil {
				errorHandler.Fatal(err)
			}
			defer f.Close()
			decoder := yaml.NewDecoder(f)
			err = decoder.Decode(&cfg)
			if err != nil {
				errorHandler.Fatal(err)
			}

			// set base
			cfg.Base = base

			// Read/parse root certificate
			rootData, err := os.ReadFile(cfg.Base + cfg.RootCertificateFile)
			if err != nil {
				// we might not have one yet!
				// TBD: switch to logger, produce warning
			} else {
				cfg.RootCertificate, err = UnpackCertFromBytes(rootData)
				if err != nil {
					errorHandler.Fatal(err)
				}
			}

			fmt.Println("parsed root certificate")

			// Read/parse public key
			pubKeyData, err := os.ReadFile(cfg.Base + cfg.PublicKeyFile)
			if err != nil {
				errorHandler.Fatal(err)
			}
			fmt.Println("unpacking...")
			cfg.PublicKey, err = UnpackPublicKeyFromBytes(pubKeyData)
			if err != nil {
				errorHandler.Fatal(err)
			}
			fmt.Println("unpacked!")

			// Read/parse public key
			privKeyData, err := os.ReadFile(cfg.Base + cfg.PrivateKeyFile)
			if err != nil {
				errorHandler.Fatal(err)
			}
			cfg.PrivateKey, err = UnpackPrivateKeyFromBytes(privKeyData)
			if err != nil {
				errorHandler.Fatal(err)
			}
			fmt.Println("got here")

		})
}

// Get returns a pointer to the singleton of the Config object. If Init() has
// not been called or returned an error, this function will return nil.
func GetConfig() *Config {
	if cfg == nil {
		errorHandler.Fatal(errors.New("Config singleton not initialized"))
	}
	return cfg
}
