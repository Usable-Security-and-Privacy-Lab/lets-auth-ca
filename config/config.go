// config loads a Configuration from a configuration file called 'config.yml'
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
package config

import (
	"crypto/rsa"
	"crypto/x509"
	"os"
	"sync"

	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/errorHandler"
	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/util"

	"gopkg.in/yaml.v2"
)

var once sync.Once
var cfg *Config

// A Config is a singleton which reads in and stores the configuration file(s)
// needed to run the CA
type Config struct {
	Name                string            `yaml:"name"`              // name of the configuration, such as 'development' or 'production'
	DbPassword          string            `yaml:"database password"` // database configuration
	PublicKeyFile       string            `yaml:"public key"`        // public key file path
	PrivateKeyFile      string            `yaml:"private key"`       // private key file path
	RootCertificateFile string            `yaml:"root cert loc"`     // location of the root certificate
	PublicKey           *rsa.PublicKey    `yaml:"-"`                 // public key
	PrivateKey          *rsa.PrivateKey   `yaml:"-"`                 // private key
	RootCertificate     *x509.Certificate `yaml:"-"`                 // root certificate
}

// Init is called early into the runtime of a program. This function
// initializes the config singleton and reads in all of the referenced files.
// After this function returns, Get() may be called to retrieve a copy of a
// pointer to the singleton.
func Init(configDir, configMode string) {
	fileName := configDir + "/" + configMode + "/config.yml"
	once.Do(
		func() {
			// Read data in
			fData, err := os.ReadFile(fileName)
			if err != nil {
				errorHandler.Fatal(err)
			}

			// Parse yaml code
			err = yaml.Unmarshal(fData, cfg)
			if err != nil {
				errorHandler.Fatal(err)
			}

			// Read/parse root certificate
			rootData, err := os.ReadFile(cfg.RootCertificateFile)
			if err != nil {
				errorHandler.Fatal(err)
			}
			cfg.RootCertificate, err = util.UnpackCertFromBytes(rootData)
			if err != nil {
				errorHandler.Fatal(err)
			}

			// Read/parse public key
			pubKeyData, err := os.ReadFile(cfg.PublicKeyFile)
			if err != nil {
				errorHandler.Fatal(err)
			}
			cfg.PublicKey, err = util.UnpackPublicKeyFromBytes(pubKeyData)
			if err != nil {
				errorHandler.Fatal(err)
			}

			// Read/parse public key
			privKeyData, err := os.ReadFile(cfg.PrivateKeyFile)
			if err != nil {
				errorHandler.Fatal(err)
			}
			cfg.PrivateKey, err = util.UnpackPrivateKeyFromBytes(privKeyData)
			if err != nil {
				errorHandler.Fatal(err)
			}
		})
}

// Get returns a pointer to the singleton of the Config object. If Init() has
// not been called or returned an error, this function will return nil.
func Get() *Config {
	return cfg
}
