package config

// Configuration is loaded from a configuration file called 'config.yml' in
// a specified directory. The intended usage is for the user to setup a
// 'development' directory and a 'production' directory containing
// necessary configuration info.

// The configuration uses the YAML format.

// This code follows the singleton pattern, so that there is one Config variable
// that is used globally. The sync.Once library ensures that the variable is
// configured only once. We follow the pattern shown here:
// https://golangbyexample.com/singleton-design-pattern-go/

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

type Config struct {
	// name of the configuration, such as 'development' or 'production'
	Name string `yaml:"name"`
	// database configuration
	DbPassword string `yaml:"database password"`
	// public key file path
	PublicKeyFile string `yaml:"public key"`
	// private key file path
	PrivateKeyFile string `yaml:"private key"`
	// location of the root certificate
	RootCertificateFile string `yaml:"root cert loc"`
	// public key
	PublicKey *rsa.PublicKey
	// private key
	PrivateKey *rsa.PrivateKey
	// root certificate
	RootCertificate *x509.Certificate
}

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

func Get() *Config {
	return cfg
}
