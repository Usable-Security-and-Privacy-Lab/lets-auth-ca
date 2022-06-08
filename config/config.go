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
	"os"
	"sync"

	"go-play/errorHandler"

	"gopkg.in/yaml.v2"
)

var once sync.Once
var cfg *Config

type Config struct {
	// name of the configuration, such as 'development' or 'production'
	Name string `yaml:"name"`
	// database configuration
	DbPassword string `yaml:"database password"`
	// private key
	PrivateKeyFile string `yaml:"private key"`
}

func Init(configDir, configMode string) {
	fileName := configDir + "/" + configMode + "/config.yml"
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
		})
}

func Get() *Config {
	return cfg
}
