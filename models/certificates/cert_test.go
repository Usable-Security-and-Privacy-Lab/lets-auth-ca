package certificates

import (
	"crypto/rsa"
	"testing"

	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/util"
)

func TestLoadKey(t *testing.T) {
	cfg := util.GetConfig()

	var key rsa.PrivateKey
	LoadKey(cfg.PrivateKeyFile, &key)
	if key.Size() == 0 {
		t.Fatalf("Error in loading private key")
	}

}
