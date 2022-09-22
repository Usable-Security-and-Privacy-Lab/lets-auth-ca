package certificates

import (
	"crypto/rsa"
	"testing"
)

func TestLoadKey(t *testing.T) {
	var key rsa.PrivateKey
	LoadKey("../../certs/letsauthprivate.key", &key)
	if key.Size() == 0 {
		t.Fatalf("Error in loading private key")
	}

}
