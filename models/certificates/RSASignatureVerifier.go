package certificates

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	// "fmt"
)

// VerifyRSASignatureFromCert verifies an RSA Signature (with SHA-256) for some string data
func VerifyRSASignatureFromCert(certWithKey, stringData, base64Signature string) error {
	// get signature from base64 into bytes
	signature, err := base64.StdEncoding.DecodeString(base64Signature)

	if err != nil {
		return err
	}

	// get message into bytes for hashing
	message := []byte(stringData)
	hashed := sha256.Sum256(message)

	// get the public key from the certificate
	// parse the certificate
	cert, err := FromPem(certWithKey)

	if err != nil {
		return err
	}

	key := cert.PublicKey

	// dot the actual verification of the signature
	return rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), crypto.SHA256, hashed[:], signature)
}
