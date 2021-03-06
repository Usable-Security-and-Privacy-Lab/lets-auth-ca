package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/errorHandler"
	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/util"
)

// SignCSR takes the ca's private key and public key and then recreates and
// re-signs the root certificate. The function then returns a pointer to the
// resulting x509.Certificate object.
func SignRoot(pubKey *rsa.PublicKey, privKey *rsa.PrivateKey) (*x509.Certificate, error) {
	rootNotBefore := time.Now()
	rootNotAfter := rootNotBefore.Add(time.Duration(nanoToSeconds * secondsToDays * RootCertValidDays))

	rootTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "letsauth.org",
			Organization: []string{"Let's Authenticate"},
		},

		EmailAddresses: []string{"<admin@letsauth.org>"},
		NotBefore:      rootNotBefore,
		NotAfter:       rootNotAfter,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	signedCertDER, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, pubKey, privKey)
	if err != nil {
		return nil, err
	}

	signedCert, err := x509.ParseCertificate(signedCertDER)
	if err != nil {
		return nil, err
	}

	return signedCert, nil
}

// ReSignRootCert is the core of the routine run by the ca when the -root flag
// is used. It recreates and re-signs the root certificate and then writes that
// certificate to the file specified in the config file.
func ReSignRootCert() {
	cfg := util.GetConfig()

	root, err := SignRoot(cfg.PublicKey, cfg.PrivateKey)
	if err != nil {
		errorHandler.Fatal(err)
	}

	rootData := util.PackCertificateToPemBytes(root)
	err = os.WriteFile(cfg.Base+cfg.RootCertificateFile, rootData, 0644)
	if err != nil {
		errorHandler.Fatal(err)
	}

	fmt.Println("Successfully resigned the root certificate")
}
