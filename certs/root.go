package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

func SignRoot(pubKey rsa.PublicKey, privKey rsa.PrivateKey) (*x509.Certificate, error) {
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

	signedCertDER, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &pubKey, &privKey)
	if err != nil {
		return nil, err
	}

	signedCert, err := x509.ParseCertificate(signedCertDER)
	if err != nil {
		return nil, err
	}

	return signedCert, nil
}
