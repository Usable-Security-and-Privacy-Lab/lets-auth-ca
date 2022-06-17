package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

const AuthCertValidDays int = 10
const RootCertValidDays int = 365
const SessionCertValidDays int = 30
const nanoToSeconds int = 1000000000
const secondsToDays int = 86400

func SignCSR(csr *x509.CertificateRequest, privKey rsa.PrivateKey, activeDays int) (*x509.Certificate, error) {
	csrNotBefore := time.Now()
	csrNotAfter := csrNotBefore.Add(time.Duration(nanoToSeconds * secondsToDays * activeDays))

	rootNotBefore := time.Now()
	rootNotAfter := rootNotBefore.Add(time.Duration(nanoToSeconds * secondsToDays * RootCertValidDays))

	csrTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: csr.Subject.CommonName,
		},

		EmailAddresses: csr.EmailAddresses,
		NotBefore:      csrNotBefore,
		NotAfter:       csrNotAfter,

		SubjectKeyId:          []byte{1, 2, 3, 4}, // May need to ba a unique identifier. Is x509 extension
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Can we have the root certificate stored in a singleton in the server and not remake the template every single time?
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

	signedCertDER, err := x509.CreateCertificate(rand.Reader, &csrTemplate, &rootTemplate, csr.PublicKey, &privKey)
	if err != nil {
		return nil, err
	}

	signedCert, err := x509.ParseCertificate(signedCertDER)
	if err != nil {
		return nil, err
	}

	return signedCert, nil
}
