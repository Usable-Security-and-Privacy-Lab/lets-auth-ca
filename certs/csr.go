// The certs package contains all of the needed components for the ca to deal with certificates.
package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/config"
)

// AuthCertValidDays represents the number of days an Authenticator Certificate
// signed by this package will be valid for.
const AuthCertValidDays int = 10

// RootCertValidDays represents the number of days the Root Certificate signed by
// this package will be valid for.
const RootCertValidDays int = 365

// SessionCertValidMins represents the number of minutes a Session Certificate
// signed by this package should be valid for.
const SessionCertValidMins int = 10
const nanoToSeconds int = 1000000000
const secondsToMinutes int = 60
const secondsToDays int = 86400

// SignCSR takes an x509.CertificateRequest, the ca's private key, and the
// number of days that the certificate should be active for and then signs the
// Certificate Signing Request using the root certificate. The function then
// returns a pointer to the resulting x509.Certificate object.
func SignCSR(csr *x509.CertificateRequest, privKey rsa.PrivateKey, activeDays int) (*x509.Certificate, error) {
	csrNotBefore := time.Now()
	csrNotAfter := csrNotBefore.Add(time.Duration(nanoToSeconds * secondsToDays * activeDays))

	// rootNotBefore := time.Now()
	// rootNotAfter := rootNotBefore.Add(time.Duration(nanoToSeconds * secondsToDays * RootCertValidDays))

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
	// rootTemplate := x509.Certificate{
	// 	SerialNumber: big.NewInt(1),
	// 	Subject: pkix.Name{
	// 		CommonName:   "letsauth.org",
	// 		Organization: []string{"Let's Authenticate"},
	// 	},

	// 	EmailAddresses: []string{"<admin@letsauth.org>"},
	// 	NotBefore:      rootNotBefore,
	// 	NotAfter:       rootNotAfter,

	// 	SubjectKeyId: []byte{1, 2, 3, 4},
	// 	KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,

	// 	BasicConstraintsValid: true,
	// 	IsCA:                  true,
	// }
	// rootCertificate := config.Get().RootCertificate

	signedCertDER, err := x509.CreateCertificate(rand.Reader, &csrTemplate, config.Get().RootCertificate, csr.PublicKey, &privKey)
	if err != nil {
		return nil, err
	}

	signedCert, err := x509.ParseCertificate(signedCertDER)
	if err != nil {
		return nil, err
	}

	return signedCert, nil
}
