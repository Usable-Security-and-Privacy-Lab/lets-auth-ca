package certs

import (
	"crypto/x509"
	"encoding/pem"
)

// UnpackCSRFromPemString takes a PEM formatted x509 Certificate
//		Signing Request and returns the x509 CertificateRequest object
func UnpackCSRFromPemString(csrPemString string) (*x509.CertificateRequest, error) {
	return UnpackCSRFromBytes([]byte(csrPemString))
}

func UnpackCSRFromBytes(csrData []byte) (*x509.CertificateRequest, error) {
	csrPemBlock, _ := pem.Decode(csrData)
	var csr *x509.CertificateRequest
	var err error
	if csrPemBlock == nil {
		csr, err = x509.ParseCertificateRequest(csrData)
	} else {
		csr, err = x509.ParseCertificateRequest(csrPemBlock.Bytes)
	}

	if err != nil {
		return nil, err
	}
	return csr, nil
}

func PackCertificateToPemBytes(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}
