package util

import (
	"crypto/rsa"
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

func UnpackCertFromPemString(cert string) (*x509.Certificate, error) {
	return UnpackCertFromBytes([]byte(cert))
}

func UnpackCertFromBytes(certData []byte) (*x509.Certificate, error) {
	certPemBlock, _ := pem.Decode(certData)
	var cert *x509.Certificate
	var err error
	if certPemBlock == nil {
		cert, err = x509.ParseCertificate(certData)
	} else {
		cert, err = x509.ParseCertificate(certPemBlock.Bytes)
	}

	if err != nil {
		return nil, err
	}
	return cert, nil
}

func PackCertificateToPemBytes(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

func UnpackPublicKeyFromPemString(publicKeyPemString string) (*rsa.PublicKey, error) {
	return UnpackPublicKeyFromBytes([]byte(publicKeyPemString))
}

func UnpackPublicKeyFromBytes(publicKeyBytes []byte) (*rsa.PublicKey, error) {
	pubKeyPemBlock, _ := pem.Decode(publicKeyBytes)
	var pubKey *rsa.PublicKey
	var err error
	if pubKeyPemBlock == nil {
		pubKey, err = x509.ParsePKCS1PublicKey(publicKeyBytes)
	} else {
		pubKey, err = x509.ParsePKCS1PublicKey(pubKeyPemBlock.Bytes)
	}

	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func PackPublicKeyToPemBytes(pubKey *rsa.PublicKey) []byte {
	pubKeyDer := x509.MarshalPKCS1PublicKey(pubKey)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDer,
	})
}

func UnpackPrivateKeyFromPemString(privateKeyPemString string) (*rsa.PrivateKey, error) {
	return UnpackPrivateKeyFromBytes([]byte(privateKeyPemString))
}

func UnpackPrivateKeyFromBytes(privateKeyBytes []byte) (*rsa.PrivateKey, error) {
	privKeyPemBlock, _ := pem.Decode(privateKeyBytes)
	var privKey *rsa.PrivateKey
	var err error
	if privKeyPemBlock == nil {
		privKey, err = x509.ParsePKCS1PrivateKey(privateKeyBytes)
	} else {
		privKey, err = x509.ParsePKCS1PrivateKey(privKeyPemBlock.Bytes)
	}

	if err != nil {
		return nil, err
	}
	return privKey, nil
}

func PackPrivateKeyToPemBytes(privKey *rsa.PrivateKey) []byte {
	privKeyDer := x509.MarshalPKCS1PrivateKey(privKey)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyDer,
	})
}
