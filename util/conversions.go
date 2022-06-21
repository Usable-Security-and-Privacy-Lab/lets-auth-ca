// util was initially part of the certs package, unfortunately since these
// functions are needed by the config package, they must be placed here to
// avoid circular dependencies.
//
// This package holds the various functions useful for basic, frequently called
// utilities. For example, converting PEM strings to x509 objects, etc.
package util

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// UnpackCSRFromPemString takes a PEM formatted x509 Certificate Signing
// Request and returns a x509.CertificateRequest object from the given data.
func UnpackCSRFromPemString(csrPemString string) (*x509.CertificateRequest, error) {
	return UnpackCSRFromBytes([]byte(csrPemString))
}

// UnpackCSRFromBytes takes a CSR in a byte array formatted with either PEM or
// ASN.1 DER and formats it into an x509.CertificateRequest object.
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

// UnpackCertFromPemString takes a PEM formatted x509 Certificate and returns
// an x509.Certificate object from the given data.
func UnpackCertFromPemString(cert string) (*x509.Certificate, error) {
	return UnpackCertFromBytes([]byte(cert))
}

// UnpackCertFromBytes takes an x509 Certificate in a byte array formatted with
// either PEM or ASN.1 DER and formats it into an x509.Certificate object.
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

// PackCertificateToPemBytes takes an x.509.Certificate object and returns it
// as a ASN.1 DER formatted byte array.
func PackCertificateToPemBytes(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// UnpackPublicKeyFromPemString takes a PEM formatted PKCS#1 Public Key and
// returns a pointer to a rsa.PublicKey object from the given data.
func UnpackPublicKeyFromPemString(publicKeyPemString string) (*rsa.PublicKey, error) {
	return UnpackPublicKeyFromBytes([]byte(publicKeyPemString))
}

// UnpackPublicKeyFromBytes takes a PKCS#1 Public Key in a byte array formatted
// with either PEM or ASN.1 DER and formats it into an rsa.PublicKey object and
// returns a pointer to that object.
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

// PackPublicKeyToPemBytes takes a pointer to an rsa.PublicKey object and
// returns a byte array of that object with PKCS#1, ASN.1 DER formatting.
func PackPublicKeyToPemBytes(pubKey *rsa.PublicKey) []byte {
	pubKeyDer := x509.MarshalPKCS1PublicKey(pubKey)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyDer,
	})
}

// UnpackPrivateKeyFromPemString takes a PEM formatted PKCS#1 Private Key and
// returns a pointer to a rsa.PrivateKey object from the given data.
func UnpackPrivateKeyFromPemString(privateKeyPemString string) (*rsa.PrivateKey, error) {
	return UnpackPrivateKeyFromBytes([]byte(privateKeyPemString))
}

// UnpackPrivateKeyFromBytes takes a PKCS#1 Private Key in a byte array
// formatted with either PEM or ASN.1 DER and formats it into an rsa.PrivateKey
// object and returns a pointer to that object.
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

// PackPrivateKeyToPemBytes takes a pointer to an rsa.PrivateKey object and
// returns a byte array of that object with PKCS#1, ASN.1 DER formatting.
func PackPrivateKeyToPemBytes(privKey *rsa.PrivateKey) []byte {
	privKeyDer := x509.MarshalPKCS1PrivateKey(privKey)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyDer,
	})
}
