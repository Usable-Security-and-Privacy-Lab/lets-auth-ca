package certs

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// VerifyRSASignatureFromCert verifies an RSA Signature (with SHA-256) for some string data
func VerifyRSASignatureFromCert(cert *x509.Certificate, message []byte, base64Signature string) error {
	// get signature from base64 into bytes
	signature, err := base64.StdEncoding.DecodeString(base64Signature)

	if err != nil {
		return err
	}

	// get message into bytes for hashing
	hashed := sha256.Sum256(message)

	// get the public key from the certificate
	key := cert.PublicKey

	// dot the actual verification of the signature
	return rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), crypto.SHA256, hashed[:], signature)
}

// AddCert adds a new service certificate to the database, along with it's association to a device certificate
func AddCert(certString, deviceCert string) error {

	pemBlock, _ := pem.Decode([]byte(certString))
	if pemBlock == nil {
		return errors.New("invalid PEM string for Certificate")
	}

	// Parse and return pemBlock
	certificate, err := x509.ParseCertificate(pemBlock.Bytes)

	if err != nil {
		return errors.New("unable to convert certificate FromPem in AddNewCert")
	}

	notBefore := certificate.NotBefore
	expTime := certificate.NotAfter

	var pubKey []byte
	if certificate != nil {
		pubKey = pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(certificate.PublicKey.(*rsa.PublicKey)),
			},
		)
	} else {
		return errors.New("unable to obtain public key from cert in AddNewCert")
	}

	var db gorm.DB

	// first try to update the certificate in the database
	sql := "UPDATE certs SET cert=?, certExp=?, lastUpdated=? WHERE pubKey=?"
	if err = db.Exec(sql, certString, expTime, notBefore, pubKey).Error; err != nil {
		fmt.Println("Error updating cert in cert table")
		fmt.Println(err)
		return errors.New("unable to update certificate in the database")
	}

	// next insert into the database if the certificate wasn't previously stored
	sql = "INSERT IGNORE certs(cert, eblob, certExp, pubKey, deviceCertId, lastUpdated)\n"
	sql += "SELECT ?, ?, ?, ?, userDevice.id, ? FROM userDevice WHERE deviceCert=?"

	err = db.Exec(sql, certString, "a blob", expTime, pubKey, notBefore, deviceCert).Error

	if err != nil {
		fmt.Println(err)
		return errors.New("error inserting into cert table")
	}

	return nil
}
