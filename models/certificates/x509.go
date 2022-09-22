package certificates

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"
)

// CertMessage is used to pass websocket information
type CertMessage struct {
	// Data used to identy websocket
	Username string

	// Data shared between both
	Certificate string `json:"certificate"`
	Type        string `json:"type"`
	GoodUntil   string `json:"goodUntil"`
	PubKey      string `json:"pubKey"`
	Address     string `json:"address"`

	// Site cert data
	SavedData string `json:"savedData"`

	// Auth cert Data
	AuthName string `json:"authName"`
	RevFlag  string `json:"revFlag"`
}

// SignCert takes in a certificate and signs the certificate.
// Requires: Data (byte array), deviceCert (string), activeDays (string), checkDeviceCert (bool)
// Ensures: The passed in certificate (data) is signed
// Errors: Invalid Device Certificate, Invalid Date, Internal Server Error
func SignCert(data []byte, deviceCert, activeDays string, checkDeviceCert bool) (string, bool) {

	// don't check the device cert if this is for a device cert
	if checkDeviceCert {
		if valid := authorize(deviceCert); !valid {
			return "Invalid Device Cert", false
		}
	}

	//get the cert out of the PEM string
	cert, _ := pem.Decode(data)
	var csr *x509.CertificateRequest
	var err error
	// var err error
	if cert == nil {
		csr, err = x509.ParseCertificateRequest(data)
		// checkError(err)
	} else {
		csr, err = x509.ParseCertificateRequest(cert.Bytes)
		// checkError(err)
	}

	if err != nil {
		return "Internal Server Error", false
	}

	random := rand.Reader

	var key rsa.PrivateKey
	LoadKey("/var/www/internal/certs/letsauthprivate.key", &key)

	now := time.Now()

	validDays, err := strconv.Atoi(activeDays)
	if err != nil {
		fmt.Println("Invalid date passed to SignCert: ", activeDays)
		return "Internal Server Error", false
	}

	// NOTE A PREVIOUS VERSION HAD SITE CERTS VALID FOR 10 DAYS AND DEVICE CERTS VALID FOR 7 DAYS
	then := now.Add(time.Duration(60 * 60 * 24 * validDays * 1000 * 1000 * 1000))

	LAnow := time.Now()
	LAthen := now.Add(60 * 60 * 24 * 365 * 1000 * 1000 * 1000) // one year (365 days) for CA cert

	//template read in from the CSR
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: csr.Subject.CommonName,
		},

		EmailAddresses: csr.EmailAddresses,
		NotBefore:      now,
		NotAfter:       then,

		SubjectKeyId:          []byte{1, 2, 3, 4},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	//template of the CA's certificate
	letsauth := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "letsauth.org",
			Organization: []string{"Let's Authenticate"},
		},

		EmailAddresses: []string{"<admin@letsauth.org>"},
		NotBefore:      LAnow,
		NotAfter:       LAthen,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	signed := letsauth

	// actually sign the certificate with the parent certificate's key
	derBytes2, err := x509.CreateCertificate(random, &template, &signed, csr.PublicKey, &key)
	checkError(err)
	// shouldn't we just return an internal server error if we fail?

	certString := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes2})

	return string(certString), true

}

// AddAuthCert adds an authenticator certificate to the database, linking it to the username
// returns whether or not it worked, and a potential error string
func AddAuthCert(username, authCert string) (bool, string) {
	db := openDatabase()
	defer db.Close()

	// fmt.Println(authCert)

	// pull necessary data from the authenticator certificate
	certificate, err := FromPem(authCert)
	if err != nil {
		return false, "Internal Server Error"
	}
	expTime := certificate.NotAfter
	pubKey, err := PubKeyFromCert(certificate)
	if err != nil {
		return false, "Internal Server Error"
	}

	name := certificate.Subject.CommonName

	var exists int
	// want to know if there's an authenticator with the same name for the same user with a different public key
	fmt.Println("Name:", name)
	fmt.Println("PubKey:", pubKey)
	fmt.Println("Username:", username)
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM userDevice WHERE name=? AND pubKey!=? AND username=?)", name, pubKey, username).Scan(&exists)
	fmt.Println("exists?", exists)

	if err != nil { // it already exists
		return false, "Internal Server Error"
	} else if exists == 1 {
		return false, "Duplicate authenticator name: please choose another name."
	}

	// this will update it if possible
	fmt.Println("AuthCert:", authCert)
	fmt.Println("PubKey:", pubKey)
	fmt.Println("ExpTime:", expTime)
	_, err = db.Exec("UPDATE userDevice SET deviceCert=?, revokeFlag=1, deviceExp=? WHERE pubKey=?", authCert, expTime, pubKey)

	if err != nil {
		fmt.Println("Error in updating authenticator certificate: ", err.Error())
		return false, "Internal Server Error"
	}

	// try to add the entry in case it wasn't updated (because it didn't exist)
	// if there's already a cert in the database for the given public key, this won't add anything
	fmt.Println("DeviceCert:", authCert)
	fmt.Println("username:", username)
	fmt.Println("revokeFlag:", 1)
	fmt.Println("deviceExp:", expTime)
	fmt.Println("pubKey:", pubKey)
	fmt.Println("name:", name)
	temp, err2 := db.Exec("INSERT IGNORE userDevice(deviceCert, username, revokeFlag, deviceExp, pubKey, name) VALUES (?, ?, ?, ?, ?, ?)", authCert, username, 1, expTime, pubKey, name)
	fmt.Println(temp.RowsAffected())

	if err2 != nil {
		fmt.Println("Error", err2)
		fmt.Println("Length of deviceCert: ", len(authCert))
		return false, "Internal Server Error"
	}

	// add the device cert to the certificate table
	fmt.Println("Before adding cert to certs table.##############################")
	err = AddCert(authCert, authCert)
	fmt.Println("After adding cert to certs table.##############################")

	if err != nil {
		fmt.Println("Error", err)
		fmt.Println("Length of deviceCert: ", len(authCert))
		return false, "Internal Server Error"
	}

	return true, ""
}

// AddCert adds a new service certificate to the database, along with it's association to a device certificate
func AddCert(certString, deviceCert string) error {

	db := openDatabase()
	defer db.Close()

	certificate, err := FromPem(certString)
	if err != nil {
		return errors.New("unable to convert certificate FromPem in AddNewCert")
	}

	notBefore := certificate.NotBefore
	expTime := certificate.NotAfter
	pubKey, err := PubKeyFromCert(certificate)
	if err != nil {
		return errors.New("unable to obtain public key from cert in AddNewCert")
	}

	// first try to update the certificate in the database
	sql := "UPDATE certs SET cert=?, certExp=?, lastUpdated=? WHERE pubKey=?"
	if _, err = db.Exec(sql, certString, expTime, notBefore, pubKey); err != nil {
		fmt.Println("Error updating cert in cert table")
		fmt.Println(err)
		return errors.New("unable to update certificate in the database")
	}

	// next insert into the database if the certificate wasn't previously stored
	sql = "INSERT IGNORE certs(cert, eblob, certExp, pubKey, deviceCertId, lastUpdated)\n"
	sql += "SELECT ?, ?, ?, ?, userDevice.id, ? FROM userDevice WHERE deviceCert=?"

	_, err = db.Exec(sql, certString, "a blob", expTime, pubKey, notBefore, deviceCert)

	if err != nil {
		fmt.Println(err)
		return errors.New("error inserting into cert table")
	}

	return nil
}

func verifyAuthCert(authCert, username string) error {
	fmt.Println("Verifying Auth Cert")
	fmt.Println(username)
	fmt.Println(authCert)

	db := openDatabase()
	defer db.Close()

	var exists int
	// want to know if there's an authenticator with the same name for the same user with a different public key
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM userDevice WHERE deviceCert=? AND username=?)", authCert, username).Scan(&exists)
	fmt.Println("Exists:", exists)

	if err != nil { // it already exists
		fmt.Println("Internal Error")
		return errors.New("internal server error")
	} else if exists == 1 {
		fmt.Println("Cert Verified")
		return nil
	} else {
		fmt.Println("Doesn't exist")
		return errors.New("AuthCert Doesn't Exist")
	}
}
