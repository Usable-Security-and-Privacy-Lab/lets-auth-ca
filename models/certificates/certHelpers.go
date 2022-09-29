package certificates

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/gob"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	// This import is blank because that's how the documentation tells us how to use it

	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/util"
	_ "github.com/go-sql-driver/mysql"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// TagDevice is the struct used to check authorization and ... (TODO ADD MROE INFO)
type TagDevice struct {
	DeviceCert string `json:"devcieCert"`
	Username   string `json:"username"`
	RevFlag    string `json:"revokeFlag"`
	DeviceExp  string `json:"deviceExp"`
}

// checkError does what it says
func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}

// FromPem takes in a PEM certificate (string) and returns an x.509 certificate pointer object
func FromPem(pemCert string) (*x509.Certificate, error) {
	// Decode passed in pemCert to a block of data
	pemBlock, _ := pem.Decode([]byte(pemCert))
	if pemBlock == nil {
		return nil, errors.New("invalid PEM string for Certificate")
	}

	// Parse and return pemBlock
	return x509.ParseCertificate(pemBlock.Bytes)
}

// PubKeyFromCert gets the public key bytes for the passed in certificate pointer (cert)
func PubKeyFromCert(cert *x509.Certificate) ([]byte, error) {

	var (
		pubKey []byte = nil // used to hold public key
		err    error  = nil // used hold possible errors
	)

	if cert == nil {
		err = errors.New("passed in a bad cert pointer")
	} else {
		pubKey = pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(cert.PublicKey.(*rsa.PublicKey)),
			},
		)
	}

	return pubKey, err
}

// openDatabase opens a sql database connection
func openDatabase() *sql.DB {
	fmt.Println("Opening up old database (model...certHelpers)")

	cfg := util.GetConfig()

	// Open our database connection
	temp_db, err := gorm.Open(mysql.Open(cfg.DbConfig), &gorm.Config{})
	if err != nil {
		return nil
	}
	var sqlDB *sql.DB
	sqlDB, err = temp_db.DB()
	if err != nil {
		return nil
	}

	// Double Check if db connection is open
	err = sqlDB.Ping()
	if err != nil {
		panic(err.Error())
	}

	return sqlDB
}

// authNotRevoked checs to see if an authenticator certificate is in the database
// and not revoked (doesn't worry abou texpieration)
// POSIBILITY TO ADD ERROR HANDELING
func authNotRevoked(authCert string) bool {

	var (
		// Used to indicate if the certificate is invalid
		revFlag string
		// database connection
		db = openDatabase()
		// the return value
		notRevoked = false
	)

	// Query the database for the given authCert
	err := db.QueryRow("SELECT revokeFlag FROM userDevice WHERE deviceCert = ?", authCert).Scan(&revFlag)
	if revFlag == "1" { // 1 indicates that the certificate is valid
		notRevoked = true
	} else if err != nil {
		fmt.Println("Error in retrieving row for deviceCert in authNotRevoked().")
	} else {
		fmt.Println("Device revoked.")
	}
	return notRevoked

}

// authorize checs the database to make sure a device certificate is valid
// todo implement this puppy!
func authorize(deviceCert string) bool {

	db := openDatabase()
	defer db.Close()

	deviceCertObject, err := FromPem(deviceCert)
	if err != nil {
		fmt.Println("Bad device cert PEM in authorize().")
		return false
	}

	if deviceCertObject.NotAfter.Before(time.Now()) { // notAfter is before now, cert is expired
		fmt.Println("DeviceCert expiered in authorize()")
		return false
	}

	var tagOne TagDevice
	err = db.QueryRow("SELECT username, revokeFlag FROM userDevice WHERE deviceCert = ?", deviceCert).Scan(&tagOne.Username, &tagOne.RevFlag)

	if err != nil {
		fmt.Println("Authorization failed")
		fmt.Println(err)
		return false
	}

	// if it's not associated with a username or has been revoked
	if tagOne.Username == "" || tagOne.RevFlag == "0" {
		fmt.Println("Device has been revoked or invalid account")
		return false
	}

	return true
}

// loads a key from a GOB encoded file
func LoadKey(fileName string, key interface{}) {
	inFile, err := os.Open(fileName)
	checkError(err)
	decoder := gob.NewDecoder(inFile)
	err = decoder.Decode(key)
	checkError(err)
	inFile.Close()
}
