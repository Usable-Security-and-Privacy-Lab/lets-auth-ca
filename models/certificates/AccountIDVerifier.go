package certificates

import (
	"errors"
	"fmt"
)

// VerifyAccountID checks to see that accountID isn't taken by
// a different user
func VerifyAccountIDTaken(signedCert, username string) error {
	// VERY SUPER IMPORANT, MYSQLTABLE ACCOUNTS NEEDS TO BE CREATED WITH ACCOUNTID (VARCHAR(100) NOT NULL and USERNAME)

	db := openDatabase()
	defer db.Close()

	certificate, err := FromPem(signedCert)
	if err != nil {
		fmt.Println(err)
		return errors.New("unable to convert certificate")
	}

	// TODO: ASK ABOUT WHERE THE AUTHENTICATORS ARE PUTTING IN THE ACCOUNT ID
	accountID := certificate.Subject.CommonName

	var exists int

	sql := "SELECT COUNT(1) FROM userDevice WHERE id=? AND username!=?"

	err = db.QueryRow(sql, accountID, username).Scan(&exists)

	if err != nil {
		fmt.Println(err)
		return errors.New("database error")
	}

	if exists == 1 {
		return errors.New("account already taken by other user")
	}

	// pubKey, err := PubKeyFromCert(certificate)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return errors.New("Internal Server Error")
	// }
	//
	// sql = "INSERT userDevice(deviceCert, username, revokeFlag, deviceExp, pubKey, name) VALUES (?, ?, ?, ?, ?)"
	// _, err = db.Exec(sql, signedCert username, accountID, signedCert, string(pubKey), "depreicated")

	// if err != nil {
	// 	fmt.Println(err)
	// 	return errors.New("Database error")
	// }

	return nil
}

func VerifyAccountIDExists(signedCert, username string) error {
	// VERY SUPER IMPORANT, MYSQLTABLE ACCOUNTS NEEDS TO BE CREATED WITH ACCOUNTID (VARCHAR(100) NOT NULL and USERNAME)

	db := openDatabase()
	defer db.Close()

	certificate, err := FromPem(signedCert)
	if err != nil {
		fmt.Println(err)
		return errors.New("unable to convert certificate")
	}

	// TODO: ASK ABOUT WHERE THE AUTHENTICATORS ARE PUTTING IN THE ACCOUNT ID
	accountID := certificate.Subject.CommonName

	var exists int

	sql := "SELECT COUNT(1) FROM userDevice WHERE id=? AND username=?"

	err = db.QueryRow(sql, accountID, username).Scan(&exists)

	if err != nil {
		fmt.Println(err)
		return errors.New("database error")
	}

	if exists == 1 {
		return errors.New("account already exists by current user")
	}

	// pubKey, err := PubKeyFromCert(certificate)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return errors.New("Internal Server Error")
	// }
	//
	// sql = "INSERT userDevice(deviceCert, username, revokeFlag, deviceExp, pubKey, name) VALUES (?, ?, ?, ?, ?)"
	// _, err = db.Exec(sql, signedCert username, accountID, signedCert, string(pubKey), "depreicated")

	// if err != nil {
	// 	fmt.Println(err)
	// 	return errors.New("Database error")
	// }

	return nil
}
