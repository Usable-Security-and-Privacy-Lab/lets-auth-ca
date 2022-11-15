package models

import (
	"crypto/x509"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

type AccountMap struct {
	gorm.Model

	username  string
	accountID uint
}

func MakeAccoutMap(username string, accountID uint) AccountMap {
	accountMap := AccountMap{
		username:  username,
		accountID: accountID,
	}
	return accountMap
}

func CreateAccountMap(a *AccountMap) error {
	err := db.Create(&a).Error
	return err
}

func VerifyAccountID(certificate *x509.Certificate, username string) error {
	// acc := AccountMap{}
	accountID := certificate.Subject.CommonName

	var exists int
	var err error

	err = db.Where("accountID=? AND username!=?", accountID, username).Scan(&exists).Error

	if err != nil {
		fmt.Println(err)
		return errors.New("database error")
	}

	if exists == 1 {
		return errors.New("account already taken by other user")
	}

	err = db.Where("accountID=? AND username=?", accountID, username).Scan(&exists).Error

	if err != nil {
		fmt.Println(err)
		return errors.New("database error")
	}

	if exists == 1 {
		return errors.New("account already exists by current user")
	}

	return nil
}
