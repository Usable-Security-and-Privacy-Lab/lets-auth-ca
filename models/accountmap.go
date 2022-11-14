package models

import (
	"crypto/x509"

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
	err := db.Where("username = ?", username).Error

	return err
}
