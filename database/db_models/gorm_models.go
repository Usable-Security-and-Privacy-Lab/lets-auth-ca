package db_models

import (
	"errors"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username    string `gorm:"unique"`
	Displayname string
	Credentials []Credential
}

type Credential struct {
	gorm.Model
	CID             string
	PublicKey       string
	AttestationType string
	Auth            Authenticator `gorm:"embedded"`
	UserID          uint
}

type Authenticator struct {
	AAGUID       string
	SignCount    uint
	CloneWarning bool
}

func (u *User) BeforeCreate(tx *gorm.DB) (err error) {
	// Check for username
	if u.Username == "" {
		return errors.New("username must be set")
	}

	//set displayname
	if u.Displayname == "" {
		u.Displayname = u.Username
	}

	return nil
}
