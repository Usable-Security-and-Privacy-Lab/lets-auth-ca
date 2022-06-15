package models

import (
	"errors"

	"gorm.io/gorm"
)

// The model for a user. Prepared for usage with gorm
type User struct {
	gorm.Model
	Username    string `gorm:"unique"`
	Displayname string
	Credentials []Credential
}

// The model for a credential. Prepared for usage with gorm.
type Credential struct {
	gorm.Model
	CID             string
	PublicKey       string
	AttestationType string
	Auth            Authenticator `gorm:"embedded"`
	UserID          uint
}

// The model for an Authenticator. Not implemented in gorm. Separate for readability.
type Authenticator struct {
	AAGUID       string
	SignCount    uint
	CloneWarning bool
}

// This function runs any time that a user is created.
// This function checks if there is a non-empty username field given.
//		Failing otherwise (canceling the insertion)
// If there is a username and no display name, the display name is set as the username.
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
