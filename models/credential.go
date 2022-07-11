package models

// borrowed from Duo Labs (thank you!)
// https://github.com/duo-labs/webauthn.io

import (
	"gorm.io/gorm"

	"github.com/duo-labs/webauthn/webauthn"

)

// Credential is the stored credential for Auth
type Credential struct {
	gorm.Model

	CredentialID string `json:"credential_id"`
	Auth Authenticator `gorm:"embedded" json:"authenticator"`
	PublicKey []byte `json:"public_key,omitempty"`
	UserID uint
}

// The model for an Authenticator. Not implemented in gorm. Separate for readability.
type Authenticator struct {
	AAGUID       []byte
	SignCount    uint32
	CloneWarning bool
}

func MakeAuthenticator(a *webauthn.Authenticator) Authenticator {
	auth := Authenticator{
		AAGUID: a.AAGUID,
		SignCount: a.SignCount,
		CloneWarning: a.CloneWarning,
	}
	return auth
}

// CreateCredential creates a new credential object
func CreateCredential(c *Credential) error {
	err := db.Create(&c).Error
	return err
}

// UpdateCredential updates the credential with new attributes.
func UpdateCredential(c *Credential) error {
	err := db.Save(&c).Error
	return err
}

// GetCredentialsForUser retrieves all credentials for a provided user regardless of relying party.
func GetCredentialsForUser(user *User) ([]Credential, error) {
	creds := []Credential{}
	err := db.Where("user_id = ?", user.ID).Find(&creds).Error
	return creds, err
}

// GetCredentialForUser retrieves a specific credential for a user.
func GetCredentialForUser(user *User, credentialID string) (Credential, error) {
	cred := Credential{}
	err := db.Where("user_id = ? AND credential_id = ?", user.ID, credentialID).Find(&cred).Error
	return cred, err
}

func UpdateAuthenticatorSignCount(c* Credential, count uint32) error {
	c.Auth.SignCount = count
	err := db.Save(&c).Error
	return err
}

// DeleteCredentialByID gets a credential by its ID. In practice, this would be a bad function without
// some other checks (like what user is logged in) because someone could hypothetically delete ANY credential.
func DeleteCredentialByID(credentialID string) error {
	return db.Where("cred_id = ?", credentialID).Delete(&Credential{}).Error
}