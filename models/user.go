package models

import (
	"encoding/base64"
	"encoding/binary"

	"gorm.io/gorm"

	"github.com/duo-labs/webauthn/webauthn"
	"github.com/duo-labs/webauthn/protocol"
)

// User represents the user model
type User struct {
	gorm.Model
	Username    string          `json:"name" gorm:"not null" validate:"required,min=2,max=25,alphanumunicode"`
	DisplayName string          `json:"display_name" gorm:"not null"`
	Credentials []Credential	`json:"credentials"`
}

// NewUser creates and returns a new User
func NewUser(name string) User {

	user := User{}
	user.Username = name
	user.DisplayName = name + "@letsauth.org"
	user.Credentials = []Credential{}

	return user
}

// GetUser returns the user that the given id corresponds to. If no user is found, an
// error is thrown.
func GetUser(id uint) (User, error) {
	u := User{}
	err := db.Where("id=?", id).First(&u).Error
	
	return u, err
}

// GetUserByUsername returns the user that the given username corresponds to. If no user is found, an
// error is thrown.
func GetUserByUsername(username string) (User, error) {
	u := User{}
	err := db.Where("username = ?", username).First(&u).Error

	return u, err
}

// CreateUser creates the given user
func CreateUser(u *User) error {
	err := db.Create(&u).Error
	return err
}

// UpdateUser updates the given user
func UpdateUser(u *User) error {
	err := db.Save(&u).Error
	return err
}

// WebAuthnID returns the user's ID
func (u User) WebAuthnID() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, uint64(u.ID))
	return buf
}

// WebAuthnName returns the user's username
func (u User) WebAuthnName() string {
	return u.Username
}

// WebAuthnDisplayName returns the user's display name
func (u User) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnIcon is not (yet) implemented
func (u User) WebAuthnIcon() string {
	return ""
}

// WebAuthnCredentials helps implement the webauthn.User interface by loading
// the user's credentials from the underlying database.
func (u User) WebAuthnCredentials() []webauthn.Credential {
	credentials, _ := GetCredentialsForUser(&u)

	wcs := make([]webauthn.Credential, len(credentials))
	for i, cred := range credentials {
		credentialID, _ := base64.URLEncoding.DecodeString(cred.CredentialID)
		auth := webauthn.Authenticator{
			AAGUID: cred.Auth.AAGUID,
			SignCount: cred.Auth.SignCount,
			CloneWarning: cred.Auth.CloneWarning,
		}
		wcs[i] = webauthn.Credential{
			ID:            credentialID,
			PublicKey:     cred.PublicKey,
			Authenticator: auth,
		}
	}
	return wcs
}

// CredentialExcludeList returns a CredentialDescriptor array filled
// with all the user's credentials
func (u User) CredentialExcludeList() []protocol.CredentialDescriptor {

	credentialExcludeList := []protocol.CredentialDescriptor{}
	for _, cred := range u.Credentials {
		buf := make([]byte, binary.MaxVarintLen64)
		binary.PutUvarint(buf, uint64(cred.ID))
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: buf,
		}
		credentialExcludeList = append(credentialExcludeList, descriptor)
	}

	return credentialExcludeList
}
