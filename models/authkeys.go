package models

import (
	"gorm.io/gorm"
)

// Each user account can have a list of authenticator public keys stored for it. These are valid for a set number of days
// and can also be revoked. The key is a public key stored in PEM format.

// When signing authenticator certificates, we will only sign a CSR if the public key is valid for the account.
type AuthKey struct {
	gorm.Model

	Key string
	UserID uint
}

// CreateAuthKey creates a new AuthKey object in the database
func CreateAuthKey(k *AuthKey) error {
	err := db.Create(&k).Error
	return err
}

// GetAuthKeysForUser retrieves all AuthKeys for a provided user
func GetAuthKeysForUser(user User) ([]AuthKey, error) {
	authKeys := []AuthKey{}
	err := db.Where("user_id = ?", user.ID).Find(&authKeys).Error
	return authKeys, err
}

func AuthKeyPresent(key string, authKeys []AuthKey) (bool) {
	for i := 0; i < len(authKeys); i++ {
		if authKeys[i].Key ==  key {
			return true
		}
	}
	return false
}

// DeleteAuthKey deletes an AuthKey using its key. This should only be called by the authorized user,
// after they have logged in (so at the finish part of a FIDO2 login).
func DeleteAuthKey(key string) error {
	return db.Where("key = ?", key).Delete(&AuthKey{}).Error
}