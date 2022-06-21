package database

import (
	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/models"
	// "gorm.io/gorm"
)

// Adds User to database
func (db *DBWrapper) AddUser(user models.User) error {
	result := db.db.Create(&user)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// Deletes user with the given username
func (db *DBWrapper) DeleteUserByUsername(username string) error {
	result := db.db.Delete(&models.User{Username: username})
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// Deletes the user with the given ID
func (db *DBWrapper) DeleteUserByID(id uint) error {
	result := db.db.Delete(&models.User{}, id)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// Updates the given user to the values given in the object
func (db *DBWrapper) UpdateUser(username string, userUpdates models.User) error {
	// var userCurrent models.User
	result := db.db.Model(&models.User{Username: username}).Updates(userUpdates)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// Gets the user object based on the given username
func (db *DBWrapper) GetUserByUsername(username string) (models.User, error) {
	var user models.User
	result := db.db.Where("username = ?", username).First(&user)
	if result.Error != nil {
		return user, result.Error
	}
	return user, nil
}

// Gets the user object based on the given ID
func (db *DBWrapper) GetUserByID(id uint) (models.User, error) {
	var user models.User
	result := db.db.First(&user, id)
	if result.Error != nil {
		return user, result.Error
	}
	return user, nil
}

// Adds the given credential to the user with the given username
func (db *DBWrapper) AddCredentialToUser(username string, cred models.Credential) error {
	var user models.User
	result := db.db.Where("username = ?", username).First(&user)
	if result.Error != nil {
		return result.Error
	}

	user.Credentials = append(user.Credentials, cred)

	result = db.db.Save(&user)
	if result.Error != nil {
		return result.Error
	}
	return nil
}
