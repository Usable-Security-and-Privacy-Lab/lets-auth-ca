package database

import (
	"errors"
	"sync"

	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/models"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// TODO: Import this from the config file, not hard coded.
const dsn = "gorm_test:ThisIsAReallySecureTestPassword@tcp(127.0.0.1:3306)/gorm?charset=utf8mb4&parseTime=True&loc=Local"

var once sync.Once
var dbWrapper *DBWrapper

type DBWrapper struct {
	db *gorm.DB
}

func GetDB() (*DBWrapper, error) {
	// Singleton model
	once.Do(func() {
		// Open Database Connection
		temp_db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
		if err != nil {
			dbWrapper = nil
			panic("Cannot connect to database")
		}

		// Set persistent pointer
		dbWrapper = &DBWrapper{db: temp_db}

		// Create/Migrate tables from models
		dbWrapper.db.AutoMigrate(&models.User{}, &models.Credential{})
	})

	// Error Check
	if dbWrapper == nil {
		return nil, errors.New("database connection not initialized")
	}

	return dbWrapper, nil
}
