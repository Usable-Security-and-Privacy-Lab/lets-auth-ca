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

// Singleton instance
var dbWrapper *DBWrapper

// This wrapper exists solely so that member functions can be written to work on the database.
type DBWrapper struct {
	db *gorm.DB
}

// The singleton pattern for a database connection.
func GetDB() (*DBWrapper, error) {
	// Singleton pattern
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
