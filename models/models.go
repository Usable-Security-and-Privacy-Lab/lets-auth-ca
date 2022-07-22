package models

// borrowed from Duo Labs (thank you!)
// https://github.com/duo-labs/webauthn.io

import (
	"encoding/binary"
	"errors"
	"database/sql"

	"gorm.io/gorm"
	"gorm.io/driver/mysql"

	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/util"
)

var db *gorm.DB

// ErrUsernameTaken is thrown when a user attempts to register a username that is taken.
var ErrUsernameTaken = errors.New("username already taken")


// BytesToID converts a byte slice to a uint. This is needed because the
// WebAuthn specification deals with byte buffers, while the primary keys in
// our database are uints.
func BytesToID(buf []byte) uint {
	// TODO: Probably want to catch the number of bytes converted in production
	id, _ := binary.Uvarint(buf)
	return uint(id)
}

// Setup initializes the Conn object
// It also populates the Config object
func Setup(config *util.Config) error {
	// assume the database is already created
	
	// Open our database connection
	temp_db, err := gorm.Open(mysql.Open(config.DbConfig), &gorm.Config{})
	if err != nil {
		return err
	}
	db = temp_db
	var sqlDB *sql.DB
	sqlDB, err = db.DB()
	if err != nil {
		return err
	}
	sqlDB.SetMaxOpenConns(1)
	// Migrate up to the latest version
	err = db.AutoMigrate(
		&User{},
		&Credential{},
		&AuthKey{},
	)

	if err != nil {
		return err
	}

	return nil
}

