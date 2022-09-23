package database

import (
	"database/sql"
	"fmt"
	"os"

	// This import is blank because that's how the documentation tells us how to use it
	_ "github.com/go-sql-driver/mysql"
)

// For information on how the secret is loaded into the docker container at runtime,
// see the DockerUpdate.md file in root.

// fidoDBpass format: fido_user:[password]@tcp(localhost:3306)/fido

var FidoDBstr string

// openDatabase opens a sql database connection
func InitFidoDatabase() bool {
	dat, err := os.ReadFile("/run/secrets/fidoDBpass")
	if err != nil {
		fmt.Println(err.Error())
		return false
	}
	FidoDBstr = string(dat)

	fmt.Println("Opening up fido database (fido test)")

	// Open db connection
	db, err := sql.Open("mysql", FidoDBstr)
	if err != nil {
		fmt.Println(err.Error())
		return false
	}
	defer db.Close()

	// Double Check if db connection is open
	err = db.Ping()
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	return true
}
