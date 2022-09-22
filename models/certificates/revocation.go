package certificates

import (
	"errors"
	"fmt"
)

// RevokeAuthCertificate revokes an auth certificate in the database.
func RevokeAuthCertificate(authCert string) error {
	db := openDatabase()
	defer db.Close()

	sql := "UPDATE userDevice SET revokeFlag=0 where deviceCert=?"
	_, err := db.Exec(sql, authCert)
	if err != nil {
		fmt.Println(err.Error())
		return errors.New("unable to update database")
	}

	return nil
}
