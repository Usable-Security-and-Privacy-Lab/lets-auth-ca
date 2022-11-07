package certificates

import (
	"errors"
	"fmt"
	"os/exec"
	"time"
)

var (
	databaseLocks = make(map[string]databaseLock)
)

func CheckEtag(username, etag string) bool {
	db := openDatabase()
	defer db.Close()

	var tag string
	sql := "SELECT etag FROM etags WHERE username=?"
	err := db.QueryRow(sql, username).Scan(&tag)
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	return etag == tag
}

type databaseLock struct {
	Username   string
	LockString string
}

func RetrieveRecoveryDataEtag(authCertificate string) string {

	db := openDatabase()
	defer db.Close()

	certificate, err := FromPem(authCertificate)
	if err != nil {
		return "unable to convert authcertPEM to certificate in RetrieveRecoveryDataEtag"
	}

	pubKey, err := PubKeyFromCert(certificate)
	if err != nil {
		return "unable to get pubkey from certificate in RetrieveRecoveryDataEtag"
	}

	var recoveryData string
	sql := "SELECT eblob FROM certs WHERE pubKey=?"
	err = db.QueryRow(sql, pubKey).Scan(&recoveryData)

	if err != nil {
		fmt.Println(err.Error())
		return "unable to read eblob from certs in RetrieveRecoveryDataEtag"
	}

	return recoveryData
}

func RetrieveRecoveryData(authCertificate, username string) (string, string, error) {

	db := openDatabase()
	defer db.Close()

	fmt.Println(authCertificate)

	err := verifyAuthCert(authCertificate, username)
	if err != nil {
		return "", "", errors.New("invalid auth cert passed into RetrievalRecovery")
	}

	var recoveryData string
	sql := "SELECT rdata FROM etags WHERE username=?"
	err = db.QueryRow(sql, username).Scan(&recoveryData)

	if err != nil {
		fmt.Println(err.Error())
		return "", "", errors.New("unable to read eblob from certs in RetrieveRecoveryData")
	}

	// var etag string
	// sql = "SELECT etag FROM etags WHERE username=?"
	// err = db.QueryRow(sql, username).Scan(&etag)

	// if err != nil {
	// 	fmt.Println(err.Error())
	// 	return "", "", errors.New("unable to read etag from etags in RetrieveRecoveryData")
	// }

	return recoveryData, "etag", nil
}

func PutRecoveryData(username, recoveryData string) (string, error) {

	db := openDatabase()
	defer db.Close()

	// next insert into the database if the certificate wasn't previously stored
	sql := "INSERT INTO etags(rdata, etag, username) VALUES (?, ?, ?)"

	_, err := db.Exec(sql, recoveryData, "etag", username)
	if err != nil {
		return "", err
	}

	newEtag := updateEtag(username)

	return newEtag, nil
}

func UpdateRecoveryData(authCertificate, username, recoveryData, lock string) (string, error) {

	db := openDatabase()
	defer db.Close()

	err := verifyAuthCert(authCertificate, username)
	if err != nil {
		return "", errors.New("invalid auth cert")
	}

	sql := "UPDATE etags SET rdata=? WHERE username=?"
	_, err = db.Exec(sql, recoveryData, username)
	if err != nil {
		fmt.Println(err.Error())
		return "", errors.New("failed to update certificate")
	}

	newEtag := updateEtag(username)

	return newEtag, nil
}

func updateEtag(username string) string {
	db := openDatabase()
	defer db.Close()

	out, err := exec.Command("uuidgen").Output()
	if err != nil {
		fmt.Println(err.Error())
		return ""
	}

	newEtag := string(out)

	sql := "UPDATE etags SET etag=? WHERE username=?"
	_, err = db.Exec(sql, newEtag, username)
	if err != nil {
		fmt.Println(err.Error())
		return ""
	}

	return newEtag
}

func GetDatabaseLock(authCertificate, username string) (string, error) {

	err := verifyAuthCert(authCertificate, username)
	if err != nil {
		return "", errors.New("unable to convert authcertPEM to certificate in RetrieveRecoveryData")
	}

	previousLock := databaseLocks[username]
	if previousLock.Username != "" {
		return "", errors.New("lock already exists")
	}

	// generate the uuid
	out, err := exec.Command("uuidgen").Output()
	if err != nil {
		fmt.Println(err.Error())
		return "", errors.New("unable to generate UUID")
	}

	out = out[:len(out)-1]

	var lock databaseLock
	lock.Username = username
	lock.LockString = string(out)

	go lockDatabase(username, lock)

	return string(out), nil
}

func lockDatabase(username string, lock databaseLock) {

	databaseLocks[username] = lock

	time.Sleep(30 * time.Second)
	UnlockDatabase(username)

}

func UnlockDatabase(username string) {

	fmt.Println("Deleted lock from database")
	storedLock := databaseLocks[username]

	if storedLock.LockString != "" && storedLock.Username == username {
		delete(databaseLocks, username)
	}
}
