package api

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/certs"
	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/models"
	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/util"
	"github.com/gorilla/mux"
)

type authenticationDataRequest struct {
	authenticatorCertificate string `json:"authenticatorCertificate"`
}

type entry struct {
	accountName       string
	accountID         uint
	sessionPublicKey  *rsa.PublicKey
	sessionPrivateKey *rsa.PrivateKey
}

type session struct {
	sessionCertificate string
	geoLocation        string
}

type sessionList struct {
	authenticatorName string
	sessions          []session
}

type AuthenticationDataResponse struct {
}

func AuthDataRetrieval(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Started AuthenticationData request %s\n", r.RequestURI)
	defer fmt.Printf("Finished AuthenticationData request %s\n", r.RequestURI)

	vars := mux.Vars(r)
	username, ok := vars["username"]
	if !ok {
		jsonResponse(w, fmt.Errorf("must supply a valid username i.e. foo@bar.com"), http.StatusBadRequest)
		return
	}

	reqBody, _ := ioutil.ReadAll(r.Body)
	var request authenticationDataRequest
	json.Unmarshal(reqBody, &request)

	authenticatorCertificate := request.authenticatorCertificate

	decryptedBytes, err := certs.DecodeAuthCert(authenticatorCertificate)

	if err != nil {
		fmt.Printf("Error in decoding authCert")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	fmt.Print(username)
	fmt.Print(decryptedBytes)

	// E. Relying Party Authentication
	// TODO: authenticatorName from authenticatorCertificate  (authenticatorList = [authenticatorName])

	/*
		create map(domain) = {"domain": {accountName, accountID, sessionPublicKey, sessionPrivateKey}}
		sessionList = [authenticatorName, [sessionCertificate, geoLocation]]

		{E(PBKDF(masterPassword), symmetricKey) |
			E(symmetricKey, [authenticatorName] |
			{"domain": {accountName, accountID, sessionPublicKey, sessionPrivateKey})}
	*/

	cfg := util.GetConfig()

	var domainMap = make(map[string]entry)

	userObj, err := models.GetUserByUsername(username)

	if err != nil {
		// user isn't in database
		fmt.Printf("User is not in database")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	domainMap[cfg.RPID] = entry{
		accountName:       username,
		accountID:         userObj.ID,
		sessionPublicKey:  cfg.PublicKey,
		sessionPrivateKey: cfg.PrivateKey,
	}

}

// What will be the difference between POST and PUT in here?
func AuthDataStorageCache(w http.ResponseWriter, r *http.Request) {
	lock := models.DataLock{
		UserID: 1,
	}
	err := models.CreateDataLock(&lock)
	if err != nil {
		fmt.Printf("Cannot create lock")
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func AuthDataStorageIdempotent(w http.ResponseWriter, r *http.Request) {
	count, err := models.CountDataLock(1)
	if err != nil {
		fmt.Printf("Cannot create lock")
		w.WriteHeader(http.StatusInternalServerError)
	}
	print(count)
}
