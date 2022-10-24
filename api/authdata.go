package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
)

type authenticationDataRequest struct {
	authenticatorCertificate string `json:"authenticatorCertificate"`
}

type entry struct {
	accountName       string
	accountID         string
	sessionPublicKey  string
	sessionPrivateKey string
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

}

func AuthDataStorageCache(w http.ResponseWriter, r *http.Request) {

}

func AuthDataStorageIdempotent(w http.ResponseWriter, r *http.Request) {

}
