package api

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"

	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"crypto/x509"

	"github.com/gorilla/mux"
	"github.com/duo-labs/webauthn/protocol"

	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/models"
	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/certs"
)


func Begin(w http.ResponseWriter, r *http.Request){
	fmt.Printf("Started login begin request %s\n", r.RequestURI)
	defer fmt.Printf("Finished CreateBegin request %s\n", r.RequestURI)

	vars := mux.Vars(r)
	username:= vars["username"]
	if !ok {
		jsonResponse(w, fmt.Errorf("must supply a valid username i.e. foo@bar.com"), http.StatusBadRequest)
		return
	}
	user := models.GetUserByUsername(username)
	err := validate.Struct(user)
	if err != nil {
		jsonResponse(w, fmt.Errorf("no user found"), http.StatusBadRequest)
		return
	}
	options, sessionData, err := webauthn.BeginLogin(&user)
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = sessionStore.SaveWebauthnSession("la3-login", sessionData, r, w)
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResponse(w, options, http.StatusOK)
}
func Finish(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Started LoginFinish request %s\n", r.RequestURI)
	defer fmt.Printf("Finished LoginFinish request %s\n", r.RequestURI)
    user := datastore.GetUser() // Get the user
    // Get the session data stored from the function above
    // using gorilla/sessions it could look like this
    sessionData := store.Get(r, "la3-login")
    parsedResponse, err := protocol.ParseCredentialRequestResponseBody(r.Body)
    credential, err := webauthn.ValidateLogin(&user, sessionData, parsedResponse)
    // Handle validation or input errors
    // If login was successful, handle next steps
    JSONResponse(w, "Login Success", http.StatusOK)
}

// from: https://github.com/duo-labs/webauthn.io/blob/3f03b482d21476f6b9fb82b2bf1458ff61a61d41/server/response.go#L15
func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}
