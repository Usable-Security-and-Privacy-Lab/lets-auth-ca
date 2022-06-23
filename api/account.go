package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/mux"
)

var webAuthn *webauthn.WebAuthn
var sessionStore *Store
var authenticatorCertificateValidDays = "10"

func InitializeVars() {
	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "BYU Usable Security & Privacy Lab",
		RPID:          "letsauth.org",
		RPOrigin:      "https://letsauth.org",
	})
	if err != nil {
		_ = fmt.Errorf("failed to create WebAuth from config: '%s'", err.Error())
	}

	sessionStore, err = NewStore()
	if err != nil {
		_ = fmt.Errorf("failed to create session store: '%s'", err.Error())
	}
}

func CreateBegin(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Started CreateBegin request %s\n", r.RequestURI)
	defer fmt.Printf("Finished CreateBegin request %s\n", r.RequestURI)

	vars := mux.Vars(r)
	username, ok := vars["username"]
	// TBD should probably define a valid username, i.e. what characters are legal, length limits if any. What are best practices here?
	if !ok {
		jsonResponse(w, fmt.Errorf("must supply a valid username"), http.StatusBadRequest)
		return
	}
	fmt.Printf("Creating username for %s\n", username)

	// TBD We need to check if this username has been taken already. If yes, return an error. If no, put it into the database. If account creation ultimately fails, remove it from the database.

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		// TBD -- we used to do this -- check to see if it is needed
		// credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
		credCreationOpts.AuthenticatorSelection.UserVerification = "discouraged"
	}

	// TBD -- we are forcing a user into the Duo webauthn concept of a user. We can decide later if this is ugly enough we want to change it -- but that would likely requiring pulling in a chunk of their code to modify
	user := NewUser(username, username)

	options, sessionData, err := webAuthn.BeginRegistration(
		user,
		registerOptions,
	)
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = sessionStore.SaveWebauthnSession("la3-create", sessionData, r, w)
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

func CreateFinish(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Started CreateFinish request %s\n", r.RequestURI)
	defer fmt.Printf("Finished CreateFinish request %s\n", r.RequestURI)

	vars := mux.Vars(r)
	username := vars["username"]
	fmt.Printf("finishing for user %s\n", username)

	// TBD this username better exist in the database
	// This is just a temporary hack
	user := NewUser(username, username)

	sessionData, err := sessionStore.GetWebauthnSession("la3-create", r)
	fmt.Println("sessionData: ", sessionData)
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	credential, err := webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Printf("got credential %+v \n", credential)

	// TBD we need to add this credential to the user's account, so that login works.
	// user.AddCredential(*credential)

	// TBD the finish endpoint should handle the CSR and return an Auth Certificate

	jsonResponse(w, "Registration Success", http.StatusOK)
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
