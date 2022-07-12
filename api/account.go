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

type AuthKeyRequest struct {
	AuthPublicKey string `json:"authPublicKey"`
}

type CSRRequest struct {
	CSR string `json:"CSR"`
}

type CertificateResponse struct {
	Certificate string `json:"certificate"`
}

func CreateBegin(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Started CreateBegin request %s\n", r.RequestURI)
	defer fmt.Printf("Finished CreateBegin request %s\n", r.RequestURI)

	vars := mux.Vars(r)
	username, ok := vars["username"]
	if !ok {
		jsonResponse(w, fmt.Errorf("must supply a valid username i.e. foo@bar.com"), http.StatusBadRequest)
		return
	}

	// validate the username
	// start by creating a new user
	user := models.NewUser(username)
	err := validate.Struct(user)
	if err != nil {
		jsonResponse(w, fmt.Errorf("usernames must be alphabetical and numeric characters only"), http.StatusBadRequest)
		return
	}

	// check if this user exists, return an error if it does
	_, err = models.GetUserByUsername(username)
	if err == nil {
		fmt.Println("Attempted to register username that already exists: ", username)
		jsonResponse(w, "User already exists", http.StatusConflict)
		return
	}
	fmt.Printf("Creating username for %s\n", username)

	// we can create a new user now
	// TBD we should probably mark this user as "in progress" in case they don't finish registration properly. We could then reclaim the username if enough time has passed without the user finishing.
	err = models.CreateUser(&user)
	if err != nil {
		fmt.Println("Error creating new user:", username)
		jsonResponse(w, "Error creating new user", http.StatusInternalServerError)
		return
	}

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		// TBD -- we used to do this -- check to see if it is needed
		// credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
		credCreationOpts.AuthenticatorSelection.UserVerification = "discouraged"
	}

	// generate PublicKeyCredentialCreationOptions, session data
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

	// TBD for all errors finishing we should probably reclaim the user record so the user
	// can recreate the account. Otherwise they will be locked out of using this username

	vars := mux.Vars(r)
	username, ok := vars["username"]
	if !ok {
		jsonResponse(w, fmt.Errorf("must supply a valid username i.e. foo@bar.com"), http.StatusBadRequest)
		return
	}
	fmt.Printf("finishing for user %s\n", username)

	// Load the session data
	sessionData, err := sessionStore.GetWebauthnSession("la3-create", r)
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Println("got session info")

	// Get the user associated with the credential
	user, err := models.GetUser(models.BytesToID(sessionData.UserID))
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Println("got user from db")

	// check that the username matches the user record
	if username != user.Username {
		jsonResponse(w, "username does not match user ID", http.StatusInternalServerError)
		return
	}

	// We need to parse the body twice and this is destructive. So read the body and save it.
	// We should probably reject body sizes that are too big, but this is OK for a demo project
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("Couldn't read request body")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
	}
	bodyCopy := ioutil.NopCloser(bytes.NewReader(body))
	r.Body = bodyCopy

	credential, err := webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Printf("got credential %+v \n", credential)

	// Save the credential and authenticator to the database
	auth := models.MakeAuthenticator(&credential.Authenticator)
	credentialID := base64.URLEncoding.EncodeToString(credential.ID)
	c := &models.Credential{
		Auth:   auth,
		PublicKey:       credential.PublicKey,
		CredentialID:    credentialID,
		UserID: user.ID,
	}
	err = models.CreateCredential(c)
	if err != nil {
		fmt.Println("failed to store credential in database")
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// reset the request body
	bodyCopy = ioutil.NopCloser(bytes.NewReader(body))
	r.Body = bodyCopy
	// print it
	var bodyBytes []byte
	fmt.Println("request:")
		bodyBytes, err = ioutil.ReadAll(r.Body)
	var prettyJSON bytes.Buffer
	if err = json.Indent(&prettyJSON, bodyBytes, "", "\t"); err != nil {
		fmt.Printf("JSON parse error: %v", err)
		return
	}
	fmt.Println(string(prettyJSON.Bytes()))
	// reset the request body
	bodyCopy = ioutil.NopCloser(bytes.NewReader(body))
	r.Body = bodyCopy

	// Get the authenticator public key from the request
	var request AuthKeyRequest
	err = json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		fmt.Println("can't get key from request")
		fmt.Println(err.Error())
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	// need to convert from base64 URL encoding
	converted, err := base64.StdEncoding.DecodeString(request.AuthPublicKey)
	request.AuthPublicKey = string(converted)

	fmt.Println("got key", request.AuthPublicKey)


	// Store the authenticator public key
	authKey := &models.AuthKey{
		Key: request.AuthPublicKey,
		UserID: user.ID,
	}
	err = models.CreateAuthKey(authKey)
	if err != nil {
		fmt.Println("can't store authenticator public key", err.Error())
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Println("OK")

	jsonResponse(w, "OK", http.StatusOK)
}

func SignCSR(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Started SignCSR request %s\n", r.RequestURI)
	defer fmt.Printf("Finished SignCSR request %s\n", r.RequestURI)
	
	vars := mux.Vars(r)
	username, ok := vars["username"]
	if !ok {
		jsonResponse(w, fmt.Errorf("must supply a valid username i.e. foo@bar.com"), http.StatusBadRequest)
		return
	}
	
	user, err := models.GetUserByUsername(username)
	if err != nil {
		// user isn't in database
		fmt.Printf("User is not in database")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	
	// Get the CSR from the request
	var request CSRRequest
	err = json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		fmt.Println("CSR missing or formatted incorrectly", err.Error())
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	cert, _ := pem.Decode([]byte(request.CSR))
	var csr *x509.CertificateRequest
	// var err error
	if cert == nil {
		csr, err = x509.ParseCertificateRequest([]byte(request.CSR))
		// checkError(err)
	} else {
		csr, err = x509.ParseCertificateRequest(cert.Bytes)
		// checkError(err)
	}
	if err != nil {
		fmt.Println("CSR bad format", err.Error())
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check that the CSR is for one of the valid authenticator public keys
	// First, get the authorized keys for this user
	authKeys, err := models.GetAuthKeysForUser(user)
	if err != nil {
		jsonResponse(w, "unable to get authenticator keys for this user", http.StatusInternalServerError)
		return
	}
	// Second, convert the public key in the CSR into PEM format
	publicKeyDer, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
	publicKeyBlock := pem.Block{
	    Type:  "PUBLIC KEY",
	    Bytes: publicKeyDer,
	}
	publicKey := string(pem.EncodeToMemory(&publicKeyBlock))

	// Third, check if the key matches any of the valid keys for this user
	present := models.AuthKeyPresent(publicKey, authKeys)
	if !present {
		jsonResponse(w, "authenticator key is not authorized for this account", http.StatusUnauthorized)
		return
	}

	// TBD we need to validate the CSR. This should include being sure it is properly signed.
	// It is for the username this account owns.
	// What else?
	if username != csr.Subject.CommonName {
		jsonResponse(w, "username doesn't match CSR subject", http.StatusBadRequest)
		return
	}

	// Sign the CSR
	authCertificate, err := certs.SignAuthCertificate(csr)
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// send the auth certificate back
	pemCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authCertificate.Raw}))
	fmt.Println("certificate in PEM format")
	fmt.Println(pemCert)
	var response CertificateResponse
	response.Certificate = pemCert
	json.NewEncoder(w).Encode(response)

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

