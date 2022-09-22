package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/models/certificates"
)

var (
	serviceCertificateValidDays       = "10"
	authenticatorCertificateValidDays = "7"
)

// certificateRequest represents the CSR for a single certificate
type certificateRequest struct {
	CSR                      string `json:"CSR"`
	AuthSignature            string `json:"authSignature"`
	AuthenticatorCertificate string `json:"authenticatorCertificate"`
}

// serviceResponse represents the response made when the CA succesfully
// signs all the certificates
type serviceResponse struct {
	SignedCertificate string `json:"serviceCertificate"`
}

func ObtainNewCertificate(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Beginning serving request %s\n", r.RequestURI)
	defer fmt.Printf("Finished serving request %s\n", r.RequestURI)

	pathVariables := mux.Vars(r)
	username := pathVariables["username"]

	reqBody, _ := ioutil.ReadAll(r.Body)
	var request certificateRequest
	json.Unmarshal(reqBody, &request)

	// Verify Authenticator Signature
	authCert, CSR, signature := request.AuthenticatorCertificate, request.CSR, request.AuthSignature

	// Sign the Certificate
	certByte := []byte(CSR)
	signedCert, ok := certificates.SignCert(certByte, authCert, serviceCertificateValidDays, true)

	// Verify that accountID isn't taken
	err := certificates.VerifyAccountIDTaken(signedCert, username)
	if err != nil {
		if err.Error() == "account already taken by other user" {
			w.WriteHeader(403)
		} else {
			w.WriteHeader(500)
		}
	}

	// TODO: Verify if the accountID of user already exists (check not to put twice)
	// maybe it can be combined with above statements
	err = certificates.VerifyAccountIDExists(signedCert, username)
	if err != nil {
		if err.Error() == "account already exists by current user" {
			w.WriteHeader(403)
		} else {
			w.WriteHeader(500)
		}
	}

	err = certificates.VerifyRSASignatureFromCert(authCert, CSR, signature)
	// TODO: AuthenticatorCertificate must be signed by CA, and for signed this account
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !ok {
		// AGAIN ASK FOR CLERIFICATION
		switch {
		case signedCert == "Invalid Device Cert":
			w.WriteHeader(403)
			fmt.Fprint(w, signedCert)
			fmt.Println("403, Invalid Device Cert")
			// Do these need returns? ask if the old Login endpoint was exhaustively tested
		default:
			w.WriteHeader(500)
			fmt.Fprint(w, signedCert)
			fmt.Printf("500, %s\n", signedCert)
		}
		return
	}

	// Add the certificate to the database
	err = certificates.AddCert(signedCert, authCert)
	if err != nil {
		// AGAIN ASK FOR CLERIFICATION
		jsonResponse(w, fmt.Errorf("failed adding cert to certs table"), http.StatusInternalServerError)
		return
	}

	response := serviceResponse{SignedCertificate: signedCert}
	final, _ := json.Marshal(response)

	fmt.Fprint(w, string(final))
}
