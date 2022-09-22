package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
)

// certificateRequest represents the CSR for a single certificate
type certificateRequest struct {
	CSR                      string `json:"CSR"`
	AuthSignature            string `json:"authSignature"`
	AuthenticatorCertificate string `json:"authenticatorCertificate"`
}

func ObtainNewCertificate(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Beginning serving request %s\n", r.RequestURI)
	defer fmt.Printf("Finished serving request %s\n", r.RequestURI)

	pathVariables := mux.Vars(r)
	username := pathVariables["username"]

	reqBody, _ := ioutil.ReadAll(r.Body)
	var request certificateRequest
	json.Unmarshal(reqBody, &request)

	var signedCertificate string

	// Verify Authenticator Signature
	authCert, CSR, signature := requestedCert.AuthenticatorCertificate, requestedCert.CSR, requestedCert.AuthSignature

	// Sign the Certificate
	certByte := []byte(CSR)
	signedCert, ok := certificates.SignCert(certByte, authCert, serviceCertificateValidDays, true)

	// Verify that accountID isn't taken
	err := certificates.VerifyAccountID(signedCert, username)
	if err != nil {
		if err.Error() == "Account already exists" {
			w.WriteHeader(403)
		} else {
			w.WriteHeader(500)
		}
	}

	// TODO: Verify if the accountID is owned by user (check not to put twice)

	err = certificates.VerifyRSASignatureFromCert(authCert, CSR, signature)
	// TODO: AuthenticatorCertificate must be signed by CA, and for signed this account
	if err != nil {
		// ASK FOR CLERIFICATION DOES THE CA RETURN BAD REQUEST?
		// TODO: deal with error
		continue
	}

	if !ok {
		// AGAIN ASK FOR CLERIFICATION
		continue
	}

	// Add the certificate to the database
	err = certificates.AddCert(signedCert, authCert)
	if err != nil {
		// AGAIN ASK FOR CLERIFICATION
		continue
	}

	response := batchResponse{SignedCertificates: signedCertificates}
	final, _ := json.Marshal(response)

	fmt.Fprint(w, string(final))
}
