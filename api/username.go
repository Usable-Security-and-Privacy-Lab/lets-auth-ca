package api

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/certs"
	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/models"
	"github.com/gorilla/mux"
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

func ObtainAccountCertificate(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Beginning serving request %s\n", r.RequestURI)
	defer fmt.Printf("Finished serving request %s\n", r.RequestURI)

	pathVariables := mux.Vars(r)
	username := pathVariables["username"]

	reqBody, _ := ioutil.ReadAll(r.Body)
	var request certificateRequest
	json.Unmarshal(reqBody, &request)

	// Verify Authenticator Signature
	authCert, CSR, signature := request.AuthenticatorCertificate, request.CSR, request.AuthSignature

	user, err := models.GetUserByUsername(username)
	if err != nil {
		// user isn't in database
		fmt.Printf("User is not in database")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Sign the Certificate
	byteCSR := []byte(CSR)
	cert, _ := pem.Decode(byteCSR)
	var csr *x509.CertificateRequest

	// var err error
	if cert == nil {
		csr, err = x509.ParseCertificateRequest(byteCSR)
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

	signedCert, err := certs.SignAuthCertificate(csr)
	pemCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signedCert.Raw}))

	if err != nil {
		switch {
		case pemCert == "Invalid Device Cert":
			w.WriteHeader(403)
			fmt.Fprint(w, pemCert)
			fmt.Println("403, Invalid Device Cert")
			// Do these need returns? ask if the old Login endpoint was exhaustively tested
		default:
			w.WriteHeader(500)
			fmt.Fprint(w, pemCert)
			fmt.Printf("500, %s\n", pemCert)
		}
		return
	}

	err = models.VerifyAccountID(signedCert, username)
	if err != nil {
		if err.Error() == "account already taken by other user" || err.Error() == "account already exists by current user" {
			w.WriteHeader(403)
		} else {
			w.WriteHeader(500)
		}
	}

	err = certs.VerifyRSASignatureFromCert(signedCert, byteCSR, signature)
	// TODO: AuthenticatorCertificate must be signed by CA, and for signed this account
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Add the certificate to the database
	err = certs.AddCert(signedCert, authCert)
	if err != nil {
		// AGAIN ASK FOR CLERIFICATION
		jsonResponse(w, fmt.Errorf("failed adding cert to certs table"), http.StatusInternalServerError)
		return
	}

	response := serviceResponse{SignedCertificate: pemCert}
	final, _ := json.Marshal(response)

	fmt.Fprint(w, string(final))
}
