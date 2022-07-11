package api

import (
	"log"

	"github.com/duo-labs/webauthn/webauthn"
	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/util"
	"github.com/go-playground/validator/v10"
)


var webAuthn *webauthn.WebAuthn
var sessionStore *Store

var validate *validator.Validate


func Init() {
	var err error
	cfg := util.GetConfig()
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,  // Display Name for your site
		RPID:          cfg.RPID,           // Generally the domain name for your site
		RPOrigin:      cfg.RPOrigin, 		// this needs to be the origin for the request, with the protocol (HTTP(S)) and port number (if not 80 for HTTP or 443 for HTTPS)
	})
	if err != nil {
		log.Fatal("failed to create WebAuthn from config:", err)
	}

	sessionStore, err = NewStore()
	if err != nil {
		log.Fatal("failed to create session store:", err)
	}
	
	validate = validator.New()
}