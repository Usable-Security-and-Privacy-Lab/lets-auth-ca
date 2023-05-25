package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"

	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/api"
	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/certs"
	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/models"
	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/util"
)

func main() {
	// process command line arguments
	signRoot := flag.Bool("root", false, "Resigns the root certificate. Mutually exclusive with other operating flags.")
	configDir := flag.String("configDir", "lets-auth-ca-development", "configuration directory")
	logLevel := flag.Int("log", 1, "Level of Logging\n\t-1:trace\n\t0:debug\n\t1:info\n\t2:warn\n\t3:error\n\t4:fatal\n\t5:Panic")
	logPath := flag.String("path", "", "Path to logging output file, leave blank for stdout/stderr")

	flag.Parse()

	util.ConfigInit(*configDir)
	cfg := util.GetConfig()
	fmt.Println(cfg.Name)

	if *signRoot {
		certs.ReSignRootCert()
		os.Exit(0)
	}

	// continue with normal CA operations

	// Logger setup
	fmt.Println("setting up logger...")
	util.SetUpLogger(*logLevel, *logPath)
	//util.LogTest()

	// initialize database
	err := models.Setup(cfg)
	if err != nil {
		log.Fatal().Err(err)
	}

	// Normal Server operations

	// Setup Gorilla mux to handle API requests
	router := mux.NewRouter().StrictSlash(true)

	// initialize the API
	api.Init()

	// configure the router
	router.HandleFunc("/la3/account/create-begin/{username}", api.CreateBegin).Methods("GET")
	router.HandleFunc("/la3/account/create-finish/{username}", api.CreateFinish).Methods("POST")
	router.HandleFunc("/la3/account/sign-csr/{username}", api.SignCSR).Methods("POST")
	router.HandleFunc("/la3/account/sign-in/{username}/{password}", api.SignIn).Methods("POST")
	router.HandleFunc("/la3/login/begin/{email_or_phone_register}", api.Begin).Methods("GET")
	router.HandleFunc("/la3/login/finish/{email_or_phone_register}", api.Begin).Methods("POST")

	url := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	fmt.Println("Serving Let's Authenticate version 3 API on", url)

	http.ListenAndServe(url, router)

	fmt.Println("Server quit")

}
