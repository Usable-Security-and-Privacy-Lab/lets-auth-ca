package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/api"
	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/certs"
	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/util"

	"github.com/gorilla/mux"
)

const (
	host = "localhost"
	port = "3060"
)

func main() {
	// process command line arguments
	signRoot := flag.Bool("root", false, "Resigns the root certificate. Mutually exclusive with other operating flags.")
	configDir := flag.String("configDir", "configs", "configuration directory")
	configMode := flag.String("config", "development", "configuration mode")
	logLevel := flag.Int("log", 1, "Level of Logging\n\t-1:trace\n\t0:debug\n\t1:info\n\t2:warn\n\t3:error\n\t4:fatal\n\t5:Panic")
	logPath := flag.String("path", "", "Path to logging output file, leave blank for stdout/stderr")

	flag.Parse()

	util.ConfigInit(*configDir, *configMode)
	cfg := util.GetConfig()
	fmt.Println(cfg.Name)

	if *signRoot {
		certs.ReSignRootCert()
		os.Exit(0)
	}
	// else continue with normal ca operations

	// Logger setup
	fmt.Println("setting up logger...")
	util.SetUpLogger(*logLevel, *logPath)
	util.LogTest()

	// Normal Server operations

	fmt.Println("Serving Let's Authenticate version 3 API")

	// Setup Gorilla mux to handle API requests
	router := mux.NewRouter().StrictSlash(true)

	// initialize the API
	api.InitializeVars()

	// configure the router
	router.HandleFunc("/la3/account/create-begin/{username}", api.CreateBegin).Methods("GET")
	router.HandleFunc("/la3/account/create-finish/{username}", api.CreateFinish).Methods("POST")

	http.ListenAndServe(":"+port, router)

	fmt.Println("Server quit")

}
