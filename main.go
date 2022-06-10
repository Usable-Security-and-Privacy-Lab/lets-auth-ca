package main

import (
	"flag"
	"fmt"
	"net/http"

	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/config"
	"github.com/Usable-Security-and-Privacy-Lab/lets-auth-ca/api"

	"github.com/gorilla/mux"
)

const (
	host = "localhost"
	port = "3060"
)

func main() {
	// process command line arguments
	configDir := flag.String("configDir", "configs", "configuration directory")
	configMode := flag.String("config", "development", "configuration mode")
	flag.Parse()
	config.Init(*configDir, *configMode)
	cfg := config.Get()
	fmt.Println(cfg.Name)

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
