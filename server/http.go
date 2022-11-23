package server

import (
	"log"
	"net/http"
	"io/ioutil"
	"encoding/base64"

	"github.com/rebeljah/squeek/jwt"
)

const (
	addr       = "localhost:8080"
	tcpAddress = "localhost:8000"
	authAddress = "localhost:8081"
)

var jwtKey []byte

func errStatusUnauthorized(w http.ResponseWriter) {
	http.Error(w, "Could not authorize", http.StatusUnauthorized)
}

func errInternal(w http.ResponseWriter) {
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// returns the TCP address of the sock server in form <ip>:<port>
func handleGetTcpAddr(w http.ResponseWriter, r *http.Request) {
	// verify jwt from incoming req
	// only care about success or failure
	_, err := jwt.JWTFromString(r.Header.Get("jwt"), jwtKey)
	if err != nil {
		errStatusUnauthorized(w)
		return
	}

	if _, err := w.Write([]byte(tcpAddress)); err != nil {
		errInternal(w)
		return
	}
}

func Init() {
	// fetch jwt key
	r, err := http.Get(authAddress + "/jwt-public-key")
	if err != nil {
		panic(err)
	}
	jwtKeyB64, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	enc := base64.StdEncoding
	if _, err := enc.Decode(jwtKey, jwtKeyB64); err != nil {
		panic(err)
	}

	// set up routes
	http.HandleFunc("/tcp-addr", handleGetTcpAddr)

	// start serving
	log.Fatal(http.ListenAndServe(addr, nil))
}
